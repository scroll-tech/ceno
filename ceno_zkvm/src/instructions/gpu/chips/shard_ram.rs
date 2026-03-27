use ceno_gpu::common::witgen::types::ShardRamColumnMap;
use ff_ext::ExtensionField;

use crate::{error::ZKVMError, tables::ShardRamConfig};

/// Extract column map from a constructed ShardRamConfig.
///
/// This reads all WitIn.id values from the config and packs them
/// into a ShardRamColumnMap suitable for GPU kernel dispatch.
pub fn extract_shard_ram_column_map<E: ExtensionField>(
    config: &ShardRamConfig<E>,
    num_witin: usize,
) -> ShardRamColumnMap {
    let addr = config.addr.id as u32;
    let is_ram_register = config.is_ram_register.id as u32;

    let value_limbs = config
        .value
        .wits_in()
        .expect("value should have WitIn limbs");
    assert_eq!(value_limbs.len(), 2, "Expected 2 value limbs");
    let value = [value_limbs[0].id as u32, value_limbs[1].id as u32];

    let shard = config.shard.id as u32;
    let global_clk = config.global_clk.id as u32;
    let local_clk = config.local_clk.id as u32;
    let nonce = config.nonce.id as u32;
    let is_global_write = config.is_global_write.id as u32;

    let mut x = [0u32; 7];
    let mut y = [0u32; 7];
    let mut slope = [0u32; 7];
    for i in 0..7 {
        x[i] = config.x[i].id as u32;
        y[i] = config.y[i].id as u32;
        slope[i] = config.slope[i].id as u32;
    }

    // Poseidon2 columns: p3_cols are contiguous, followed by post_linear_layer_cols
    let poseidon2_base_col = config.perm_config.p3_cols[0].id as u32;
    let num_p3_cols = config.perm_config.p3_cols.len() as u32;
    let num_post_linear = config.perm_config.post_linear_layer_cols.len() as u32;
    let num_poseidon2_cols = num_p3_cols + num_post_linear;

    // Verify contiguity: p3_cols should be contiguous
    for (i, col) in config.perm_config.p3_cols.iter().enumerate() {
        debug_assert_eq!(
            col.id as u32,
            poseidon2_base_col + i as u32,
            "p3_cols not contiguous at index {}",
            i
        );
    }
    // post_linear_layer_cols should be contiguous after p3_cols
    let post_base = poseidon2_base_col + num_p3_cols;
    for (i, col) in config.perm_config.post_linear_layer_cols.iter().enumerate() {
        debug_assert_eq!(
            col.id as u32,
            post_base + i as u32,
            "post_linear_layer_cols not contiguous at index {}",
            i
        );
    }

    ShardRamColumnMap {
        addr,
        is_ram_register,
        value,
        shard,
        global_clk,
        local_clk,
        nonce,
        is_global_write,
        x,
        y,
        slope,
        poseidon2_base_col,
        num_poseidon2_cols,
        num_p3_cols,
        num_cols: num_witin as u32,
    }
}

// ---------------------------------------------------------------------------
// ShardRam EC batch computation
// ---------------------------------------------------------------------------

use ceno_gpu::common::witgen::types::GpuShardRamRecord;
use gkr_iop::RAMType;
use p3::field::FieldAlgebra;
use tracing::info_span;

/// Convert a ShardRamRecord to GpuShardRamRecord (metadata only, EC fields zeroed).
pub(crate) fn shard_ram_record_to_gpu(rec: &crate::tables::ShardRamRecord) -> GpuShardRamRecord {
    GpuShardRamRecord {
        addr: rec.addr,
        ram_type: match rec.ram_type {
            RAMType::Register => 1,
            RAMType::Memory => 2,
            _ => 0,
        },
        value: rec.value,
        _pad0: 0,
        shard: rec.shard,
        local_clk: rec.local_clk,
        global_clk: rec.global_clk,
        is_to_write_set: if rec.is_to_write_set { 1 } else { 0 },
        nonce: 0,
        point_x: [0; 7],
        point_y: [0; 7],
    }
}

/// Convert a GPU-computed GpuShardRamRecord to ECPoint.
fn gpu_shard_ram_record_to_ec_point<E: ExtensionField>(
    gpu_rec: &GpuShardRamRecord,
) -> crate::tables::ECPoint<E> {
    use crate::scheme::septic_curve::{SepticExtension, SepticPoint};

    let mut point_x_arr = [E::BaseField::ZERO; 7];
    let mut point_y_arr = [E::BaseField::ZERO; 7];
    for j in 0..7 {
        point_x_arr[j] = E::BaseField::from_canonical_u32(gpu_rec.point_x[j]);
        point_y_arr[j] = E::BaseField::from_canonical_u32(gpu_rec.point_y[j]);
    }

    let x = SepticExtension(point_x_arr);
    let y = SepticExtension(point_y_arr);
    let point = SepticPoint::from_affine(x, y);

    crate::tables::ECPoint {
        nonce: gpu_rec.nonce,
        point,
    }
}

/// Batch compute EC points on GPU, D2H results back to CPU as ShardRamInput.
///
/// Used by the CPU fallback path in `structs.rs` when the full GPU pipeline
/// is unavailable. For the device-resident variant, see `gpu_batch_continuation_ec_on_device`.
pub fn gpu_batch_continuation_ec<E: ExtensionField>(
    write_records: &[(crate::tables::ShardRamRecord, &'static str)],
    read_records: &[(crate::tables::ShardRamRecord, &'static str)],
) -> Result<
    (
        Vec<crate::tables::ShardRamInput<E>>,
        Vec<crate::tables::ShardRamInput<E>>,
    ),
    ZKVMError,
> {
    use crate::tables::ShardRamInput;
    use gkr_iop::gpu::get_cuda_hal;

    let hal = get_cuda_hal().map_err(|e| {
        ZKVMError::InvalidWitness(format!("GPU not available for batch EC: {e}").into())
    })?;

    let total = write_records.len() + read_records.len();
    if total == 0 {
        return Ok((vec![], vec![]));
    }

    let mut gpu_records: Vec<GpuShardRamRecord> = Vec::with_capacity(total);
    for (rec, _name) in write_records.iter().chain(read_records.iter()) {
        gpu_records.push(shard_ram_record_to_gpu(rec));
    }

    let result = info_span!("gpu_batch_ec", n = total)
        .in_scope(|| hal.witgen.batch_continuation_ec(&gpu_records))
        .map_err(|e| ZKVMError::InvalidWitness(format!("GPU batch EC failed: {e}").into()))?;

    let mut write_inputs = Vec::with_capacity(write_records.len());
    let mut read_inputs = Vec::with_capacity(read_records.len());

    for (i, gpu_rec) in result.iter().enumerate() {
        let (rec, name) = if i < write_records.len() {
            (&write_records[i].0, write_records[i].1)
        } else {
            let ri = i - write_records.len();
            (&read_records[ri].0, read_records[ri].1)
        };

        let ec_point = gpu_shard_ram_record_to_ec_point::<E>(gpu_rec);
        let input = ShardRamInput {
            name,
            record: rec.clone(),
            ec_point,
        };

        if i < write_records.len() {
            write_inputs.push(input);
        } else {
            read_inputs.push(input);
        }
    }

    Ok((write_inputs, read_inputs))
}

/// Batch compute EC points on GPU, results stay on device.
///
/// Used by the full GPU pipeline in `structs.rs` where records feed directly
/// into `merge_and_partition_records` on device without D2H.
pub fn gpu_batch_continuation_ec_on_device(
    write_records: &[(crate::tables::ShardRamRecord, &'static str)],
    read_records: &[(crate::tables::ShardRamRecord, &'static str)],
) -> Result<
    (
        ceno_gpu::common::buffer::BufferImpl<'static, u32>,
        usize,
        usize,
    ),
    ZKVMError,
> {
    use gkr_iop::gpu::get_cuda_hal;

    let hal = get_cuda_hal().map_err(|e| {
        ZKVMError::InvalidWitness(format!("GPU not available for batch EC: {e}").into())
    })?;

    let n_writes = write_records.len();
    let n_reads = read_records.len();
    let total = n_writes + n_reads;
    if total == 0 {
        let empty = hal
            .witgen
            .alloc_u32_zeroed(1, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("alloc: {e}").into()))?;
        return Ok((empty, 0, 0));
    }

    let mut gpu_records: Vec<GpuShardRamRecord> = Vec::with_capacity(total);
    for (rec, _name) in write_records.iter().chain(read_records.iter()) {
        gpu_records.push(shard_ram_record_to_gpu(rec));
    }

    let (device_buf, _count) = info_span!("gpu_batch_ec_on_device", n = total)
        .in_scope(|| {
            hal.witgen
                .batch_continuation_ec_on_device(&gpu_records, None)
        })
        .map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU batch EC on device failed: {e}").into())
        })?;

    Ok((device_buf, n_writes, n_reads))
}

/// Try to run ShardRamCircuit assign_instances on GPU.
/// Returns `Ok(None)` if GPU is unavailable or disabled.
pub(crate) fn try_gpu_assign_shard_ram<E: ExtensionField>(
    config: &ShardRamConfig<E>,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[crate::tables::ShardRamInput<E>],
) -> Result<Option<crate::tables::RMMCollections<E::BaseField>>, ZKVMError> {
    use ceno_gpu::{
        Buffer, CudaHal,
        bb31::CudaHalBB31,
        common::{transpose::matrix_transpose, witgen::types::GpuShardRamRecord},
    };
    use gkr_iop::gpu::gpu_prover::get_cuda_hal;
    use p3::field::PrimeField32;
    use witness::{InstancePaddingStrategy, next_pow2_instance_padding};

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;

    if !crate::instructions::gpu::config::is_gpu_witgen_enabled() {
        return Ok(None);
    }

    // GPU only supports BabyBear
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    let num_local_reads = steps
        .iter()
        .take_while(|s| s.record.is_to_write_set)
        .count();

    let n = next_pow2_instance_padding(steps.len());
    let num_rows_padded = 2 * n;

    // 1. Convert ShardRamInput → GpuShardRamRecord
    let gpu_records: Vec<GpuShardRamRecord> =
        tracing::info_span!("gpu_shard_ram_pack_records", n = steps.len()).in_scope(|| {
            steps
                .iter()
                .map(|step| {
                    let r = &step.record;
                    let ec = &step.ec_point;
                    let mut rec = GpuShardRamRecord::default();
                    rec.addr = r.addr;
                    rec.ram_type = r.ram_type as u32;
                    rec.value = r.value;
                    rec.shard = r.shard;
                    rec.local_clk = r.local_clk;
                    rec.global_clk = r.global_clk;
                    rec.is_to_write_set = if r.is_to_write_set { 1 } else { 0 };
                    rec.nonce = ec.nonce;
                    for i in 0..7 {
                        let px: BB =
                            unsafe { *(&ec.point.x.0[i] as *const E::BaseField as *const BB) };
                        let py: BB =
                            unsafe { *(&ec.point.y.0[i] as *const E::BaseField as *const BB) };
                        rec.point_x[i] = px.as_canonical_u32();
                        rec.point_y[i] = py.as_canonical_u32();
                    }
                    rec
                })
                .collect()
        });

    // 2. Extract column map
    let col_map = extract_shard_ram_column_map(config, num_witin);

    // 3. GPU Phase 1: per-row assignment
    let (gpu_witness, gpu_structural) = tracing::info_span!(
        "gpu_shard_ram_per_row",
        n = steps.len(),
        num_rows_padded,
        num_witin,
    )
    .in_scope(|| {
        hal.witgen
            .witgen_shard_ram_per_row(
                &col_map,
                &gpu_records,
                num_local_reads as u32,
                num_witin as u32,
                num_structural_witin as u32,
                num_rows_padded as u32,
                None,
            )
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("GPU shard_ram per-row kernel failed: {e}").into(),
                )
            })
    })?;

    // 4. GPU Phase 2: EC binary tree
    let witness_buf =
        tracing::info_span!("gpu_shard_ram_ec_tree", n).in_scope(|| -> Result<_, ZKVMError> {
            let col_offsets = col_map.to_flat();
            let gpu_cols = hal.alloc_u32_from_host(&col_offsets, None).map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU alloc col offsets failed: {e}").into())
            })?;

            let mut init_x = vec![BB::ZERO; n * 7];
            let mut init_y = vec![BB::ZERO; n * 7];
            for (i, step) in steps.iter().enumerate() {
                for j in 0..7 {
                    init_x[i * 7 + j] = unsafe {
                        *(&step.ec_point.point.x.0[j] as *const E::BaseField as *const BB)
                    };
                    init_y[i * 7 + j] = unsafe {
                        *(&step.ec_point.point.y.0[j] as *const E::BaseField as *const BB)
                    };
                }
            }

            let mut cur_x = hal.alloc_elems_from_host(&init_x, None).map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU alloc init_x failed: {e}").into())
            })?;
            let mut cur_y = hal.alloc_elems_from_host(&init_y, None).map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU alloc init_y failed: {e}").into())
            })?;

            let mut witness_buf = gpu_witness.device_buffer;
            let mut offset = num_rows_padded / 2;
            let mut current_layer_len = n;

            loop {
                if current_layer_len <= 1 {
                    break;
                }

                let (next_x, next_y) = hal
                    .witgen
                    .shard_ram_ec_tree_layer(
                        &gpu_cols,
                        &cur_x,
                        &cur_y,
                        &mut witness_buf,
                        current_layer_len,
                        offset,
                        num_rows_padded,
                        None,
                    )
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("GPU EC tree layer failed: {e}").into())
                    })?;

                current_layer_len /= 2;
                offset += current_layer_len;
                cur_x = next_x;
                cur_y = next_y;
            }

            Ok(witness_buf)
        })?;

    // 5. GPU transpose: column-major → row-major + D2H
    let (wit_data, struct_data) = tracing::info_span!(
        "gpu_shard_ram_transpose_d2h",
        num_rows_padded,
        num_witin,
    )
    .in_scope(|| -> Result<_, ZKVMError> {
        let wit_num_rows = num_rows_padded;
        let wit_num_cols = num_witin;
        let mut rmm_buf = hal
            .witgen
            .alloc_elems_on_device(wit_num_rows * wit_num_cols, false, None)
            .map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU alloc for transpose failed: {e}").into())
            })?;
        matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
            &hal.inner,
            &mut rmm_buf,
            &witness_buf,
            wit_num_rows,
            wit_num_cols,
        )
        .map_err(|e| ZKVMError::InvalidWitness(format!("GPU transpose failed: {e}").into()))?;

        let gpu_wit_data: Vec<BB> = rmm_buf
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU D2H wit failed: {e}").into()))?;
        let wit_data: Vec<E::BaseField> = unsafe {
            let mut data = std::mem::ManuallyDrop::new(gpu_wit_data);
            Vec::from_raw_parts(
                data.as_mut_ptr() as *mut E::BaseField,
                data.len(),
                data.capacity(),
            )
        };

        let struct_num_cols = num_structural_witin;
        let mut struct_rmm_buf = hal
            .witgen
            .alloc_elems_on_device(wit_num_rows * struct_num_cols, false, None)
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("GPU alloc for struct transpose failed: {e}").into(),
                )
            })?;
        matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
            &hal.inner,
            &mut struct_rmm_buf,
            &gpu_structural.device_buffer,
            wit_num_rows,
            struct_num_cols,
        )
        .map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU struct transpose failed: {e}").into())
        })?;

        let gpu_struct_data: Vec<BB> = struct_rmm_buf
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU D2H struct failed: {e}").into()))?;
        let struct_data: Vec<E::BaseField> = unsafe {
            let mut data = std::mem::ManuallyDrop::new(gpu_struct_data);
            Vec::from_raw_parts(
                data.as_mut_ptr() as *mut E::BaseField,
                data.len(),
                data.capacity(),
            )
        };

        Ok((wit_data, struct_data))
    })?;

    let raw_witin = witness::RowMajorMatrix::new_by_values(
        wit_data,
        num_witin,
        InstancePaddingStrategy::Default,
    );
    let raw_structural_witin = witness::RowMajorMatrix::new_by_values(
        struct_data,
        num_structural_witin,
        InstancePaddingStrategy::Default,
    );

    tracing::info!(
        "GPU shard_ram assign_instances done: {} records, {} padded rows",
        steps.len(),
        num_rows_padded
    );

    Ok(Some([raw_witin, raw_structural_witin]))
}

/// GPU assign_instances from a device buffer of GpuShardRamRecord.
/// Avoids ShardRamInput → GpuShardRamRecord conversion and H2D transfer.
pub(crate) fn try_gpu_assign_shard_ram_from_device<E: ExtensionField>(
    config: &ShardRamConfig<E>,
    num_witin: usize,
    num_structural_witin: usize,
    device_records: &ceno_gpu::common::buffer::BufferImpl<'static, u32>,
    num_records: usize,
    num_local_writes: usize,
) -> Result<Option<crate::tables::RMMCollections<E::BaseField>>, ZKVMError> {
    use ceno_gpu::{Buffer, CudaHal, bb31::CudaHalBB31, common::transpose::matrix_transpose};
    use gkr_iop::gpu::gpu_prover::get_cuda_hal;
    use witness::{InstancePaddingStrategy, next_pow2_instance_padding};

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;

    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    let n = next_pow2_instance_padding(num_records);
    let num_rows_padded = 2 * n;

    let col_map = extract_shard_ram_column_map(config, num_witin);

    // GPU Phase 1: per-row assignment (records already on device)
    let (gpu_witness, gpu_structural) = tracing::info_span!(
        "gpu_shard_ram_per_row_from_device",
        n = num_records,
        num_rows_padded,
        num_witin,
    )
    .in_scope(|| {
        hal.witgen
            .witgen_shard_ram_per_row_from_device(
                &col_map,
                device_records,
                num_records,
                num_local_writes as u32,
                num_witin as u32,
                num_structural_witin as u32,
                num_rows_padded as u32,
                None,
            )
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("GPU shard_ram per-row (from_device) kernel failed: {e}").into(),
                )
            })
    })?;

    // GPU: extract EC points from device records
    let witness_buf = tracing::info_span!("gpu_shard_ram_ec_tree_from_device", n).in_scope(
        || -> Result<_, ZKVMError> {
            let col_offsets = col_map.to_flat();
            let gpu_cols = hal.alloc_u32_from_host(&col_offsets, None).map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU alloc col offsets failed: {e}").into())
            })?;

            let (mut cur_x, mut cur_y) = hal
                .witgen
                .extract_ec_points_from_device(device_records, num_records, n, None)
                .map_err(|e| {
                    ZKVMError::InvalidWitness(format!("GPU extract_ec_points failed: {e}").into())
                })?;

            let mut witness_buf = gpu_witness.device_buffer;
            let mut offset = num_rows_padded / 2;
            let mut current_layer_len = n;

            loop {
                if current_layer_len <= 1 {
                    break;
                }

                let (next_x, next_y) = hal
                    .witgen
                    .shard_ram_ec_tree_layer(
                        &gpu_cols,
                        &cur_x,
                        &cur_y,
                        &mut witness_buf,
                        current_layer_len,
                        offset,
                        num_rows_padded,
                        None,
                    )
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("GPU EC tree layer failed: {e}").into())
                    })?;

                current_layer_len /= 2;
                offset += current_layer_len;
                cur_x = next_x;
                cur_y = next_y;
            }

            Ok(witness_buf)
        },
    )?;

    // GPU transpose + D2H
    let (wit_data, struct_data) = tracing::info_span!(
        "gpu_shard_ram_transpose_d2h_from_device",
        num_rows_padded,
        num_witin,
    )
    .in_scope(|| -> Result<_, ZKVMError> {
        let wit_num_rows = num_rows_padded;
        let wit_num_cols = num_witin;
        let mut rmm_buf = hal
            .witgen
            .alloc_elems_on_device(wit_num_rows * wit_num_cols, false, None)
            .map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU alloc for transpose failed: {e}").into())
            })?;
        matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
            &hal.inner,
            &mut rmm_buf,
            &witness_buf,
            wit_num_rows,
            wit_num_cols,
        )
        .map_err(|e| ZKVMError::InvalidWitness(format!("GPU transpose failed: {e}").into()))?;

        let gpu_wit_data: Vec<BB> = rmm_buf
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU D2H wit failed: {e}").into()))?;
        let wit_data: Vec<E::BaseField> = unsafe {
            let mut data = std::mem::ManuallyDrop::new(gpu_wit_data);
            Vec::from_raw_parts(
                data.as_mut_ptr() as *mut E::BaseField,
                data.len(),
                data.capacity(),
            )
        };

        let struct_num_cols = num_structural_witin;
        let mut struct_rmm_buf = hal
            .witgen
            .alloc_elems_on_device(wit_num_rows * struct_num_cols, false, None)
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("GPU alloc for struct transpose failed: {e}").into(),
                )
            })?;
        matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
            &hal.inner,
            &mut struct_rmm_buf,
            &gpu_structural.device_buffer,
            wit_num_rows,
            struct_num_cols,
        )
        .map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU struct transpose failed: {e}").into())
        })?;

        let gpu_struct_data: Vec<BB> = struct_rmm_buf
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU D2H struct failed: {e}").into()))?;
        let struct_data: Vec<E::BaseField> = unsafe {
            let mut data = std::mem::ManuallyDrop::new(gpu_struct_data);
            Vec::from_raw_parts(
                data.as_mut_ptr() as *mut E::BaseField,
                data.len(),
                data.capacity(),
            )
        };

        Ok((wit_data, struct_data))
    })?;

    let raw_witin = witness::RowMajorMatrix::new_by_values(
        wit_data,
        num_witin,
        InstancePaddingStrategy::Default,
    );
    let raw_structural_witin = witness::RowMajorMatrix::new_by_values(
        struct_data,
        num_structural_witin,
        InstancePaddingStrategy::Default,
    );

    tracing::info!(
        "GPU shard_ram assign_instances (from_device) done: {} records, {} padded rows",
        num_records,
        num_rows_padded
    );

    Ok(Some([raw_witin, raw_structural_witin]))
}

/// Full GPU pipeline for assign_shared_circuit: device-resident EC merge + partition + assign.
/// Returns `Ok(None)` if GPU is unavailable, `Ok(Some(inputs))` on success.
#[allow(clippy::type_complexity)]
pub(crate) fn try_gpu_assign_shared_circuit<E: ExtensionField>(
    shard_ctx: &crate::e2e::ShardContext,
    final_mem: &[(
        &'static str,
        Option<std::ops::Range<ceno_emul::Addr>>,
        &[crate::tables::MemFinalRecord],
    )],
    config: &ShardRamConfig<E>,
    num_witin: usize,
    num_structural_witin: usize,
    max_chunk: usize,
) -> Result<Option<Vec<crate::structs::ChipInput<E>>>, ZKVMError> {
    use crate::{
        instructions::gpu::{
            chips::shard_ram::gpu_batch_continuation_ec_on_device,
            dispatch::take_shared_device_buffers,
        },
        structs::{ChipInput, ZKVMWitnesses},
        tables::{ShardRamCircuit, ShardRamInput, ShardRamRecord, TableCircuit},
    };
    use ceno_gpu::Buffer;
    use gkr_iop::gpu::get_cuda_hal;
    use rayon::prelude::*;
    use tracing::info_span;

    // 1. Take shared device buffers (if available)
    let mut shared = match take_shared_device_buffers() {
        Some(s) => s,
        None => return Ok(None),
    };

    let hal = match get_cuda_hal() {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    tracing::info!("[GPU full pipeline] starting device-resident assign_shared_circuit");

    // 2. D2H the EC count and addr count
    let ec_count = {
        let cv: Vec<u32> = shared
            .ec_count
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("shared_ec_count D2H: {e}").into()))?;
        cv[0] as usize
    };
    let addr_count = {
        let cv: Vec<u32> = shared
            .addr_count
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("shared_addr_count D2H: {e}").into()))?;
        cv[0] as usize
    };

    tracing::info!(
        "[GPU full pipeline] shared buffers: {} EC records, {} addr_accessed",
        ec_count,
        addr_count,
    );

    // 3. GPU sort addr_accessed + dedup, then D2H sorted unique addrs
    let addr_accessed: Vec<ceno_emul::WordAddr> = if addr_count > 0 {
        info_span!("gpu_sort_addr").in_scope(|| {
            let (deduped, unique_count) = hal
                .witgen
                .sort_and_dedup_u32(&mut shared.addr_buf, addr_count, None)
                .map_err(|e| ZKVMError::InvalidWitness(format!("GPU sort addr: {e}").into()))?;
            if unique_count == 0 {
                return Ok::<Vec<ceno_emul::WordAddr>, ZKVMError>(vec![]);
            }
            let addrs: Vec<ceno_emul::WordAddr> =
                deduped.into_iter().map(ceno_emul::WordAddr).collect();
            tracing::info!(
                "[GPU full pipeline] sorted {} addrs → {} unique",
                addr_count,
                unique_count,
            );
            Ok(addrs)
        })?
    } else {
        vec![]
    };

    // 4. CPU collect_records (uses sorted unique addrs)
    let (write_record_pairs, read_record_pairs) = info_span!("collect_records").in_scope(|| {
        let first_shard_access_later_recs: Vec<(ShardRamRecord, &'static str)> =
            if shard_ctx.is_first_shard() {
                final_mem
                    .par_iter()
                    .filter(|(_, range, _)| range.is_none())
                    .flat_map(|(mem_name, _, final_mem)| {
                        final_mem.par_iter().filter_map(|mem_record| {
                            let (waddr, addr) = ZKVMWitnesses::<E>::mem_addresses(mem_record);
                            ZKVMWitnesses::<E>::make_cross_shard_record(
                                mem_name,
                                mem_record,
                                waddr,
                                addr,
                                shard_ctx,
                                &addr_accessed,
                            )
                        })
                    })
                    .collect()
            } else {
                vec![]
            };

        let current_shard_access_later_recs: Vec<(ShardRamRecord, &'static str)> = final_mem
            .par_iter()
            .filter(|(_, range, _)| range.is_some())
            .flat_map(|(mem_name, range, final_mem)| {
                let range = range.as_ref().unwrap();
                final_mem.par_iter().filter_map(|mem_record| {
                    let (waddr, addr) = ZKVMWitnesses::<E>::mem_addresses(mem_record);
                    if !range.contains(&addr) {
                        return None;
                    }
                    ZKVMWitnesses::<E>::make_cross_shard_record(
                        mem_name,
                        mem_record,
                        waddr,
                        addr,
                        shard_ctx,
                        &addr_accessed,
                    )
                })
            })
            .collect();

        let write_record_pairs: Vec<(ShardRamRecord, &'static str)> = shard_ctx
            .write_records()
            .iter()
            .flat_map(|records| {
                records.iter().map(|(vma, record)| {
                    ((vma, record, true).into(), "current_shard_external_write")
                })
            })
            .chain(first_shard_access_later_recs)
            .chain(current_shard_access_later_recs)
            .collect();

        let read_record_pairs: Vec<(ShardRamRecord, &'static str)> = shard_ctx
            .read_records()
            .iter()
            .flat_map(|records| {
                records.iter().map(|(vma, record)| {
                    ((vma, record, false).into(), "current_shard_external_read")
                })
            })
            .collect();

        (write_record_pairs, read_record_pairs)
    });

    // 5. GPU batch EC on device for continuation records
    let (cont_ec_buf, cont_n_writes, cont_n_reads) = info_span!("gpu_batch_ec_on_device")
        .in_scope(|| {
            gpu_batch_continuation_ec_on_device(&write_record_pairs, &read_record_pairs)
        })?;
    let cont_total = cont_n_writes + cont_n_reads;

    tracing::info!(
        "[GPU full pipeline] batch EC on device: {} writes + {} reads = {} continuation records",
        cont_n_writes,
        cont_n_reads,
        cont_total,
    );

    // 6. GPU merge shared_ec + batch_ec, then partition by is_to_write_set
    let (partitioned_buf, num_writes, total_records) =
        info_span!("gpu_merge_partition").in_scope(|| {
            hal.witgen
                .merge_and_partition_records(
                    &shared.ec_buf,
                    ec_count,
                    &cont_ec_buf,
                    cont_total,
                    None,
                )
                .map_err(|e| ZKVMError::InvalidWitness(format!("GPU merge+partition: {e}").into()))
        })?;

    tracing::info!(
        "[GPU full pipeline] merged+partitioned: {} total ({} writes, {} reads)",
        total_records,
        num_writes,
        total_records - num_writes,
    );

    // 7. GPU assign_instances from device buffer (chunked by max_cross_shard)
    let record_u32s = std::mem::size_of::<ceno_gpu::common::witgen::types::GpuShardRamRecord>() / 4;

    let circuit_inputs =
        info_span!("shard_ram_assign_from_device", n = total_records).in_scope(|| {
            let mut inputs = Vec::new();
            let mut records_offset = 0usize;
            let mut writes_remaining = num_writes;

            while records_offset < total_records {
                let chunk_size = max_chunk.min(total_records - records_offset);
                let chunk_writes = writes_remaining.min(chunk_size);
                writes_remaining = writes_remaining.saturating_sub(chunk_size);

                let chunk_byte_start = records_offset * record_u32s * 4;
                let chunk_byte_end = (records_offset + chunk_size) * record_u32s * 4;
                let chunk_view = partitioned_buf.as_slice_range(chunk_byte_start..chunk_byte_end);
                let chunk_buf: ceno_gpu::common::buffer::BufferImpl<'static, u32> = unsafe {
                    std::mem::transmute(ceno_gpu::common::buffer::BufferImpl::<u32>::new_from_view(
                        chunk_view,
                    ))
                };

                let witness = ShardRamCircuit::<E>::try_gpu_assign_instances_from_device(
                    config,
                    num_witin,
                    num_structural_witin,
                    &chunk_buf,
                    chunk_size,
                    chunk_writes,
                )?;

                let witness = witness.ok_or_else(|| {
                    ZKVMError::InvalidWitness("GPU shard_ram from_device returned None".into())
                })?;

                let num_reads = chunk_size - chunk_writes;
                inputs.push(ChipInput::new(
                    ShardRamCircuit::<E>::name(),
                    witness,
                    vec![chunk_writes, num_reads],
                ));

                records_offset += chunk_size;
            }
            Ok::<_, ZKVMError>(inputs)
        })?;

    tracing::info!(
        "[GPU full pipeline] assign_shared_circuit complete: {} total records",
        total_records,
    );

    Ok(Some(circuit_inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        structs::ProgramParams,
        tables::{ShardRamCircuit, TableCircuit},
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_shard_ram_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            ShardRamCircuit::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();

        let col_map = extract_shard_ram_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        // Basic columns should be in range
        // (excluding poseidon2 meta entries which are counts, not column IDs)
        for (i, &col) in flat[..30].iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (flat index {}) out of range: {} >= {}",
                col,
                i,
                col,
                col_map.num_cols
            );
        }

        // Check uniqueness of actual column IDs (first 30 entries)
        let mut seen = std::collections::HashSet::new();
        for &col in &flat[..30] {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }

        // Verify Poseidon2 column counts are reasonable
        assert_eq!(col_map.num_p3_cols, 299, "Expected 299 p3 cols");
        assert_eq!(
            col_map.num_poseidon2_cols, 344,
            "Expected 344 total Poseidon2 cols"
        );
    }
}
