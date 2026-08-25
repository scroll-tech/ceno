use ceno_emul::WordAddr;
use ceno_gpu::common::witgen::types::ShardRamColumnMap;
use ff_ext::ExtensionField;
use gkr_iop::RAMType;
use rustc_hash::FxHashSet;

use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    tables::{
        MemFinalRecord, ShardRamConfig, ShardRamEcTreeConfig, ShardRamRecord,
        Y6_LO_TOP_BYTE_LT_BOUND,
    },
};

/// Filter and construct a cross-shard ShardRamRecord without EC computation.
/// EC is computed in batch on device by the GPU pipeline.
#[inline(always)]
fn make_cross_shard_record(
    mem_name: &'static str,
    mem_record: &MemFinalRecord,
    waddr: WordAddr,
    addr: u32,
    shard_ctx: &ShardContext,
    addr_accessed: &FxHashSet<WordAddr>,
) -> Option<(ShardRamRecord, &'static str)> {
    if addr_accessed.contains(&waddr) || !shard_ctx.after_current_shard_cycle(mem_record.cycle) {
        return None;
    }

    let global_write = ShardRamRecord {
        addr: match mem_record.ram_type {
            RAMType::Register => addr,
            RAMType::Memory => waddr.into(),
            _ => unimplemented!(),
        },
        ram_type: mem_record.ram_type,
        value: mem_record.init_value,
        shard: shard_ctx.shard_id as u64,
        local_clk: 0,
        global_clk: 0,
        is_to_write_set: true,
    };
    Some((global_write, mem_name))
}

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
    for i in 0..7 {
        x[i] = config.x[i].id as u32;
        y[i] = config.y[i].id as u32;
    }
    let y6_lo_bytes = std::array::from_fn(|i| config.y6_lo_bytes[i].id as u32);

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
        y6_lo_bytes,
        slope: [0; 7],
        poseidon2_base_col,
        num_poseidon2_cols,
        num_p3_cols,
        num_cols: num_witin as u32,
    }
}

pub fn extract_shard_ram_ec_tree_column_map<E: ExtensionField>(
    config: &ShardRamEcTreeConfig<E>,
    num_witin: usize,
) -> ShardRamColumnMap {
    let mut x = [0u32; 7];
    let mut y = [0u32; 7];
    let mut slope = [0u32; 7];
    for i in 0..7 {
        x[i] = config.x[i].id as u32;
        y[i] = config.y[i].id as u32;
        slope[i] = config.slope[i].id as u32;
    }

    ShardRamColumnMap {
        addr: 0,
        is_ram_register: 0,
        value: [0; 2],
        shard: 0,
        global_clk: 0,
        local_clk: 0,
        nonce: 0,
        is_global_write: 0,
        x,
        y,
        y6_lo_bytes: [0; 4],
        slope,
        poseidon2_base_col: 0,
        num_poseidon2_cols: 0,
        num_p3_cols: 0,
        num_cols: num_witin as u32,
    }
}

// ---------------------------------------------------------------------------
// ShardRam EC batch computation
// ---------------------------------------------------------------------------

use ceno_gpu::common::witgen::types::GpuShardRamRecord;
use tracing::info_span;

const LEGACY_SEGMENT_SHIFT: u32 = 62;
const LEGACY_BUCKET_LIMIT: usize = 1usize << 30;
const LEGACY_FIRST_CONTINUATION_SEGMENT: u64 = 1;
const LEGACY_CURRENT_CONTINUATION_SEGMENT: u64 = 2;

fn legacy_btree_ordinal(
    is_write: bool,
    bucket: usize,
    addr: ceno_emul::WordAddr,
) -> Result<u64, ZKVMError> {
    if bucket >= LEGACY_BUCKET_LIMIT {
        return Err(ZKVMError::InvalidWitness(
            format!("legacy ShardRAM bucket {bucket} exceeds 30 bits").into(),
        ));
    }
    let segment = if is_write { 0 } else { 3u64 };
    Ok((segment << LEGACY_SEGMENT_SHIFT) | ((bucket as u64) << 32) | u64::from(addr.0))
}

fn legacy_continuation_ordinal(segment: u64, index: usize) -> Result<u64, ZKVMError> {
    let index = u64::try_from(index)
        .map_err(|_| ZKVMError::InvalidWitness("continuation index exceeds u64".into()))?;
    if index >= (1u64 << LEGACY_SEGMENT_SHIFT) {
        return Err(ZKVMError::InvalidWitness(
            "continuation index exceeds ordinal segment".into(),
        ));
    }
    Ok((segment << LEGACY_SEGMENT_SHIFT) | index)
}

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
        ordinal: 0,
        shard: rec.shard,
        local_clk: rec.local_clk,
        global_clk: rec.global_clk,
        is_to_write_set: if rec.is_to_write_set { 1 } else { 0 },
        nonce: 0,
        point_x: [0; 7],
        point_y: [0; 7],
    }
}

fn shard_ram_record_to_gpu_with_ordinal(
    rec: &crate::tables::ShardRamRecord,
    ordinal: u64,
) -> GpuShardRamRecord {
    GpuShardRamRecord {
        ordinal,
        ..shard_ram_record_to_gpu(rec)
    }
}

/// Batch compute EC points on GPU, results stay on device.
///
/// Used by the full GPU pipeline in `structs.rs` where records feed directly
/// into `merge_and_finalize_records` on device without D2H.
pub fn gpu_batch_continuation_ec_on_device(
    write_records: &[(crate::tables::ShardRamRecord, &'static str, u64)],
    read_records: &[(crate::tables::ShardRamRecord, &'static str, u64)],
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
    for (rec, _name, ordinal) in write_records.iter().chain(read_records.iter()) {
        gpu_records.push(shard_ram_record_to_gpu_with_ordinal(rec, *ordinal));
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
/// Returns `Ok(None)` if GPU is unavailable or disabled. On success the
/// y6_lo byte / LTU lookup multiplicity is derived from `steps` and pushed
/// into `lk_multiplicity` so the caller sees the same per-row contribution
/// the CPU `assign_instance` path would have made.
pub(crate) fn try_gpu_assign_shard_ram<E: ExtensionField>(
    config: &ShardRamConfig<E>,
    num_witin: usize,
    num_structural_witin: usize,
    lk_multiplicity: &mut crate::witness::LkMultiplicity,
    steps: &[crate::tables::ShardRamInput<E>],
) -> Result<Option<crate::tables::RMMCollections<E::BaseField>>, ZKVMError> {
    use crate::scheme::constants::SEPTIC_EXTENSION_DEGREE;
    use ceno_gpu::{
        Buffer,
        bb31::CudaHalBB31,
        common::{transpose::matrix_transpose, witgen::types::GpuShardRamRecord},
    };
    use gkr_iop::gpu::gpu_prover::get_cuda_hal;
    use p3::field::PrimeField32;
    use witness::{DeviceMatrixLayout, InstancePaddingStrategy, next_pow2_instance_padding};

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;

    if crate::instructions::gpu::dispatch::is_force_cpu_path() {
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

    let num_rows_padded = next_pow2_instance_padding(steps.len());

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

    let witness_buf = gpu_witness.device_buffer;

    // 5. Structural witness: keep device-resident only when cache policy keeps device backing.
    // In debug mode or cache-none mode, do transpose + D2H.
    let raw_structural_witin = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        let struct_data = tracing::info_span!(
            "gpu_shard_ram_structural_transpose_d2h",
            rows = gpu_structural.num_rows,
            num_structural_witin,
        )
        .in_scope(|| -> Result<_, ZKVMError> {
            let wit_num_rows = gpu_structural.num_rows;
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

            let gpu_struct_data: Vec<BB> = struct_rmm_buf.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU D2H struct failed: {e}").into())
            })?;
            let out: Vec<E::BaseField> = unsafe {
                let mut data = std::mem::ManuallyDrop::new(gpu_struct_data);
                Vec::from_raw_parts(
                    data.as_mut_ptr() as *mut E::BaseField,
                    data.len(),
                    data.capacity(),
                )
            };

            Ok(out)
        })?;
        witness::RowMajorMatrix::new_by_values(
            struct_data,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        )
    } else {
        witness::RowMajorMatrix::new_by_device_backing(
            steps.len(),
            num_structural_witin,
            InstancePaddingStrategy::Default,
            gpu_structural.device_buffer,
            DeviceMatrixLayout::ColMajor,
        )
    };

    // 6. Main witness: keep device-resident only when cache policy keeps device backing.
    // In debug mode or cache-none mode, do transpose + D2H.
    let raw_witin = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        tracing::info_span!(
            "gpu_shard_ram_witness_transpose_d2h",
            num_rows_padded,
            num_witin
        )
        .in_scope(|| -> Result<_, ZKVMError> {
            let mut rmm_buf = hal
                .witgen
                .alloc_elems_on_device(num_rows_padded * num_witin, false, None)
                .map_err(|e| {
                    ZKVMError::InvalidWitness(
                        format!("GPU alloc for witness transpose failed: {e}").into(),
                    )
                })?;
            matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
                &hal.inner,
                &mut rmm_buf,
                &witness_buf,
                num_rows_padded,
                num_witin,
            )
            .map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU witness transpose failed: {e}").into())
            })?;

            let gpu_wit_data: Vec<BB> = rmm_buf.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU D2H witness failed: {e}").into())
            })?;
            let wit_data: Vec<E::BaseField> = unsafe {
                let mut data = std::mem::ManuallyDrop::new(gpu_wit_data);
                Vec::from_raw_parts(
                    data.as_mut_ptr() as *mut E::BaseField,
                    data.len(),
                    data.capacity(),
                )
            };
            Ok(witness::RowMajorMatrix::new_by_values(
                wit_data,
                num_witin,
                InstancePaddingStrategy::Default,
            ))
        })?
    } else {
        witness::RowMajorMatrix::new_by_device_backing(
            steps.len(),
            num_witin,
            InstancePaddingStrategy::Default,
            witness_buf,
            DeviceMatrixLayout::ColMajor,
        )
    };

    tracing::info!(
        "GPU shard_ram assign_instances done: {} records, {} padded rows",
        steps.len(),
        num_rows_padded
    );

    // Debug: compare GPU witness against CPU baseline
    if crate::instructions::gpu::config::is_debug_compare_enabled() {
        crate::instructions::gpu::utils::debug_compare::debug_compare_shard_ram_witness::<E>(
            config,
            num_witin,
            num_structural_witin,
            steps,
            &raw_witin,
            &raw_structural_witin,
        );
    }

    // The GPU witness kernel above writes the row data but does not run
    // the per-row `assign_instance` CPU path that pushes the y6_lo byte /
    // LTU lookup multiplicity. Derive the same contribution from `steps`
    // here so the caller's `lk_multiplicity` mirrors the CPU branch and
    // `combined_lk_mlt` balances the U8 / LTU table `mlt` columns. Source
    // of truth for the queries is `ShardRamConfig::configure`.
    for step in steps {
        let y6_lo = crate::tables::y6_lo_value::<E>(
            step.ec_point.point.y.0[SEPTIC_EXTENSION_DEGREE - 1],
            step.record.is_to_write_set,
        );
        for i in 0..3 {
            lk_multiplicity.assert_const_range((y6_lo >> (8 * i)) & 0xff, 8);
        }
        lk_multiplicity.lookup_ltu_byte((y6_lo >> 24) & 0xff, Y6_LO_TOP_BYTE_LT_BOUND);
    }

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
    use ceno_gpu::{Buffer, bb31::CudaHalBB31, common::transpose::matrix_transpose};
    use gkr_iop::gpu::gpu_prover::get_cuda_hal;
    use witness::{DeviceMatrixLayout, InstancePaddingStrategy, next_pow2_instance_padding};

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;

    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    let num_rows_padded = next_pow2_instance_padding(num_records);

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
                    format!("GPU shard_ram per-row (from_device) kernel failed: {e:?}").into(),
                )
            })
    })?;

    let witness_buf = gpu_witness.device_buffer;

    // Structural witness: keep device-resident only when cache policy keeps device backing.
    // In debug mode or cache-none mode, do transpose + D2H.
    let raw_structural_witin = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        let struct_data = tracing::info_span!(
            "gpu_shard_ram_structural_transpose_d2h_from_device",
            rows = gpu_structural.num_rows,
            num_structural_witin,
        )
        .in_scope(|| -> Result<_, ZKVMError> {
            let wit_num_rows = gpu_structural.num_rows;
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

            let gpu_struct_data: Vec<BB> = struct_rmm_buf.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU D2H struct failed: {e}").into())
            })?;
            let out: Vec<E::BaseField> = unsafe {
                let mut data = std::mem::ManuallyDrop::new(gpu_struct_data);
                Vec::from_raw_parts(
                    data.as_mut_ptr() as *mut E::BaseField,
                    data.len(),
                    data.capacity(),
                )
            };

            Ok(out)
        })?;
        witness::RowMajorMatrix::new_by_values(
            struct_data,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        )
    } else {
        witness::RowMajorMatrix::new_by_device_backing(
            num_records,
            num_structural_witin,
            InstancePaddingStrategy::Default,
            gpu_structural.device_buffer,
            DeviceMatrixLayout::ColMajor,
        )
    };

    // Witness: keep device-resident only when cache policy keeps device backing.
    // In debug mode or cache-none mode, do transpose + D2H.
    let raw_witin = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        tracing::info_span!(
            "gpu_shard_ram_witness_transpose_d2h_from_device",
            num_rows_padded,
            num_witin,
        )
        .in_scope(|| -> Result<_, ZKVMError> {
            let mut rmm_buf = hal
                .witgen
                .alloc_elems_on_device(num_rows_padded * num_witin, false, None)
                .map_err(|e| {
                    ZKVMError::InvalidWitness(
                        format!("GPU alloc for witness transpose failed: {e}").into(),
                    )
                })?;
            matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
                &hal.inner,
                &mut rmm_buf,
                &witness_buf,
                num_rows_padded,
                num_witin,
            )
            .map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU witness transpose failed: {e}").into())
            })?;

            let gpu_wit_data: Vec<BB> = rmm_buf.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU D2H witness failed: {e}").into())
            })?;
            let wit_data: Vec<E::BaseField> = unsafe {
                let mut data = std::mem::ManuallyDrop::new(gpu_wit_data);
                Vec::from_raw_parts(
                    data.as_mut_ptr() as *mut E::BaseField,
                    data.len(),
                    data.capacity(),
                )
            };
            Ok(witness::RowMajorMatrix::new_by_values(
                wit_data,
                num_witin,
                InstancePaddingStrategy::Default,
            ))
        })?
    } else {
        witness::RowMajorMatrix::new_by_device_backing(
            num_records,
            num_witin,
            InstancePaddingStrategy::Default,
            witness_buf,
            DeviceMatrixLayout::ColMajor,
        )
    };

    tracing::info!(
        "GPU shard_ram assign_instances (from_device) done: {} records, {} padded rows",
        num_records,
        num_rows_padded
    );

    // Debug: compare GPU witness against CPU baseline (D2H + convert + CPU assign)
    if crate::instructions::gpu::config::is_debug_compare_enabled() {
        crate::instructions::gpu::utils::debug_compare::debug_compare_shard_ram_witness_from_device::<
            E,
        >(
            config,
            num_witin,
            num_structural_witin,
            device_records,
            num_records,
            num_local_writes,
            &raw_witin,
            &raw_structural_witin,
        );
    }

    Ok(Some([raw_witin, raw_structural_witin]))
}

pub(crate) fn try_gpu_assign_shard_ram_ec_tree_from_device<E: ExtensionField>(
    config: &ShardRamEcTreeConfig<E>,
    num_witin: usize,
    num_structural_witin: usize,
    device_records: &ceno_gpu::common::buffer::BufferImpl<'static, u32>,
    num_records: usize,
    num_write_records: usize,
) -> Result<Option<crate::tables::RMMCollections<E::BaseField>>, ZKVMError> {
    use ceno_gpu::{Buffer, CudaHal, bb31::CudaHalBB31, common::transpose::matrix_transpose};
    use gkr_iop::gpu::gpu_prover::get_cuda_hal;
    use witness::{DeviceMatrixLayout, InstancePaddingStrategy, next_pow2_instance_padding};

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;

    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    if num_records == 0 {
        return Ok(Some([
            witness::RowMajorMatrix::empty(),
            witness::RowMajorMatrix::empty(),
        ]));
    }

    let n = next_pow2_instance_padding(num_records);
    let num_rows_padded = 2 * n;
    let col_map = extract_shard_ram_ec_tree_column_map(config, num_witin);

    let (mut gpu_witness, gpu_structural, mut cur_x, mut cur_y) = tracing::info_span!(
        "gpu_shard_ram_ec_tree_per_row_from_device",
        n = num_records,
        num_write_records,
        num_rows_padded,
        num_witin,
    )
    .in_scope(|| {
        hal.witgen
            .witgen_shard_ram_ec_tree_per_row_from_device(
                &col_map,
                device_records,
                num_records,
                num_write_records,
                num_witin as u32,
                num_structural_witin as u32,
                num_rows_padded as u32,
                None,
            )
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("GPU shard_ram EC tree per-row kernel failed: {e:?}").into(),
                )
            })
    })?;

    tracing::info_span!("gpu_shard_ram_ec_tree_layers_from_device", n).in_scope(
        || -> Result<(), ZKVMError> {
            let col_offsets = col_map.to_flat();
            let gpu_cols = hal.alloc_u32_from_host(&col_offsets, None).map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU alloc col offsets failed: {e}").into())
            })?;

            let mut offset = n;
            let mut current_layer_len = n;
            while current_layer_len > 1 {
                let (next_x, next_y) = hal
                    .witgen
                    .shard_ram_ec_tree_layer(
                        &gpu_cols,
                        &cur_x,
                        &cur_y,
                        &mut gpu_witness.device_buffer,
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

            Ok(())
        },
    )?;

    let raw_structural_witin = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        let struct_data = tracing::info_span!(
            "gpu_shard_ram_ec_tree_structural_transpose_d2h_from_device",
            rows = gpu_structural.num_rows,
            num_structural_witin,
        )
        .in_scope(|| -> Result<_, ZKVMError> {
            let mut struct_rmm_buf = hal
                .witgen
                .alloc_elems_on_device(num_rows_padded * num_structural_witin, false, None)
                .map_err(|e| {
                    ZKVMError::InvalidWitness(
                        format!("GPU alloc for EC tree struct transpose failed: {e}").into(),
                    )
                })?;
            matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
                &hal.inner,
                &mut struct_rmm_buf,
                &gpu_structural.device_buffer,
                num_rows_padded,
                num_structural_witin,
            )
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("GPU EC tree struct transpose failed: {e}").into(),
                )
            })?;

            let gpu_struct_data: Vec<BB> = struct_rmm_buf.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU D2H EC tree struct failed: {e}").into())
            })?;
            let out: Vec<E::BaseField> = unsafe {
                let mut data = std::mem::ManuallyDrop::new(gpu_struct_data);
                Vec::from_raw_parts(
                    data.as_mut_ptr() as *mut E::BaseField,
                    data.len(),
                    data.capacity(),
                )
            };
            Ok(out)
        })?;
        witness::RowMajorMatrix::new_by_values(
            struct_data,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        )
    } else {
        witness::RowMajorMatrix::new_by_rotation_device_backing(
            num_records,
            1,
            num_structural_witin,
            InstancePaddingStrategy::Default,
            gpu_structural.device_buffer,
            DeviceMatrixLayout::ColMajor,
        )
    };

    let raw_witin = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        tracing::info_span!(
            "gpu_shard_ram_ec_tree_witness_transpose_d2h_from_device",
            num_rows_padded,
            num_witin,
        )
        .in_scope(|| -> Result<_, ZKVMError> {
            let mut rmm_buf = hal
                .witgen
                .alloc_elems_on_device(num_rows_padded * num_witin, false, None)
                .map_err(|e| {
                    ZKVMError::InvalidWitness(
                        format!("GPU alloc for EC tree witness transpose failed: {e}").into(),
                    )
                })?;
            matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
                &hal.inner,
                &mut rmm_buf,
                &gpu_witness.device_buffer,
                num_rows_padded,
                num_witin,
            )
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("GPU EC tree witness transpose failed: {e}").into(),
                )
            })?;

            let gpu_wit_data: Vec<BB> = rmm_buf.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU D2H EC tree witness failed: {e}").into())
            })?;
            let wit_data: Vec<E::BaseField> = unsafe {
                let mut data = std::mem::ManuallyDrop::new(gpu_wit_data);
                Vec::from_raw_parts(
                    data.as_mut_ptr() as *mut E::BaseField,
                    data.len(),
                    data.capacity(),
                )
            };
            Ok(witness::RowMajorMatrix::new_by_values(
                wit_data,
                num_witin,
                InstancePaddingStrategy::Default,
            ))
        })?
    } else {
        witness::RowMajorMatrix::new_by_rotation_device_backing(
            num_records,
            1,
            num_witin,
            InstancePaddingStrategy::Default,
            gpu_witness.device_buffer,
            DeviceMatrixLayout::ColMajor,
        )
    };

    Ok(Some([raw_witin, raw_structural_witin]))
}

/// Full GPU pipeline for assign_shared_circuit: device-resident EC merge + partition + assign.
/// Returns `Ok(None)` if GPU is unavailable, `Ok(Some((inputs, lk_mlt)))` on
/// success — `lk_mlt` carries the y6_lo byte / LTU lookup multiplicity that
/// `ShardRamConfig::configure` consumes (mirrors the per-row CPU push in
/// `ShardRamCircuit::assign_instance`).
#[allow(clippy::type_complexity)]
pub(crate) fn try_gpu_assign_shared_circuit<E: ExtensionField>(
    shard_ctx: &crate::e2e::ShardContext,
    final_mem: &[(
        &'static str,
        Option<std::ops::Range<ceno_emul::Addr>>,
        &[crate::tables::MemFinalRecord],
    )],
    config: &ShardRamConfig<E>,
    ec_tree_config: &crate::tables::ShardRamEcTreeConfig<E>,
    num_witin: usize,
    num_structural_witin: usize,
    ec_tree_num_witin: usize,
    ec_tree_num_structural_witin: usize,
) -> Result<
    Option<(
        Vec<crate::structs::ChipInput<E>>,
        Vec<crate::structs::ChipInput<E>>,
        gkr_iop::utils::lk_multiplicity::Multiplicity<u64>,
    )>,
    ZKVMError,
> {
    use crate::{
        instructions::gpu::{
            chips::shard_ram::{
                gpu_batch_continuation_ec_on_device, try_gpu_assign_shard_ram_ec_tree_from_device,
            },
            dispatch::take_shared_device_buffers,
        },
        structs::{ChipInput, ZKVMWitnesses},
        tables::{ShardRamCircuit, ShardRamEcTreeCircuit, ShardRamRecord, TableCircuit},
        witness::LkMultiplicity,
    };
    use ceno_gpu::Buffer;
    use ff_ext::SmallField;
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
    let emission_expected = {
        let cv: Vec<u32> = shared.emission_expected.to_vec().map_err(|e| {
            ZKVMError::InvalidWitness(format!("emission expectations D2H: {e}").into())
        })?;
        if cv.len() != 3 {
            return Err(ZKVMError::InvalidWitness(
                "emission expectation ABI length mismatch".into(),
            ));
        }
        ceno_gpu::common::witgen::types::EmissionExpectations {
            writes: cv[0],
            reads: cv[1],
            addresses: cv[2],
        }
    };
    let expected_ec = emission_expected
        .writes
        .checked_add(emission_expected.reads)
        .ok_or_else(|| ZKVMError::InvalidWitness("expected EC count overflow".into()))?
        as usize;
    let ec_capacity = shared.ec_buf.len()
        / (std::mem::size_of::<ceno_gpu::common::witgen::types::GpuShardRamRecord>() / 4);
    let addr_capacity = shared.addr_buf.len();
    if ec_count != expected_ec || addr_count > shared.reserved_address_capacity as usize {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "emission mismatch: EC observed={ec_count} expected={expected_ec}; address observed={addr_count} reserved={}",
                shared.reserved_address_capacity,
            ).into(),
        ));
    }
    if ec_count > ec_capacity
        || expected_ec > ec_capacity
        || addr_count > addr_capacity
        || shared.reserved_address_capacity as usize > addr_capacity
    {
        return Err(ZKVMError::InvalidWitness(
            "emission count exceeds allocated capacity".into(),
        ));
    }

    tracing::info!(
        ec_observed = ec_count,
        ec_expected_writes = emission_expected.writes,
        ec_expected_reads = emission_expected.reads,
        address_observed = addr_count,
        address_reserved = shared.reserved_address_capacity,
        address_capacity = addr_capacity,
        "GPU emission contract validated"
    );

    tracing::info!(
        "[GPU full pipeline] shared buffers: {} EC records, {} addr_accessed",
        ec_count,
        addr_count,
    );

    // 3. Build the unique address set on GPU. Preserve the dense input so hash
    // overflow or probe exhaustion can fall back to the existing exact sort.
    let addr_accessed: Vec<ceno_emul::WordAddr> = if addr_count > 0 {
        info_span!("gpu_unique_addr").in_scope(|| {
            let deduped = match hal
                .witgen
                .hash_dedup_u32(&shared.addr_buf, addr_count, None)
                .map_err(|e| ZKVMError::InvalidWitness(format!("GPU hash addr: {e}").into()))?
            {
                Some(addrs) => addrs,
                None => {
                    tracing::warn!(
                        "[GPU full pipeline] address hash table exhausted; falling back to sort"
                    );
                    hal.witgen
                        .sort_and_dedup_u32(&mut shared.addr_buf, addr_count, None)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU sort addr fallback: {e}").into())
                        })?
                        .0
                }
            };
            let unique_count = deduped.len();
            if unique_count == 0 {
                return Ok::<Vec<ceno_emul::WordAddr>, ZKVMError>(vec![]);
            }
            let addrs: Vec<ceno_emul::WordAddr> =
                deduped.into_iter().map(ceno_emul::WordAddr).collect();
            tracing::info!(
                "[GPU full pipeline] aggregated {} addrs → {} unique",
                addr_count,
                unique_count,
            );
            Ok(addrs)
        })?
    } else {
        vec![]
    };

    // 4. CPU collect_records (uses unique addrs)
    let addr_accessed: rustc_hash::FxHashSet<ceno_emul::WordAddr> =
        addr_accessed.into_iter().collect();
    let (write_record_pairs, read_record_pairs, continuation_segments) =
        info_span!("collect_records").in_scope(|| {
            let first_shard_access_later_recs: Vec<(ShardRamRecord, &'static str)> =
                if shard_ctx.is_first_shard() {
                    final_mem
                        .par_iter()
                        .filter(|(_, range, _)| range.is_none())
                        .flat_map(|(mem_name, _, final_mem)| {
                            final_mem.par_iter().filter_map(|mem_record| {
                                let (waddr, addr) = ZKVMWitnesses::<E>::mem_addresses(mem_record);
                                make_cross_shard_record(
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
                        make_cross_shard_record(
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

            let mut write_record_pairs: Vec<(ShardRamRecord, &'static str, u64)> = shard_ctx
                .write_records()
                .iter()
                .enumerate()
                .flat_map(|(bucket, records)| {
                    records.iter().map(move |(vma, record)| {
                        Ok((
                            (vma, record, true).into(),
                            "current_shard_external_write",
                            legacy_btree_ordinal(true, bucket, *vma)?,
                        ))
                    })
                })
                .collect::<Result<_, ZKVMError>>()?;
            let segment0 = u32::try_from(write_record_pairs.len())
                .map_err(|_| ZKVMError::InvalidWitness("segment 0 count exceeds u32".into()))?;
            let segment1 = u32::try_from(first_shard_access_later_recs.len())
                .map_err(|_| ZKVMError::InvalidWitness("segment 1 count exceeds u32".into()))?;
            let segment2 = u32::try_from(current_shard_access_later_recs.len())
                .map_err(|_| ZKVMError::InvalidWitness("segment 2 count exceeds u32".into()))?;
            write_record_pairs.extend(
                first_shard_access_later_recs
                    .into_iter()
                    .enumerate()
                    .map(|(index, (record, name))| {
                        Ok((
                            record,
                            name,
                            legacy_continuation_ordinal(LEGACY_FIRST_CONTINUATION_SEGMENT, index)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, ZKVMError>>()?,
            );
            write_record_pairs.extend(
                current_shard_access_later_recs
                    .into_iter()
                    .enumerate()
                    .map(|(index, (record, name))| {
                        Ok((
                            record,
                            name,
                            legacy_continuation_ordinal(
                                LEGACY_CURRENT_CONTINUATION_SEGMENT,
                                index,
                            )?,
                        ))
                    })
                    .collect::<Result<Vec<_>, ZKVMError>>()?,
            );

            let read_record_pairs: Vec<(ShardRamRecord, &'static str, u64)> = shard_ctx
                .read_records()
                .iter()
                .enumerate()
                .flat_map(|(bucket, records)| {
                    records.iter().map(move |(vma, record)| {
                        Ok((
                            (vma, record, false).into(),
                            "current_shard_external_read",
                            legacy_btree_ordinal(false, bucket, *vma)?,
                        ))
                    })
                })
                .collect::<Result<_, ZKVMError>>()?;
            let segment3 = u32::try_from(read_record_pairs.len())
                .map_err(|_| ZKVMError::InvalidWitness("segment 3 count exceeds u32".into()))?;

            Ok::<_, ZKVMError>((
                write_record_pairs,
                read_record_pairs,
                [segment0, segment1, segment2, segment3],
            ))
        })?;

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
    let mut expected_segments = continuation_segments;
    expected_segments[0] = expected_segments[0]
        .checked_add(emission_expected.writes)
        .ok_or_else(|| ZKVMError::InvalidWitness("segment 0 expectation overflow".into()))?;
    expected_segments[3] = expected_segments[3]
        .checked_add(emission_expected.reads)
        .ok_or_else(|| ZKVMError::InvalidWitness("segment 3 expectation overflow".into()))?;
    let continuation_writes = continuation_segments[0]
        .checked_add(continuation_segments[1])
        .and_then(|count| count.checked_add(continuation_segments[2]))
        .ok_or_else(|| ZKVMError::InvalidWitness("continuation write count overflow".into()))?;
    if cont_n_writes != continuation_writes as usize
        || cont_n_reads != continuation_segments[3] as usize
    {
        return Err(ZKVMError::InvalidWitness(
            "continuation EC segment count mismatch".into(),
        ));
    }
    let finalization_expectations = ceno_gpu::common::witgen::types::FinalizationExpectations {
        segment_counts: expected_segments,
        legacy_bucket_limit: u32::try_from(multilinear_extensions::util::max_usable_threads())
            .map_err(|_| ZKVMError::InvalidWitness("legacy bucket limit exceeds u32".into()))?,
    };

    // 6. Exactly one deterministic finalization feeds both consumers.
    let (partitioned_buf, num_writes, total_records, finalized_segments) =
        info_span!("gpu_merge_finalize").in_scope(|| {
            hal.witgen
                .merge_and_finalize_records(
                    &shared.ec_buf,
                    ec_count,
                    &cont_ec_buf,
                    cont_total,
                    &finalization_expectations,
                    None,
                )
                .map_err(|e| ZKVMError::InvalidWitness(format!("GPU merge+finalize: {e}").into()))
        })?;

    tracing::info!(
        finalizer_status = 0,
        segment0 = finalized_segments[0],
        segment1 = finalized_segments[1],
        segment2 = finalized_segments[2],
        segment3 = finalized_segments[3],
        expected_total = finalized_segments
            .iter()
            .map(|&count| u64::from(count))
            .sum::<u64>(),
        observed_total = total_records,
        "GPU finalizer contract validated"
    );

    tracing::info!(
        "[GPU full pipeline] merged+finalized: {} total ({} writes, {} reads)",
        total_records,
        num_writes,
        total_records - num_writes,
    );

    let record_u32s = std::mem::size_of::<ceno_gpu::common::witgen::types::GpuShardRamRecord>() / 4;
    // GpuShardRamRecord (#[repr(C)]) layout — derived from shard_ram_record_to_gpu
    debug_assert_eq!(record_u32s, 28, "GpuShardRamRecord layout changed");
    const IS_TO_WRITE_SET_U32_OFFSET: usize = 12;
    const POINT_Y6_U32_OFFSET: usize = 27;

    let host_data: Vec<u32> = if total_records == 0 {
        vec![]
    } else {
        partitioned_buf
            .to_vec_n(total_records * record_u32s)
            .map_err(|e| {
                ZKVMError::InvalidWitness(
                    format!("[GPU full pipeline] partitioned_buf D2H: {e}").into(),
                )
            })?
    };
    debug_assert_eq!(host_data.len(), total_records * record_u32s);

    // 6.5. Derive ShardRam's per-row y6_lo byte / LTU lookup multiplicity
    // from the partitioned device buffer. Mirrors the per-row CPU push in
    // `ShardRamCircuit::assign_instance`; the constraint these queries serve
    // lives in `ShardRamConfig::configure` (y6_lo bytes + lookup_ltu_byte).
    let lk_mlt = info_span!("gpu_shard_ram_derive_lk_mlt", n = total_records).in_scope(
        || -> Result<gkr_iop::utils::lk_multiplicity::Multiplicity<u64>, ZKVMError> {
            if total_records == 0 {
                return Ok(gkr_iop::utils::lk_multiplicity::Multiplicity::default());
            }
            let prime = <E::BaseField as SmallField>::MODULUS_U64;
            let lk_multiplicity = LkMultiplicity::default();
            host_data.par_chunks_exact(record_u32s).for_each(|rec| {
                let mut local = lk_multiplicity.clone();
                let is_to_write_set = rec[IS_TO_WRITE_SET_U32_OFFSET] != 0;
                let y6 = rec[POINT_Y6_U32_OFFSET] as u64;
                let y6_lo = if is_to_write_set {
                    prime - 1 - y6
                } else {
                    y6 - 1
                };
                for i in 0..3 {
                    local.assert_const_range((y6_lo >> (8 * i)) & 0xff, 8);
                }
                local.lookup_ltu_byte((y6_lo >> 24) & 0xff, Y6_LO_TOP_BYTE_LT_BOUND);
            });
            Ok(lk_multiplicity.into_finalize_result())
        },
    )?;

    // 7. GPU assign_instances from device buffer. The proof format stores one
    // chip proof per circuit, so shard RAM must stay in one witness entry.
    let (circuit_inputs, ec_tree_circuit_inputs) =
        info_span!("shard_ram_assign_from_device", n = total_records).in_scope(|| {
            if total_records == 0 {
                return Ok::<(Vec<ChipInput<E>>, Vec<ChipInput<E>>), ZKVMError>((vec![], vec![]));
            }

            let witness = ShardRamCircuit::<E>::try_gpu_assign_instances_from_device(
                config,
                num_witin,
                num_structural_witin,
                &partitioned_buf,
                total_records,
                num_writes,
            )?;

            let witness = witness.ok_or_else(|| {
                ZKVMError::InvalidWitness("GPU shard_ram from_device returned None".into())
            })?;

            let num_reads = total_records - num_writes;
            let circuit_inputs = vec![ChipInput::new(
                ShardRamCircuit::<E>::name(),
                witness,
                [num_writes, num_reads],
            )];

            let ec_tree_witness = try_gpu_assign_shard_ram_ec_tree_from_device(
                ec_tree_config,
                ec_tree_num_witin,
                ec_tree_num_structural_witin,
                &partitioned_buf,
                total_records,
                num_writes,
            )?
            .ok_or_else(|| {
                ZKVMError::InvalidWitness("GPU shard_ram EC tree from_device returned None".into())
            })?;
            let ec_tree_circuit_inputs = vec![ChipInput::new(
                ShardRamEcTreeCircuit::<E>::name(),
                ec_tree_witness,
                [num_reads, num_writes],
            )];

            Ok::<_, ZKVMError>((circuit_inputs, ec_tree_circuit_inputs))
        })?;

    tracing::info!(
        "[GPU full pipeline] assign_shared_circuit complete: {} total records",
        total_records,
    );

    Ok(Some((circuit_inputs, ec_tree_circuit_inputs, lk_mlt)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        structs::ProgramParams,
        tables::{ShardRamCircuit, ShardRamEcTreeCircuit, TableCircuit, y6_lo_value},
    };
    use ff_ext::BabyBearExt4;
    use p3::{babybear::BabyBear, field::PrimeCharacteristicRing};

    type E = BabyBearExt4;

    #[test]
    fn legacy_ordinals_preserve_segment_bucket_and_address_order() {
        let w0 = legacy_btree_ordinal(true, 0, ceno_emul::WordAddr(9)).unwrap();
        let w1 = legacy_btree_ordinal(true, 1, ceno_emul::WordAddr(2)).unwrap();
        let first = legacy_continuation_ordinal(LEGACY_FIRST_CONTINUATION_SEGMENT, 0).unwrap();
        let current = legacy_continuation_ordinal(LEGACY_CURRENT_CONTINUATION_SEGMENT, 0).unwrap();
        let r0 = legacy_btree_ordinal(false, 0, ceno_emul::WordAddr(1)).unwrap();
        let r1 = legacy_btree_ordinal(false, 0, ceno_emul::WordAddr(2)).unwrap();

        assert!(w0 < w1);
        assert!(w1 < first);
        assert!(first < current);
        assert!(current < r0);
        assert!(r0 < r1);
        assert_eq!(
            legacy_continuation_ordinal(LEGACY_FIRST_CONTINUATION_SEGMENT, 1).unwrap(),
            first + 1
        );
    }

    #[test]
    fn legacy_ordinals_reject_out_of_range_components() {
        assert!(legacy_btree_ordinal(true, LEGACY_BUCKET_LIMIT, ceno_emul::WordAddr(0)).is_err());
        if usize::BITS > LEGACY_SEGMENT_SHIFT {
            assert!(
                legacy_continuation_ordinal(
                    LEGACY_CURRENT_CONTINUATION_SEGMENT,
                    1usize << LEGACY_SEGMENT_SHIFT
                )
                .is_err()
            );
        }
    }

    #[test]
    fn four_segment_ordinals_and_bounds_are_exact() {
        let limit = LEGACY_BUCKET_LIMIT;
        assert!(limit > 0);
        let segment0 =
            legacy_btree_ordinal(true, limit - 1, ceno_emul::WordAddr(u32::MAX)).unwrap();
        let segment1 = legacy_continuation_ordinal(LEGACY_FIRST_CONTINUATION_SEGMENT, 0).unwrap();
        let segment2 = legacy_continuation_ordinal(LEGACY_CURRENT_CONTINUATION_SEGMENT, 0).unwrap();
        let segment3 =
            legacy_btree_ordinal(false, limit - 1, ceno_emul::WordAddr(u32::MAX)).unwrap();
        assert_eq!(segment0 >> LEGACY_SEGMENT_SHIFT, 0);
        assert_eq!(segment1 >> LEGACY_SEGMENT_SHIFT, 1);
        assert_eq!(segment2 >> LEGACY_SEGMENT_SHIFT, 2);
        assert_eq!(segment3 >> LEGACY_SEGMENT_SHIFT, 3);
        assert!(segment0 < segment1 && segment1 < segment2 && segment2 < segment3);
        assert!(legacy_btree_ordinal(true, limit, ceno_emul::WordAddr(0)).is_err());
        assert!(legacy_btree_ordinal(false, limit, ceno_emul::WordAddr(0)).is_err());

        let expected = ceno_gpu::common::witgen::types::FinalizationExpectations {
            segment_counts: [2, 3, 5, 7],
            legacy_bucket_limit: u32::try_from(limit).unwrap(),
        };
        assert_eq!(std::mem::size_of_val(&expected), 20);
        assert_eq!(expected.segment_counts.iter().sum::<u32>(), 17);
    }

    #[test]
    fn emission_and_address_capacity_relations_fail_closed_without_repair() {
        fn validate(
            observed_ec: u32,
            expected_writes: u32,
            expected_reads: u32,
            ec_capacity: u32,
            observed_addresses: u32,
            reserved_addresses: u32,
            physical_addresses: u32,
        ) -> bool {
            let Some(expected_ec) = expected_writes.checked_add(expected_reads) else {
                return false;
            };
            observed_ec == expected_ec
                && observed_ec <= ec_capacity
                && expected_ec <= ec_capacity
                && observed_addresses <= reserved_addresses
                && reserved_addresses <= physical_addresses
        }

        assert!(validate(5, 2, 3, 5, 7, 9, 9));
        assert!(validate(5, 2, 3, 8, 7, 12, 16));
        assert!(!validate(4, 2, 3, 8, 7, 12, 16));
        assert!(!validate(6, 2, 3, 8, 7, 12, 16));
        assert!(!validate(5, 2, 3, 4, 7, 12, 16));
        assert!(!validate(5, 2, 3, 8, 13, 12, 16));
        assert!(!validate(5, 2, 3, 8, 7, 17, 16));
        assert!(!validate(0, u32::MAX, 1, u32::MAX, 0, 0, 0));
    }

    #[test]
    fn shard_ram_column_maps_cover_main_and_ec_tree_routes() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            ShardRamCircuit::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();

        let col_map = extract_shard_ram_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        // Main-kernel column IDs through y6_lo bytes are concrete and in range.
        for (i, &col) in flat[..27].iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (flat index {}) out of range: {} >= {}",
                col,
                i,
                col,
                col_map.num_cols
            );
        }
        assert_eq!(col_map.y6_lo_bytes, config.y6_lo_bytes.map(|w| w.id as u32));
        assert_eq!(&flat[23..27], &col_map.y6_lo_bytes);
        assert_eq!(col_map.y6_lo_bytes, [367, 368, 369, 370]);

        // Verify Poseidon2 column counts are reasonable
        assert_eq!(col_map.num_p3_cols, 299, "Expected 299 p3 cols");
        assert_eq!(
            col_map.num_poseidon2_cols, 344,
            "Expected 344 total Poseidon2 cols"
        );

        let mut ec_cs = ConstraintSystem::<E>::new(|| "ec tree test");
        let mut ec_cb = CircuitBuilder::new(&mut ec_cs);
        let (ec_config, _) = ShardRamEcTreeCircuit::<E>::build_gkr_iop_circuit(
            &mut ec_cb,
            &ProgramParams::default(),
        )
        .unwrap();
        let ec_map = extract_shard_ram_ec_tree_column_map(&ec_config, ec_cb.cs.num_witin as usize);
        assert_eq!(ec_map.y6_lo_bytes, [0; 4]);
        assert_eq!(&ec_map.to_flat()[23..27], &[0; 4]);
    }

    #[test]
    fn shard_ram_y6_lo_formula_and_little_endian_bytes_match_cpu() {
        const PRIME: u64 = 0x7800_0001;
        let y6 = 0x1234_567u64;
        let read = y6_lo_value::<E>(BabyBear::from_u64(y6), false);
        let write = y6_lo_value::<E>(BabyBear::from_u64(y6), true);
        assert_eq!(read, y6 - 1);
        assert_eq!(write, PRIME - 1 - y6);
        assert_eq!(
            std::array::from_fn::<_, 4, _>(|i| ((read >> (8 * i)) & 0xff) as u8),
            (read as u32).to_le_bytes()
        );
        assert_eq!(
            std::array::from_fn::<_, 4, _>(|i| ((write >> (8 * i)) & 0xff) as u8),
            (write as u32).to_le_bytes()
        );
    }
}
