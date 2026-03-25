use ceno_gpu::common::witgen::types::ShardRamColumnMap;
use ff_ext::ExtensionField;

use crate::tables::ShardRamConfig;

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

use crate::error::ZKVMError;

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
