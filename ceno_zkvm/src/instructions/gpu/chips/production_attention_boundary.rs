use ceno_emul::{StepRecord, WriteOp, tensor::TensorProductionFullLayerWitness};
use ceno_gpu::{
    Buffer,
    common::{BufferImpl, witgen::ProductionAttentionBoundaryInputOp},
};
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use p3::field::PrimeCharacteristicRing;
use witness::{DeviceMatrixLayout, InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        gpu::cache::{ensure_shard_metadata_cached, with_cached_shard_meta},
        riscv::ecall::{TensorProductionBoundaryConfig, TensorProductionBoundaryReplayDescriptor},
    },
    tables::RMMCollections,
};

pub(crate) fn assign_production_tensor_producer_device<E: ExtensionField>(
    config: &TensorProductionBoundaryConfig<E>,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    call: &TensorProductionFullLayerWitness,
    values: &BufferImpl<'static, i32>,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    let rows = usize::try_from(call.head_count)
        .ok()
        .and_then(|heads| heads.checked_mul(ceno_emul::tensor::production_attention::SEQUENCE))
        .and_then(|words| words.checked_mul(ceno_emul::tensor::production_attention::HEAD_DIM))
        .ok_or_else(|| {
            ZKVMError::InvalidWitness("production tensor producer rows overflow".into())
        })?;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>()
        || call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER
        || call.layer >= 32
        || values.len() != rows
        || num_witin != 9
        || num_structural_witin != 5
    {
        return Err(ZKVMError::InvalidWitness(
            "production tensor producer metadata changed".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production tensor producer CUDA unavailable: {error}").into(),
        )
    })?;
    ensure_shard_metadata_cached(&hal, shard_ctx, steps)?;
    let dynamic_lk_ptr = with_cached_shard_meta(|buffers| {
        buffers
            .shared_lk
            .map(|counters| counters.dynamic)
            .unwrap_or_default()
    });
    if dynamic_lk_ptr == 0 {
        return Err(ZKVMError::InvalidWitness(
            "production tensor producer requires shard-owned GPU lookup counters".into(),
        ));
    }
    let columns = config.device_output_column_map(num_witin, num_structural_witin)?;
    let allocation_bytes = rows
        .checked_mul(num_witin)
        .and_then(|elements| elements.checked_mul(std::mem::size_of::<E::BaseField>()))
        .ok_or_else(|| {
            ZKVMError::InvalidWitness("production tensor producer allocation overflow".into())
        })?;
    super::log_production_allocation("tensor_producer_before", allocation_bytes, 0);
    let result = hal
        .witgen
        .witgen_production_attention_tensor_producer(
            columns,
            values,
            call.import_cycle,
            call.projected_qkv_tensor_id,
            call.projected_qkv_version,
            0,
            call.layer,
            dynamic_lk_ptr,
            false,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production tensor producer assignment failed: {error}").into(),
            )
        })?;
    if result.witness.len() != rows * num_witin {
        return Err(ZKVMError::InvalidWitness(
            "production tensor producer allocation length changed".into(),
        ));
    }
    super::log_production_allocation("tensor_producer_after", allocation_bytes, 0);
    let log_rows = rows.trailing_zeros() as usize;
    let witness = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        log_rows,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    drop(result.structural);
    let mut structural = RowMajorMatrix::<E::BaseField>::new_by_rotation(
        1,
        log_rows,
        num_structural_witin,
        InstancePaddingStrategy::Default,
    );
    let padded_rows = 1usize << (log_rows + 1);
    for row in 0..padded_rows {
        let offset = row * num_structural_witin;
        structural.values[offset] = E::BaseField::from_usize(row & (rows - 1));
        structural.values[offset + 4] = E::BaseField::ONE;
    }
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production tensor producer synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}

pub(crate) fn assign_production_boundary_device<E: ExtensionField>(
    config: &TensorProductionBoundaryConfig<E>,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    descriptor: TensorProductionBoundaryReplayDescriptor,
    journal: &[WriteOp],
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Err(ZKVMError::InvalidWitness(
            "production attention boundary requires the BabyBear GPU backend".into(),
        ));
    }
    config.validate_device_layout(num_structural_witin)?;
    let expected_width = if descriptor.is_memory { 15 } else { 9 };
    if num_witin != expected_width
        || (descriptor.is_memory && journal.len() != descriptor.rows)
        || (!descriptor.is_memory && !journal.is_empty())
    {
        return Err(ZKVMError::InvalidWitness(
            "production boundary width or journal length changed".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production attention boundary CUDA unavailable: {error}").into(),
        )
    })?;
    ensure_shard_metadata_cached(&hal, shard_ctx, steps)?;
    let dynamic_lk_ptr = with_cached_shard_meta(|buffers| {
        buffers
            .shared_lk
            .map(|counters| counters.dynamic)
            .unwrap_or_default()
    });
    if dynamic_lk_ptr == 0 {
        return Err(ZKVMError::InvalidWitness(
            "production boundary requires shard-owned GPU lookup counters".into(),
        ));
    }
    let allocation_elems = descriptor.rows.checked_mul(num_witin).ok_or_else(|| {
        ZKVMError::InvalidWitness("production boundary allocation overflow".into())
    })?;
    let allocation_bytes = allocation_elems
        .checked_mul(std::mem::size_of::<E::BaseField>())
        .ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary byte size overflow".into())
        })?;
    super::log_production_allocation("boundary_before", allocation_bytes, 0);
    let values = &descriptor.values
        [descriptor.tensor_index_start..descriptor.tensor_index_start + descriptor.rows];
    let use_virtual_structural = descriptor.log_rows == 23;
    let result = if descriptor.is_memory {
        let rhs = descriptor.syscall_cycle.checked_add(3).ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary timestamp overflow".into())
        })?;
        if rhs >= 1 << 32 {
            return Err(ZKVMError::InvalidWitness(
                "production boundary timestamp exceeds device field input".into(),
            ));
        }
        let packed = journal
            .iter()
            .zip(values)
            .enumerate()
            .map(|(row, (op, &value))| {
                let previous_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
                let expected_address = descriptor
                    .base_byte_address
                    .checked_add(u32::try_from(row * 4).map_err(|_| {
                        ZKVMError::InvalidWitness(
                            "production boundary row address offset overflow".into(),
                        )
                    })?)
                    .ok_or_else(|| {
                        ZKVMError::InvalidWitness("production boundary row address overflow".into())
                    })?;
                let value = value as u32;
                if op.addr.baddr().0 != expected_address
                    || op.value.after != value
                    || (descriptor.direction == 0 && op.value.before != value)
                    || previous_cycle >= rhs
                    || rhs - previous_cycle > (1 << 29)
                {
                    return Err(ZKVMError::InvalidWitness(
                        "production boundary RAM operation is noncanonical".into(),
                    ));
                }
                Ok(ProductionAttentionBoundaryInputOp {
                    before_value: op.value.before,
                    after_value: op.value.after,
                    previous_cycle_lo: previous_cycle as u32,
                    previous_cycle_hi: (previous_cycle >> 32) as u32,
                })
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;
        let columns = config.device_input_column_map(num_witin, num_structural_witin)?;
        hal.witgen.witgen_production_attention_boundary_input(
            columns,
            &packed,
            descriptor.import_cycle,
            descriptor.syscall_cycle,
            descriptor.tensor_id,
            descriptor.tensor_version,
            descriptor.base_byte_address,
            descriptor.layer,
            dynamic_lk_ptr,
            false,
        )
    } else {
        let columns = config.device_output_column_map(num_witin, num_structural_witin)?;
        hal.witgen.witgen_production_attention_boundary_output(
            columns,
            values,
            descriptor.import_cycle,
            descriptor.tensor_id,
            descriptor.tensor_version,
            descriptor.base_byte_address,
            descriptor.layer,
            dynamic_lk_ptr,
            false,
        )
    }
    .map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production boundary GPU assignment failed: {error}").into(),
        )
    })?;
    if result.witness.len() != allocation_elems {
        return Err(ZKVMError::InvalidWitness(
            "production boundary device allocation length changed".into(),
        ));
    }
    super::log_production_allocation("boundary_after", allocation_bytes, 0);
    let witness = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        descriptor.log_rows,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    // Full-range boundaries use the specialized low-23-bit virtual formula.
    // Smaller rotating boundaries need a low-log_rows index repeated across
    // the padded rotation half, which the specialized formula cannot express.
    // Materialize that small structural matrix on the host instead of applying
    // the projection-only formula to a different domain.
    drop(result.structural);
    let structural = if use_virtual_structural {
        RowMajorMatrix::<E::BaseField>::empty()
    } else {
        let mut structural = RowMajorMatrix::<E::BaseField>::new_by_rotation(
            1,
            descriptor.log_rows,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let padded_rows = 1usize << (descriptor.log_rows + 1);
        assert_eq!(structural.height(), padded_rows);
        assert_eq!(structural.width(), 5);
        assert_eq!(structural.values.len(), padded_rows * 5);
        for row in 0..padded_rows {
            let offset = row * 5;
            structural.values[offset] = E::BaseField::from_usize(row & (descriptor.rows - 1));
            structural.values[offset + 4] = E::BaseField::ONE;
        }
        tracing::info!(
            target: "ceno_pipeline",
            log_rows = descriptor.log_rows,
            logical_rows = descriptor.rows,
            padded_rows,
            structural_bytes = structural.values.len() * std::mem::size_of::<E::BaseField>(),
            "production rotating boundary structural matrix materialized"
        );
        structural
    };
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production boundary assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}
