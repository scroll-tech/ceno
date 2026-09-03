use ceno_emul::{StepRecord, tensor::TensorProductionFullLayerWitness};
use ceno_gpu::{Buffer, common::BufferImpl};
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
    calls: &[&TensorProductionFullLayerWitness],
    values: &BufferImpl<'static, i32>,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    let rows = calls
        .len()
        .checked_mul(ceno_emul::tensor::production_attention::SEQUENCE)
        .and_then(|words| words.checked_mul(ceno_emul::tensor::production_attention::HEAD_DIM))
        .ok_or_else(|| {
            ZKVMError::InvalidWitness("production tensor producer rows overflow".into())
        })?;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>()
        || calls.is_empty()
        || calls.iter().any(|call| {
            call.head_count != 1
                || call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER
                || call.layer != calls[0].layer
        })
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
        .witgen_production_attention_tensor_producer_slots(
            columns,
            values,
            &calls
                .iter()
                .map(|call| {
                    (
                        call.import_cycle,
                        call.projected_qkv_tensor_id,
                        call.projected_qkv_version,
                        0,
                    )
                })
                .collect::<Vec<_>>(),
            calls[0].layer,
            dynamic_lk_ptr,
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
    let rows_per_slot = ceno_emul::tensor::production_attention::SEQUENCE
        * ceno_emul::tensor::production_attention::HEAD_DIM;
    for row in 0..padded_rows {
        let offset = row * num_structural_witin;
        structural.values[offset] = E::BaseField::from_usize(
            crate::instructions::riscv::ecall::production_boundary_physical_local_index(
                row,
                rows_per_slot,
            ),
        );
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
    descriptors: &[TensorProductionBoundaryReplayDescriptor],
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Err(ZKVMError::InvalidWitness(
            "production attention boundary requires the BabyBear GPU backend".into(),
        ));
    }
    config.validate_device_layout(num_structural_witin)?;
    let descriptor = descriptors.first().ok_or_else(|| {
        ZKVMError::InvalidWitness("production boundary descriptor group is empty".into())
    })?;
    crate::instructions::riscv::ecall::validate_production_boundary_group(descriptors)?;
    let is_hidden_broadcast =
        (descriptor.stage, descriptor.direction, descriptor.part) == (0, 0, 0);
    let metadata_slots = if is_hidden_broadcast {
        descriptors.len()
    } else {
        1
    };
    if num_witin != 4 + 5 * metadata_slots {
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
    let rows = if is_hidden_broadcast {
        descriptor.rows
    } else {
        descriptor
            .rows
            .checked_mul(descriptors.len())
            .ok_or_else(|| {
                ZKVMError::InvalidWitness("production boundary grouped rows overflow".into())
            })?
    };
    let allocation_elems = rows.checked_mul(num_witin).ok_or_else(|| {
        ZKVMError::InvalidWitness("production boundary allocation overflow".into())
    })?;
    let allocation_bytes = allocation_elems
        .checked_mul(std::mem::size_of::<E::BaseField>())
        .ok_or_else(|| {
            ZKVMError::InvalidWitness("production boundary byte size overflow".into())
        })?;
    super::log_production_allocation("boundary_before", allocation_bytes, 0);
    let use_virtual_structural = descriptor.stage != 1 && descriptor.log_rows == 23;
    let result = if is_hidden_broadcast {
        hal.witgen
            .witgen_production_attention_boundary_output_broadcast(
                &config.device_output_column_maps(num_witin, num_structural_witin)?,
                &descriptor.values[descriptor.tensor_index_start
                    ..descriptor.tensor_index_start + descriptor.rows],
                &descriptors
                    .iter()
                    .map(|item| {
                        (
                            item.import_cycle,
                            item.tensor_id,
                            item.tensor_version,
                            item.base_byte_address,
                        )
                    })
                    .collect::<Vec<_>>(),
                descriptor.layer,
                dynamic_lk_ptr,
            )
    } else {
        hal.witgen
            .witgen_production_attention_boundary_output_slots(
                config.device_output_column_map(num_witin, num_structural_witin)?,
                &descriptors
                    .iter()
                    .map(|item| {
                        (
                            &item.values
                                [item.tensor_index_start..item.tensor_index_start + item.rows],
                            item.import_cycle,
                            item.tensor_id,
                            item.tensor_version,
                            item.base_byte_address,
                        )
                    })
                    .collect::<Vec<_>>(),
                descriptor.layer,
                dynamic_lk_ptr,
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
        rows.trailing_zeros() as usize,
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
            rows.trailing_zeros() as usize,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let padded_rows = 1usize << (rows.trailing_zeros() as usize + 1);
        assert_eq!(structural.height(), padded_rows);
        assert_eq!(structural.width(), 5);
        assert_eq!(structural.values.len(), padded_rows * 5);
        for row in 0..padded_rows {
            let offset = row * 5;
            structural.values[offset] = E::BaseField::from_usize(
                crate::instructions::riscv::ecall::production_boundary_physical_local_index(
                    row,
                    descriptor.rows,
                ),
            );
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
