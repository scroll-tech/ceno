use ceno_emul::{StepRecord, WriteOp};
use ceno_gpu::common::witgen::ProductionAttentionBoundaryRamOp;
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
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
    if journal.len() != descriptor.rows {
        return Err(ZKVMError::InvalidWitness(
            "production boundary journal length changed".into(),
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
        .enumerate()
        .map(|(row, op)| {
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
            if op.addr.baddr().0 != expected_address
                || previous_cycle >= rhs
                || rhs - previous_cycle > (1 << 29)
            {
                return Err(ZKVMError::InvalidWitness(
                    "production boundary RAM address/timestamp is noncanonical".into(),
                ));
            }
            Ok(ProductionAttentionBoundaryRamOp {
                addr: op.addr.baddr().0,
                before: op.value.before,
                after: op.value.after,
                previous_cycle_lo: previous_cycle as u32,
                previous_cycle_hi: (previous_cycle >> 32) as u32,
                reserved: 0,
            })
        })
        .collect::<Result<Vec<_>, ZKVMError>>()?;
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_boundary(
            columns,
            &packed,
            descriptor.import_cycle,
            descriptor.syscall_cycle,
            descriptor.tensor_id,
            descriptor.tensor_version,
            descriptor.base_byte_address,
            dynamic_lk_ptr,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production boundary GPU assignment failed: {error}").into(),
            )
        })?;
    let witness = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        23,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    let structural = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        23,
        num_structural_witin,
        InstancePaddingStrategy::Default,
        result.structural,
        DeviceMatrixLayout::ColMajor,
    );
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production boundary assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}
