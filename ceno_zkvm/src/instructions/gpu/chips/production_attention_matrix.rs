use ceno_emul::{StepRecord, tensor::TensorProductionFullLayerWitness};
use ceno_gpu::common::witgen::production_attention_matrix::ProductionProjectedQkv;
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use witness::{DeviceMatrixLayout, InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        gpu::cache::{ensure_shard_metadata_cached, with_cached_shard_meta},
        riscv::ecall::{TensorProductionPvCoreInstruction, TensorProductionQkCoreInstruction},
    },
    tables::RMMCollections,
};

pub(crate) fn assign_production_qk_device<E: ExtensionField, const GROUP: usize>(
    config: &<TensorProductionQkCoreInstruction<E, GROUP> as crate::instructions::Instruction<E>>::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    call: &TensorProductionFullLayerWitness,
    projected_qkv: &ProductionProjectedQkv,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() || GROUP >= 8 {
        return Err(ZKVMError::InvalidWitness(
            "production QK requires the BabyBear GPU backend and a valid group".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer != 0 {
        return Err(ZKVMError::InvalidWitness(
            "production QK call identity changed".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(format!("production QK CUDA unavailable: {error}").into())
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
            "production QK requires shard-owned GPU lookup counters".into(),
        ));
    }
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_qk(
            columns,
            GROUP as u32,
            call.import_cycle,
            call.projected_qkv_tensor_id,
            call.projected_qkv_version,
            call.attention_output_tensor_id,
            call.attention_output_version,
            &projected_qkv.query,
            &projected_qkv.key,
            dynamic_lk_ptr,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production QK GPU assignment failed: {error}").into(),
            )
        })?;
    let witness = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        24,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    let structural = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        24,
        num_structural_witin,
        InstancePaddingStrategy::Default,
        result.structural,
        DeviceMatrixLayout::ColMajor,
    );
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production QK assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}

pub(crate) fn assign_production_pv_device<E: ExtensionField, const GROUP: usize>(
    config: &<TensorProductionPvCoreInstruction<E, GROUP> as crate::instructions::Instruction<E>>::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    call: &TensorProductionFullLayerWitness,
    projected_qkv: &ProductionProjectedQkv,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() || GROUP >= 8 {
        return Err(ZKVMError::InvalidWitness(
            "production PV requires the BabyBear GPU backend and a valid group".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer != 0 {
        return Err(ZKVMError::InvalidWitness(
            "production PV call identity changed".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(format!("production PV CUDA unavailable: {error}").into())
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
            "production PV requires shard-owned GPU lookup counters".into(),
        ));
    }
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_pv(
            columns,
            GROUP as u32,
            call.import_cycle,
            call.projected_qkv_tensor_id,
            call.projected_qkv_version,
            call.attention_output_tensor_id,
            call.attention_output_version,
            &projected_qkv.value,
            &projected_qkv.probability,
            dynamic_lk_ptr,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production PV GPU assignment failed: {error}").into(),
            )
        })?;
    let witness = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        24,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    let structural = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        24,
        num_structural_witin,
        InstancePaddingStrategy::Default,
        result.structural,
        DeviceMatrixLayout::ColMajor,
    );
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production PV assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}
