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
        riscv::ecall::{
            TensorProductionShiftCoreInstruction, TensorProductionSoftmaxCoreInstruction,
        },
    },
    tables::RMMCollections,
};

pub(crate) fn assign_production_shift_device<E: ExtensionField>(
    config: &<TensorProductionShiftCoreInstruction<E> as crate::instructions::Instruction<E>>::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    call: &TensorProductionFullLayerWitness,
    projected_qkv: &ProductionProjectedQkv,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;
    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Err(ZKVMError::InvalidWitness(
            "production shift requires the BabyBear GPU backend".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer != 0 {
        return Err(ZKVMError::InvalidWitness(
            "production shift call identity changed".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(format!("production shift CUDA unavailable: {error}").into())
    })?;
    ensure_shard_metadata_cached(&hal, shard_ctx, steps)?;
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_shift(
            columns,
            call.import_cycle,
            call.attention_output_tensor_id,
            call.attention_output_version,
            &projected_qkv.shift,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production shift GPU assignment failed: {error}").into(),
            )
        })?;
    let witness = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        16,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    let structural = RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
        1,
        16,
        num_structural_witin,
        InstancePaddingStrategy::Default,
        result.structural,
        DeviceMatrixLayout::ColMajor,
    );
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production shift assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}

pub(crate) fn assign_production_softmax_device<E: ExtensionField, const GROUP: usize>(
    config: &<TensorProductionSoftmaxCoreInstruction<E, GROUP> as crate::instructions::Instruction<E>>::InstructionConfig,
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
            "production softmax requires the BabyBear GPU backend and a valid group".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer != 0 {
        return Err(ZKVMError::InvalidWitness(
            "production softmax call identity changed".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(format!("production softmax CUDA unavailable: {error}").into())
    })?;
    ensure_shard_metadata_cached(&hal, shard_ctx, steps)?;
    let pointers = with_cached_shard_meta(|buffers| {
        buffers.shared_lk.map(|counters| {
            (
                counters.dynamic,
                counters.llama_softmax_exp3,
                counters.llama_softmax_exp4,
                counters.llama_production_softmax_middle,
                counters.llama_production_softmax_high,
            )
        })
    })
    .ok_or_else(|| {
        ZKVMError::InvalidWitness(
            "production softmax requires shard-owned GPU lookup counters".into(),
        )
    })?;
    if pointers.0 == 0 || pointers.3 == 0 || pointers.4 == 0 {
        return Err(ZKVMError::InvalidWitness(
            "production softmax lookup counter pointer is null".into(),
        ));
    }
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_softmax(
            columns,
            GROUP as u32,
            call.import_cycle,
            call.attention_output_tensor_id,
            call.attention_output_version,
            &projected_qkv.query,
            &projected_qkv.key,
            &projected_qkv.shift,
            pointers.0,
            pointers.3,
            pointers.4,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production softmax GPU assignment failed: {error}").into(),
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
            format!("production softmax assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}
