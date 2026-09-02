use ceno_emul::{StepRecord, tensor::TensorProductionFullLayerWitness};
use ceno_gpu::{
    Buffer,
    common::witgen::production_attention_matrix::{
        ProductionAttentionDerived, ProductionProjectedQkv,
    },
};
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
    let head_count = usize::try_from(call.head_count)
        .map_err(|_| ZKVMError::InvalidWitness("production QK head count overflow".into()))?;
    let group_limit = 32 / head_count;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>()
        || !matches!(head_count, 1 | 2 | 4)
        || head_count != ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
        || GROUP >= group_limit
        || call.head_start as usize != GROUP * head_count
    {
        return Err(ZKVMError::InvalidWitness(
            "production QK requires the BabyBear GPU backend and a valid group".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer >= 32 {
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
    let rows = head_count << 22;
    let log_rows = 22 + head_count.ilog2() as usize;
    super::log_production_allocation(
        "qk_before",
        rows * num_witin * std::mem::size_of::<E::BaseField>(),
        rows * num_structural_witin * std::mem::size_of::<E::BaseField>(),
    );
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_qk(
            columns,
            GROUP as u32,
            call.head_count,
            call.import_cycle,
            call.projected_qkv_tensor_id,
            call.projected_qkv_version,
            call.layer,
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
    if result.witness.len() != rows * num_witin
        || result.structural.len() != rows * num_structural_witin
    {
        return Err(ZKVMError::InvalidWitness(
            "production QK GPU allocation does not match RMM metadata".into(),
        ));
    }
    super::log_production_allocation(
        "qk_after",
        rows * num_witin * std::mem::size_of::<E::BaseField>(),
        rows * num_structural_witin * std::mem::size_of::<E::BaseField>(),
    );
    let witness = RowMajorMatrix::<E::BaseField>::new_by_device_backing(
        rows,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    let structural = RowMajorMatrix::<E::BaseField>::new_by_device_backing(
        rows,
        num_structural_witin,
        InstancePaddingStrategy::Default,
        result.structural,
        DeviceMatrixLayout::ColMajor,
    );
    validate_non_rotating_domain(
        "QK",
        head_count,
        rows,
        log_rows,
        num_witin,
        num_structural_witin,
        &witness,
        &structural,
    )?;
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
    attention_derived: &ProductionAttentionDerived,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    let head_count = usize::try_from(call.head_count)
        .map_err(|_| ZKVMError::InvalidWitness("production PV head count overflow".into()))?;
    let group_limit = 32 / head_count;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>()
        || !matches!(head_count, 1 | 2 | 4)
        || head_count != ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
        || GROUP >= group_limit
        || call.head_start as usize != GROUP * head_count
    {
        return Err(ZKVMError::InvalidWitness(
            "production PV requires the BabyBear GPU backend and a valid group".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer >= 32 {
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
    let rows = head_count << 22;
    let log_rows = 22 + head_count.ilog2() as usize;
    super::log_production_allocation(
        "pv_before",
        rows * num_witin * std::mem::size_of::<E::BaseField>(),
        rows * num_structural_witin * std::mem::size_of::<E::BaseField>(),
    );
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_pv(
            columns,
            GROUP as u32,
            call.head_count,
            call.import_cycle,
            call.projected_qkv_tensor_id,
            call.projected_qkv_version,
            call.attention_output_tensor_id,
            call.attention_output_version,
            &projected_qkv.value,
            &attention_derived.probability,
            dynamic_lk_ptr,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production PV GPU assignment failed: {error}").into(),
            )
        })?;
    if result.witness.len() != rows * num_witin
        || result.structural.len() != rows * num_structural_witin
    {
        return Err(ZKVMError::InvalidWitness(
            "production PV GPU allocation does not match RMM metadata".into(),
        ));
    }
    super::log_production_allocation(
        "pv_after",
        rows * num_witin * std::mem::size_of::<E::BaseField>(),
        rows * num_structural_witin * std::mem::size_of::<E::BaseField>(),
    );
    let witness = RowMajorMatrix::<E::BaseField>::new_by_device_backing(
        rows,
        num_witin,
        InstancePaddingStrategy::Default,
        result.witness,
        DeviceMatrixLayout::ColMajor,
    );
    let structural = RowMajorMatrix::<E::BaseField>::new_by_device_backing(
        rows,
        num_structural_witin,
        InstancePaddingStrategy::Default,
        result.structural,
        DeviceMatrixLayout::ColMajor,
    );
    validate_non_rotating_domain(
        "PV",
        head_count,
        rows,
        log_rows,
        num_witin,
        num_structural_witin,
        &witness,
        &structural,
    )?;
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production PV assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}

#[allow(clippy::too_many_arguments)]
fn validate_non_rotating_domain<F: p3::field::PrimeCharacteristicRing + Copy + Send + Sync>(
    family: &str,
    head_count: usize,
    rows: usize,
    log_rows: usize,
    num_witin: usize,
    num_structural_witin: usize,
    witness: &RowMajorMatrix<F>,
    structural: &RowMajorMatrix<F>,
) -> Result<(), ZKVMError> {
    for supported_heads in [1usize, 2, 4] {
        let supported_log_rows = 22 + supported_heads.ilog2() as usize;
        assert_eq!(
            supported_heads << 22,
            1usize << supported_log_rows,
            "production matrix domain formula changed for heads={supported_heads}"
        );
    }
    let valid = matches!(head_count, 1 | 2 | 4)
        && rows == head_count << 22
        && rows == 1usize << log_rows
        && witness.num_instances() == rows
        && structural.num_instances() == rows
        && witness.num_vars() == log_rows
        && structural.num_vars() == log_rows
        && witness.width() == num_witin
        && structural.width() == num_structural_witin
        && witness.occupied_physical_rows() == rows
        && structural.occupied_physical_rows() == rows
        && witness.has_device_backing()
        && structural.has_device_backing()
        && witness.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor)
        && structural.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor);
    if !valid {
        return Err(ZKVMError::InvalidWitness(
            format!("production {family} non-rotating RMM domain metadata changed").into(),
        ));
    }
    tracing::info!(
        target: "ceno_pipeline",
        family,
        head_count,
        rows,
        log_rows,
        num_witin,
        num_structural_witin,
        "production TensorVM non-rotating domain validated"
    );
    Ok(())
}
