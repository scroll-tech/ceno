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
        gpu::cache::{
            ensure_shard_metadata_cached, production_softmax_lookup_counter_sums,
            with_cached_shard_meta,
        },
        riscv::ecall::{
            TensorProductionShiftCoreInstruction, TensorProductionSoftmaxCoreInstruction,
        },
    },
    tables::RMMCollections,
};

pub(crate) fn assign_production_shift_device<E: ExtensionField>(
    config: &<TensorProductionShiftCoreInstruction<E> as crate::instructions::Instruction<
        E,
    >>::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    call: &TensorProductionFullLayerWitness,
    attention_derived: &ProductionAttentionDerived,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;
    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    let head_count = usize::try_from(call.head_count)
        .map_err(|_| ZKVMError::InvalidWitness("production shift head count overflow".into()))?;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>()
        || !matches!(head_count, 1 | 2 | 4)
        || head_count != ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
        || call.head_start as usize >= 32
        || call.head_start as usize % head_count != 0
    {
        return Err(ZKVMError::InvalidWitness(
            "production shift requires the BabyBear GPU backend".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer >= 32 {
        return Err(ZKVMError::InvalidWitness(
            "production shift call identity changed".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(format!("production shift CUDA unavailable: {error}").into())
    })?;
    ensure_shard_metadata_cached(&hal, shard_ctx, steps)?;
    let rows = head_count << 22;
    let log_rows = 22 + head_count.ilog2() as usize;
    super::log_production_allocation(
        "shift_before",
        rows * num_witin * std::mem::size_of::<E::BaseField>(),
        rows * num_structural_witin * std::mem::size_of::<E::BaseField>(),
    );
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let result = hal
        .witgen
        .witgen_production_attention_shift(
            columns,
            call.layer,
            call.head_start,
            call.head_count,
            call.import_cycle,
            call.attention_output_tensor_id,
            call.attention_output_version,
            &attention_derived.shift,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production shift GPU assignment failed: {error}").into(),
            )
        })?;
    if result.witness.len() != rows * num_witin
        || result.structural.len() != rows * num_structural_witin
    {
        return Err(ZKVMError::InvalidWitness(
            "production shift GPU allocation does not match RMM metadata".into(),
        ));
    }
    super::log_production_allocation(
        "shift_after",
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
        "Shift",
        head_count,
        22,
        rows,
        log_rows,
        num_witin,
        num_structural_witin,
        &witness,
        &structural,
    )?;
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production shift assignment synchronize failed: {error}").into(),
        )
    })?;
    Ok(([witness, structural], Multiplicity::default()))
}

pub(crate) fn assign_production_softmax_device<E: ExtensionField>(
    config: &<TensorProductionSoftmaxCoreInstruction<E> as crate::instructions::Instruction<E>>::InstructionConfig,
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
        .map_err(|_| ZKVMError::InvalidWitness("production softmax head count overflow".into()))?;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>()
        || !matches!(head_count, 1 | 2 | 4)
        || head_count != ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
        || call.head_start as usize >= 32
        || call.head_start as usize % head_count != 0
    {
        return Err(ZKVMError::InvalidWitness(
            "production softmax requires the BabyBear GPU backend and a valid group".into(),
        ));
    }
    if call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER || call.layer >= 32 {
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
    let rows = head_count << 22;
    let log_rows = 22 + head_count.ilog2() as usize;
    super::log_production_allocation(
        "softmax_before",
        rows * num_witin * std::mem::size_of::<E::BaseField>(),
        rows * num_structural_witin * std::mem::size_of::<E::BaseField>(),
    );
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let audit_before = std::env::var_os("CENO_TENSOR_SOFTMAX_LK_AUDIT")
        .map(|_| production_softmax_lookup_counter_sums())
        .transpose()?;
    let result = hal
        .witgen
        .witgen_production_attention_softmax(
            columns,
            call.head_start,
            call.head_count,
            call.import_cycle,
            call.layer,
            call.attention_output_tensor_id,
            call.attention_output_version,
            &projected_qkv.query,
            &projected_qkv.key,
            &attention_derived.shift,
            pointers.0,
            pointers.3,
            pointers.4,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production softmax GPU assignment failed: {error}").into(),
            )
        })?;
    if result.witness.len() != rows * num_witin
        || result.structural.len() != rows * num_structural_witin
    {
        return Err(ZKVMError::InvalidWitness(
            "production softmax GPU allocation does not match RMM metadata".into(),
        ));
    }
    super::log_production_allocation(
        "softmax_after",
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
        "Softmax",
        head_count,
        22,
        rows,
        log_rows,
        num_witin,
        num_structural_witin,
        &witness,
        &structural,
    )?;
    hal.inner.synchronize().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production softmax assignment synchronize failed: {error}").into(),
        )
    })?;
    if let Some(before) = audit_before {
        let after = production_softmax_lookup_counter_sums()?;
        let expected_rows = rows as u64;
        let delta = (
            after.0.checked_sub(before.0),
            after.1.checked_sub(before.1),
            after.2.checked_sub(before.2),
        );
        tracing::info!(
            dynamic_20_before = before.0,
            dynamic_20_after = after.0,
            middle_before = before.1,
            middle_after = after.1,
            high_before = before.2,
            high_after = after.2,
            "production softmax lookup counter audit"
        );
        if delta
            != (
                Some(2 * expected_rows),
                Some(expected_rows),
                Some(expected_rows),
            )
        {
            return Err(ZKVMError::InvalidWitness(
                format!(
                    "production softmax lookup counter retention changed: rows={rows}, before={before:?}, after={after:?}"
                )
                .into(),
            ));
        }
    }
    Ok(([witness, structural], Multiplicity::default()))
}

#[allow(clippy::too_many_arguments)]
fn validate_non_rotating_domain<F: p3::field::PrimeCharacteristicRing + Copy + Send + Sync>(
    family: &str,
    head_count: usize,
    base_log_rows: usize,
    rows: usize,
    log_rows: usize,
    num_witin: usize,
    num_structural_witin: usize,
    witness: &RowMajorMatrix<F>,
    structural: &RowMajorMatrix<F>,
) -> Result<(), ZKVMError> {
    for supported_heads in [1usize, 2, 4] {
        let supported_log_rows = base_log_rows + supported_heads.ilog2() as usize;
        assert_eq!(
            supported_heads << base_log_rows,
            1usize << supported_log_rows,
            "production {family} domain formula changed for heads={supported_heads}"
        );
    }
    let valid = matches!(head_count, 1 | 2 | 4)
        && rows == head_count << base_log_rows
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
