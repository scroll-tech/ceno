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
        riscv::ecall::TensorProductionQkShiftSoftmaxCoreInstruction,
    },
    tables::RMMCollections,
};

pub(crate) fn assign_production_qk_shift_softmax_device<E: ExtensionField>(
    config: &<TensorProductionQkShiftSoftmaxCoreInstruction<E> as crate::instructions::Instruction<E>>::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    calls: &[&TensorProductionFullLayerWitness],
    projected_qkv: &ProductionProjectedQkv,
    attention_derived: &ProductionAttentionDerived,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;
    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    let head_count = calls.len();
    let call = calls.first().ok_or_else(|| {
        ZKVMError::InvalidWitness("production fused attention call group is empty".into())
    })?;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>()
        || !head_count.is_power_of_two()
        || head_count > 32
        || head_count != ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT
        || call.head_start >= 32
        || call.head_start as usize % head_count != 0
        || calls.iter().enumerate().any(|(slot, item)| {
            item.head_count != 1
                || item.head_start != call.head_start + slot as u32
                || item.layer != call.layer
        })
        || call.profile != ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER
        || call.layer >= 32
    {
        return Err(ZKVMError::InvalidWitness(
            "production fused attention requires a valid BabyBear GPU head group".into(),
        ));
    }
    let hal = get_cuda_hal().map_err(|error| {
        ZKVMError::InvalidWitness(
            format!("production fused attention CUDA unavailable: {error}").into(),
        )
    })?;
    ensure_shard_metadata_cached(&hal, shard_ctx, steps)?;
    let pointers = with_cached_shard_meta(|buffers| {
        buffers.shared_lk.map(|counters| {
            (
                counters.dynamic,
                counters.llama_production_softmax_middle,
                counters.llama_production_softmax_high,
            )
        })
    })
    .ok_or_else(|| {
        ZKVMError::InvalidWitness(
            "production fused attention requires shard-owned GPU lookup counters".into(),
        )
    })?;
    let rows = head_count << 22;
    let log_rows = 22 + head_count.ilog2() as usize;
    super::log_production_allocation(
        "qk_shift_softmax_before",
        rows * num_witin * std::mem::size_of::<E::BaseField>(),
        rows * num_structural_witin * std::mem::size_of::<E::BaseField>(),
    );
    let columns = config.device_column_map(num_witin, num_structural_witin)?;
    let audit_before = std::env::var_os("CENO_TENSOR_SOFTMAX_LK_AUDIT")
        .map(|_| production_softmax_lookup_counter_sums())
        .transpose()?;
    let result = hal
        .witgen
        .witgen_production_attention_qk_shift_softmax(
            columns,
            &calls
                .iter()
                .map(|call| {
                    (
                        call.head_start,
                        call.import_cycle,
                        call.projected_qkv_tensor_id,
                        call.projected_qkv_version,
                        call.layer,
                        call.attention_output_tensor_id,
                        call.attention_output_version,
                    )
                })
                .collect::<Vec<_>>(),
            &projected_qkv.query,
            &projected_qkv.key,
            &attention_derived.shift,
            pointers.0,
            pointers.1,
            pointers.2,
        )
        .map_err(|error| {
            ZKVMError::InvalidWitness(
                format!("production fused attention GPU assignment failed: {error}").into(),
            )
        })?;
    if result.witness.len() != rows * num_witin
        || result.structural.len() != rows * num_structural_witin
    {
        return Err(ZKVMError::InvalidWitness(
            "production fused attention GPU allocation does not match RMM metadata".into(),
        ));
    }
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
        "QkShiftSoftmax",
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
            format!("production fused attention synchronize failed: {error}").into(),
        )
    })?;
    if let Some(before) = audit_before {
        let after = production_softmax_lookup_counter_sums()?;
        let expected = rows as u64;
        if (
            after.0.checked_sub(before.0),
            after.1.checked_sub(before.1),
            after.2.checked_sub(before.2),
        ) != (Some(2 * expected), Some(expected), Some(expected))
        {
            return Err(ZKVMError::InvalidWitness(
                "production fused attention lookup counter retention changed".into(),
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
