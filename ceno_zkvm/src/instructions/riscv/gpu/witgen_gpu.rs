/// GPU witness generation dispatcher for the proving pipeline.
///
/// This module provides `try_gpu_assign_instances` which:
/// 1. Runs the GPU kernel to fill the witness matrix (fast)
/// 2. Runs a CPU loop to collect side effects (shard_ctx.send, lk_multiplicity)
/// 3. Returns the GPU-generated witness + CPU-collected side effects
use ceno_emul::{StepIndex, StepRecord};
use ceno_gpu::{Buffer, bb31::CudaHalBB31};
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use multilinear_extensions::util::max_usable_threads;
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use tracing::info_span;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    e2e::ShardContext, error::ZKVMError, instructions::Instruction, tables::RMMCollections,
    witness::LkMultiplicity,
};

#[derive(Debug, Clone, Copy)]
pub enum GpuWitgenKind {
    Add,
    Lw,
}

/// Try to run GPU witness generation for the given instruction.
/// Returns `Ok(Some(...))` if GPU was used, `Ok(None)` if GPU is unavailable (caller should fallback to CPU).
///
/// # Safety invariant
///
/// The caller **must** ensure that `I::InstructionConfig` matches `kind`:
/// - `GpuWitgenKind::Add` requires `I` to be `ArithInstruction` (config = `ArithConfig<E>`)
/// - `GpuWitgenKind::Lw`  requires `I` to be `LoadInstruction`  (config = `LoadConfig<E>`)
///
/// Violating this will cause undefined behavior via pointer cast in [`gpu_fill_witness`].
pub(crate) fn try_gpu_assign_instances<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<Option<(RMMCollections<E::BaseField>, Multiplicity<u64>)>, ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    let total_instances = step_indices.len();
    if total_instances == 0 {
        // Empty: just return empty matrices
        let num_structural_witin = num_structural_witin.max(1);
        let raw_witin = RowMajorMatrix::<E::BaseField>::new(0, num_witin, I::padding_strategy());
        let raw_structural =
            RowMajorMatrix::<E::BaseField>::new(0, num_structural_witin, I::padding_strategy());
        let lk = LkMultiplicity::default();
        return Ok(Some((
            [raw_witin, raw_structural],
            lk.into_finalize_result(),
        )));
    }

    // GPU only supports BabyBear field
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField>()
    {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(hal) => hal,
        Err(_) => return Ok(None), // GPU not available, fallback to CPU
    };

    tracing::debug!("[GPU witgen] {:?} with {} instances", kind, total_instances);
    info_span!("gpu_witgen", kind = ?kind, n = total_instances).in_scope(|| {
        gpu_assign_instances_inner::<E, I>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            shard_steps,
            step_indices,
            kind,
            &hal,
        )
        .map(Some)
    })
}

fn gpu_assign_instances_inner<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
    hal: &CudaHalBB31,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    let num_structural_witin = num_structural_witin.max(1);
    let total_instances = step_indices.len();

    // Step 1: GPU fills witness matrix
    let gpu_witness = info_span!("gpu_kernel").in_scope(|| {
        gpu_fill_witness::<E, I>(
            hal,
            config,
            shard_ctx,
            num_witin,
            shard_steps,
            step_indices,
            kind,
        )
    })?;

    // Step 2: CPU collects side effects (shard_ctx.send, lk_multiplicity)
    // We run assign_instance with a scratch buffer per thread and discard the witness data.
    let lk_multiplicity = info_span!("cpu_side_effects").in_scope(|| {
        collect_side_effects::<E, I>(config, shard_ctx, num_witin, shard_steps, step_indices)
    })?;

    // Step 3: Build structural witness (just selector = ONE)
    let mut raw_structural = RowMajorMatrix::<E::BaseField>::new(
        total_instances,
        num_structural_witin,
        I::padding_strategy(),
    );
    for row in raw_structural.iter_mut() {
        *row.last_mut().unwrap() = E::BaseField::ONE;
    }
    raw_structural.padding_by_strategy();

    // Step 4: Convert GPU witness to RowMajorMatrix
    let mut raw_witin = info_span!("d2h_copy").in_scope(|| {
        gpu_witness_to_rmm::<E>(
            gpu_witness,
            total_instances,
            num_witin,
            I::padding_strategy(),
        )
    })?;
    raw_witin.padding_by_strategy();

    Ok((
        [raw_witin, raw_structural],
        lk_multiplicity.into_finalize_result(),
    ))
}

/// GPU kernel dispatch based on instruction kind.
fn gpu_fill_witness<E: ExtensionField, I: Instruction<E>>(
    hal: &CudaHalBB31,
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<
    ceno_gpu::common::witgen_types::GpuWitnessResult<
        ceno_gpu::common::BufferImpl<'static, <ff_ext::BabyBearExt4 as ExtensionField>::BaseField>,
    >,
    ZKVMError,
> {
    // Cast shard_steps to bytes for bulk H2D (no gather — GPU does indirect access).
    let shard_steps_bytes: &[u8] = info_span!("shard_steps_bytes").in_scope(|| unsafe {
        std::slice::from_raw_parts(
            shard_steps.as_ptr() as *const u8,
            shard_steps.len() * std::mem::size_of::<StepRecord>(),
        )
    });
    // Convert step_indices from usize to u32 for GPU.
    let indices_u32: Vec<u32> = info_span!("indices_u32", n = step_indices.len())
        .in_scope(|| step_indices.iter().map(|&i| i as u32).collect());
    let shard_offset = shard_ctx.current_shard_offset_cycle();

    match kind {
        GpuWitgenKind::Add => {
            // Safety: we know config is ArithConfig<E> when kind == Add
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::add::extract_add_column_map(arith_config, num_witin));
            info_span!("hal_witgen_add").in_scope(|| {
                hal.witgen_add(&col_map, shard_steps_bytes, &indices_u32, shard_offset, None)
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("GPU witgen_add failed: {e}").into())
                    })
            })
        }
        GpuWitgenKind::Lw => {
            // LoadConfig location depends on the u16limb_circuit feature
            #[cfg(feature = "u16limb_circuit")]
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load_v2::LoadConfig<E>)
            };
            #[cfg(not(feature = "u16limb_circuit"))]
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load::LoadConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::lw::extract_lw_column_map(load_config, num_witin));
            info_span!("hal_witgen_lw").in_scope(|| {
                hal.witgen_lw(&col_map, shard_steps_bytes, &indices_u32, shard_offset, None)
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("GPU witgen_lw failed: {e}").into())
                    })
            })
        }
    }
}

/// CPU-side loop to collect side effects only (shard_ctx.send, lk_multiplicity).
/// Runs assign_instance with a scratch buffer per thread.
fn collect_side_effects<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> Result<LkMultiplicity, ZKVMError> {
    let nthreads = max_usable_threads();
    let total = step_indices.len();
    let batch_size = if total > 256 {
        total.div_ceil(nthreads)
    } else {
        total
    }
    .max(1);

    let lk_multiplicity = LkMultiplicity::default();
    let shard_ctx_vec = shard_ctx.get_forked();

    step_indices
        .par_chunks(batch_size)
        .zip(shard_ctx_vec)
        .flat_map(|(indices, mut shard_ctx)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            // Reusable scratch buffer for this thread's assign_instance calls
            let mut scratch = vec![E::BaseField::ZERO; num_witin];
            indices
                .iter()
                .copied()
                .map(|step_idx| {
                    // Zero out scratch for each step
                    scratch.fill(E::BaseField::ZERO);
                    I::assign_instance(
                        config,
                        &mut shard_ctx,
                        &mut scratch,
                        &mut lk_multiplicity,
                        &shard_steps[step_idx],
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Result<(), ZKVMError>>()?;

    Ok(lk_multiplicity)
}

/// Convert GPU device buffer to RowMajorMatrix via D2H copy.
fn gpu_witness_to_rmm<E: ExtensionField>(
    gpu_result: ceno_gpu::common::witgen_types::GpuWitnessResult<
        ceno_gpu::common::BufferImpl<'static, <ff_ext::BabyBearExt4 as ExtensionField>::BaseField>,
    >,
    num_rows: usize,
    num_cols: usize,
    padding: InstancePaddingStrategy,
) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
    let gpu_data: Vec<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField> = gpu_result
        .device_buffer
        .to_vec()
        .map_err(|e| ZKVMError::InvalidWitness(format!("GPU D2H copy failed: {e}").into()))?;

    // Safety: BabyBear is the only supported GPU field, and E::BaseField must match
    let data: Vec<E::BaseField> = unsafe {
        let mut data = std::mem::ManuallyDrop::new(gpu_data);
        Vec::from_raw_parts(
            data.as_mut_ptr() as *mut E::BaseField,
            data.len(),
            data.capacity(),
        )
    };

    Ok(RowMajorMatrix::<E::BaseField>::new_by_values(
        data, num_cols, padding,
    ))
}
