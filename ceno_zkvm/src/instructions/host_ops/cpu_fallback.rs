use ceno_emul::StepIndex;
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use itertools::Itertools;
use multilinear_extensions::util::max_usable_threads;
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use witness::RowMajorMatrix;

use crate::{
    e2e::ShardContext, error::ZKVMError, tables::RMMCollections, witness::LkMultiplicity,
};

use super::super::Instruction;

/// CPU-only assign_instances. Extracted so GPU-enabled instructions can call this as fallback.
pub fn cpu_assign_instances<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[ceno_emul::StepRecord],
    step_indices: &[StepIndex],
) -> Result<
    (
        RMMCollections<E::BaseField>,
        Multiplicity<u64>,
    ),
    ZKVMError,
> {
    assert!(num_structural_witin == 0 || num_structural_witin == 1);
    let num_structural_witin = num_structural_witin.max(1);

    let nthreads = max_usable_threads();
    let total_instances = step_indices.len();
    let num_instance_per_batch = if total_instances > 256 {
        total_instances.div_ceil(nthreads)
    } else {
        total_instances
    }
    .max(1);
    let lk_multiplicity = LkMultiplicity::default();
    let mut raw_witin =
        RowMajorMatrix::<E::BaseField>::new(total_instances, num_witin, I::padding_strategy());
    let mut raw_structual_witin = RowMajorMatrix::<E::BaseField>::new(
        total_instances,
        num_structural_witin,
        I::padding_strategy(),
    );
    let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);
    let raw_structual_witin_iter = raw_structual_witin.par_batch_iter_mut(num_instance_per_batch);
    let shard_ctx_vec = shard_ctx.get_forked();

    raw_witin_iter
        .zip_eq(raw_structual_witin_iter)
        .zip_eq(step_indices.par_chunks(num_instance_per_batch))
        .zip(shard_ctx_vec)
        .flat_map(
            |(((instances, structural_instance), indices), mut shard_ctx)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                instances
                    .chunks_mut(num_witin)
                    .zip_eq(structural_instance.chunks_mut(num_structural_witin))
                    .zip_eq(indices.iter().copied())
                    .map(|((instance, structural_instance), step_idx)| {
                        *structural_instance.last_mut().unwrap() = E::BaseField::ONE;
                        I::assign_instance(
                            config,
                            &mut shard_ctx,
                            instance,
                            &mut lk_multiplicity,
                            &shard_steps[step_idx],
                        )
                    })
                    .collect::<Vec<_>>()
            },
        )
        .collect::<Result<(), ZKVMError>>()?;

    raw_witin.padding_by_strategy();
    raw_structual_witin.padding_by_strategy();
    Ok((
        [raw_witin, raw_structual_witin],
        lk_multiplicity.into_finalize_result(),
    ))
}

/// CPU-only side-effect collection for GPU-enabled instructions.
///
/// This path deliberately avoids scratch witness buffers and calls only the
/// instruction-specific side-effect collector.
pub fn cpu_collect_side_effects<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    shard_steps: &[ceno_emul::StepRecord],
    step_indices: &[StepIndex],
) -> Result<Multiplicity<u64>, ZKVMError> {
    cpu_collect_side_effects_inner::<E, I>(config, shard_ctx, shard_steps, step_indices, false)
}

/// CPU-side `send()` / `addr_accessed` collection for GPU-assisted lk paths.
///
/// Implementations may still increment fetch multiplicity on CPU, but all other
/// lookup multiplicities are expected to come from the GPU path.
pub fn cpu_collect_shard_side_effects<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    shard_steps: &[ceno_emul::StepRecord],
    step_indices: &[StepIndex],
) -> Result<Multiplicity<u64>, ZKVMError> {
    cpu_collect_side_effects_inner::<E, I>(config, shard_ctx, shard_steps, step_indices, true)
}

fn cpu_collect_side_effects_inner<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    shard_steps: &[ceno_emul::StepRecord],
    step_indices: &[StepIndex],
    shard_only: bool,
) -> Result<Multiplicity<u64>, ZKVMError> {
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
            indices
                .iter()
                .copied()
                .map(|step_idx| {
                    if shard_only {
                        I::collect_shard_side_effects_instance(
                            config,
                            &mut shard_ctx,
                            &mut lk_multiplicity,
                            &shard_steps[step_idx],
                        )
                    } else {
                        I::collect_side_effects_instance(
                            config,
                            &mut shard_ctx,
                            &mut lk_multiplicity,
                            &shard_steps[step_idx],
                        )
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Result<(), ZKVMError>>()?;

    Ok(lk_multiplicity.into_finalize_result())
}
