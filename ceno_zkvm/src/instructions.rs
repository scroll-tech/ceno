use crate::{
    circuit_builder::CircuitBuilder, e2e::ShardContext, error::ZKVMError, structs::ProgramParams,
    tables::RMMCollections, witness::LkMultiplicity,
};
use ceno_emul::{StepIndex, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::{
    chip::Chip,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
    utils::lk_multiplicity::Multiplicity,
};
use itertools::Itertools;
use multilinear_extensions::{ToExpr, util::max_usable_threads};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

pub mod gpu;
pub mod riscv;

pub use gpu::utils::{cpu_assign_instances, cpu_collect_lk_and_shardram, cpu_collect_shardram};

pub trait Instruction<E: ExtensionField> {
    type InstructionConfig: Send + Sync;
    type InsnType: Clone + Copy;

    const GPU_LK_SHARDRAM: bool = false;

    fn padding_strategy() -> InstancePaddingStrategy {
        InstancePaddingStrategy::Default
    }

    fn inst_kinds() -> &'static [Self::InsnType];

    fn name() -> String;

    /// construct circuit and manipulate circuit builder, then return the respective config
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError>;

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, param)?;
        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();

        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let selector_type = SelectorType::Prefix(selector.expr());

        // all shared the same selector
        let (out_evals, mut chip) = (
            [
                // r_record
                (0..r_len).collect_vec(),
                // w_record
                (r_len..r_len + w_len).collect_vec(),
                // lk_record
                (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                // zero_record
                (0..zero_len).collect_vec(),
            ],
            Chip::new_from_cb(cb, 0),
        );

        // register selector to legacy constrain system
        cb.cs.r_selector = Some(selector_type.clone());
        cb.cs.w_selector = Some(selector_type.clone());
        cb.cs.lk_selector = Some(selector_type.clone());
        cb.cs.zero_selector = Some(selector_type.clone());

        let layer = Layer::from_circuit_builder(cb, format!("{}_main", Self::name()), 0, out_evals);
        chip.add_layer(layer);

        Ok((config, chip.gkr_circuit()))
    }

    fn generate_fixed_traces(
        _config: &Self::InstructionConfig,
        _num_fixed: usize,
    ) -> Option<RowMajorMatrix<E::BaseField>> {
        None
    }

    // assign single instance giving step from trace
    fn assign_instance<'a>(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext<'a>,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError>;

    fn collect_lk_and_shardram(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut ShardContext,
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(ZKVMError::InvalidWitness(
            format!(
                "{} does not implement lk and shardram collection",
                Self::name()
            )
            .into(),
        ))
    }

    fn collect_shardram(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut ShardContext,
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(ZKVMError::InvalidWitness(
            format!(
                "{} does not implement shardram-only collection",
                Self::name()
            )
            .into(),
        ))
    }

    fn assign_instances(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        shard_steps: &[StepRecord],
        step_indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        // TODO: selector is the only structural witness
        // this is workaround, as call `construct_circuit` will not initialized selector
        // we can remove this one all opcode unittest migrate to call `build_gkr_iop_circuit`
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
        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
            total_instances,
            num_witin,
            Self::padding_strategy(),
        );
        let mut raw_structual_witin = RowMajorMatrix::<E::BaseField>::new(
            total_instances,
            num_structural_witin,
            Self::padding_strategy(),
        );
        let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);
        let raw_structual_witin_iter =
            raw_structual_witin.par_batch_iter_mut(num_instance_per_batch);
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
                            Self::assign_instance(
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

    fn assign_instances_from_steps(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        num_witin: usize,
        num_structural_witin: usize,
        steps: &[StepRecord],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let indices = full_step_indices(steps);
        Self::assign_instances(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            steps,
            &indices,
        )
    }
}

pub fn full_step_indices(steps: &[StepRecord]) -> Vec<StepIndex> {
    (0..steps.len()).collect()
}

// ---------------------------------------------------------------------------
// Macros to reduce per-chip boilerplate
// ---------------------------------------------------------------------------

/// Implement `collect_lk_and_shardram` with a common prologue
/// (create `CpuLkShardramSink`, dispatch to `config.$field.emit_lk_and_shardram`)
/// and a chip-specific body for additional LK ops.
///
/// The closure receives `(sink, step, config, ctx)`:
/// - `sink: &mut CpuLkShardramSink` — emit LK ops and send events
/// - `step: &StepRecord` — current step
/// - `config: &Self::InstructionConfig` — circuit config (for sub-configs)
/// - `ctx: &ShardContext` — read-only shard context
///
/// Usage inside `impl Instruction<E> for MyChip`:
/// ```ignore
/// impl_collect_lk_and_shardram!(r_insn, |sink, step, _config, _ctx| {
///     emit_u16_limbs(sink, step.rd().unwrap().value.after);
/// });
/// ```
#[macro_export]
macro_rules! impl_collect_lk_and_shardram {
    ($field:ident, |$sink:ident, $step:ident, $config:ident, $ctx:ident| $body:block) => {
        fn collect_lk_and_shardram(
            config: &Self::InstructionConfig,
            shard_ctx: &mut $crate::e2e::ShardContext,
            lk_multiplicity: &mut $crate::witness::LkMultiplicity,
            step: &ceno_emul::StepRecord,
        ) -> Result<(), $crate::error::ZKVMError> {
            let shard_ctx_ptr = shard_ctx as *mut $crate::e2e::ShardContext;
            let _ctx = unsafe { &*shard_ctx_ptr };
            let mut _sink_val = unsafe {
                $crate::instructions::gpu::utils::CpuLkShardramSink::from_raw(
                    shard_ctx_ptr,
                    lk_multiplicity,
                )
            };
            config.$field.emit_lk_and_shardram(&mut _sink_val, _ctx, step);
            let $sink = &mut _sink_val;
            let $step = step;
            let $config = config;
            let $ctx = _ctx;
            $body
            Ok(())
        }
    };
}

/// Implement `collect_shardram` by delegating to
/// `config.$field.emit_shardram(shard_ctx, lk_multiplicity, step)`.
///
/// Every chip's implementation is identical except for the config field name
/// (`r_insn`, `i_insn`, `b_insn`, `s_insn`, `j_insn`, `im_insn`).
///
/// Usage inside `impl Instruction<E> for MyChip`:
/// ```ignore
/// impl_collect_shardram!(r_insn);
/// ```
#[macro_export]
macro_rules! impl_collect_shardram {
    ($field:ident) => {
        fn collect_shardram(
            config: &Self::InstructionConfig,
            shard_ctx: &mut $crate::e2e::ShardContext,
            lk_multiplicity: &mut $crate::witness::LkMultiplicity,
            step: &ceno_emul::StepRecord,
        ) -> Result<(), $crate::error::ZKVMError> {
            config
                .$field
                .emit_shardram(shard_ctx, lk_multiplicity, step);
            Ok(())
        }
    };
}

/// Implement the `#[cfg(feature = "gpu")] fn assign_instances` override that:
/// 1. Computes `Option<GpuWitgenKind>` from `$kind_expr`
/// 2. Tries `try_gpu_assign_instances` → returns on success
/// 3. Falls back to `cpu_assign_instances`
///
/// Usage inside `impl Instruction<E> for MyChip`:
/// ```ignore
/// // Single kind (always GPU):
/// impl_gpu_assign!(GpuWitgenKind::Lui);
///
/// // Match expression → Option<GpuWitgenKind>:
/// impl_gpu_assign!(match I::INST_KIND {
///     InsnKind::ADD => Some(GpuWitgenKind::Add),
///     InsnKind::SUB => Some(GpuWitgenKind::Sub),
///     _ => None,
/// });
/// ```
#[macro_export]
macro_rules! impl_gpu_assign {
    // Match/block → Option<GpuWitgenKind>
    (match $($rest:tt)*) => {
        $crate::impl_gpu_assign!(@ match $($rest)*);
    };
    // Single kind — always use GPU
    ($kind:expr) => {
        $crate::impl_gpu_assign!(@ Some($kind));
    };
    (@ $kind_expr:expr) => {
        #[cfg(feature = "gpu")]
        fn assign_instances(
            config: &Self::InstructionConfig,
            shard_ctx: &mut $crate::e2e::ShardContext,
            num_witin: usize,
            num_structural_witin: usize,
            shard_steps: &[ceno_emul::StepRecord],
            step_indices: &[ceno_emul::StepIndex],
        ) -> Result<
            (
                $crate::tables::RMMCollections<E::BaseField>,
                gkr_iop::utils::lk_multiplicity::Multiplicity<u64>,
            ),
            $crate::error::ZKVMError,
        > {
            use $crate::instructions::gpu::dispatch;
            let gpu_kind: Option<dispatch::GpuWitgenKind> = $kind_expr;
            if let Some(kind) = gpu_kind {
                if let Some(result) = dispatch::try_gpu_assign_instances::<E, Self>(
                    config,
                    shard_ctx,
                    num_witin,
                    num_structural_witin,
                    shard_steps,
                    step_indices,
                    kind,
                )? {
                    return Ok(result);
                }
            }
            $crate::instructions::cpu_assign_instances::<E, Self>(
                config,
                shard_ctx,
                num_witin,
                num_structural_witin,
                shard_steps,
                step_indices,
            )
        }
    };
}
