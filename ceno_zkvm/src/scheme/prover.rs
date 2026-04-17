use ceno_gpu::Buffer;
use ff_ext::ExtensionField;
use gkr_iop::{
    cpu::{CpuBackend, CpuProver},
    hal::ProverBackend,
};
use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

#[cfg(feature = "gpu")]
use crate::scheme::gpu::estimate_chip_proof_memory;
use crate::scheme::{
    constants::SEPTIC_EXTENSION_DEGREE,
    hal::MainSumcheckEvals,
    scheduler::{ChipScheduler, ChipTask, ChipTaskResult},
};
use either::Either;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{Expression, Instance};
use p3::{field::FieldAlgebra, matrix::Matrix};
use std::iter::Iterator;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use tracing::info_span;
use transcript::{ForkableTranscript, Transcript};

use super::{PublicValues, ZKVMChipProof, ZKVMProof, hal::ProverDevice};
#[cfg(feature = "gpu")]
use crate::structs::ProvingKey;
use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    scheme::{
        hal::{DeviceProvingKey, ProofInput},
        utils::build_main_witness,
    },
    structs::{TowerProofs, ZKVMProvingKey, ZKVMWitnesses},
};

type CreateTableProof<E> = (ZKVMChipProof<E>, MainSumcheckEvals<E>, Point<E>);

pub type ZkVMCpuProver<E, PCS> =
    ZKVMProver<E, PCS, CpuBackend<E, PCS>, CpuProver<CpuBackend<E, PCS>>>;

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>, PB: ProverBackend, PD>
{
    pub pk: Arc<ZKVMProvingKey<E, PCS>>,
    device: PD,
    // device_pk might be none if there is no fixed commitment
    device_first_shard_pk: Option<DeviceProvingKey<'static, PB>>,
    device_non_first_shard_pk: Option<DeviceProvingKey<'static, PB>>,
    _marker: PhantomData<PB>,
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
> ZKVMProver<E, PCS, PB, PD>
{
    pub fn new_with_single_shard(pk: ZKVMProvingKey<E, PCS>, device: PD) -> Self {
        let pk = Arc::new(pk);
        let device_first_shard_pk = if pk.as_ref().has_fixed_commitment() {
            Some(device.transport_proving_key(true, pk.clone()))
        } else {
            None
        };

        ZKVMProver {
            pk,
            device,
            device_first_shard_pk,
            device_non_first_shard_pk: None,
            _marker: PhantomData,
        }
    }

    pub fn new(pk: Arc<ZKVMProvingKey<E, PCS>>, device: PD) -> Self {
        let (device_first_shard_pk, device_non_first_shard_pk) =
            if pk.as_ref().has_fixed_commitment() {
                (
                    Some(device.transport_proving_key(true, pk.clone())),
                    Some(device.transport_proving_key(false, pk.clone())),
                )
            } else {
                (None, None)
            };

        ZKVMProver {
            pk,
            device,
            device_first_shard_pk,
            device_non_first_shard_pk,
            _marker: PhantomData,
        }
    }

    pub fn get_device_proving_key(
        &self,
        shard_ctx: &ShardContext,
    ) -> Option<&DeviceProvingKey<'static, PB>> {
        if shard_ctx.is_first_shard() {
            self.device_first_shard_pk.as_ref()
        } else {
            self.device_non_first_shard_pk.as_ref()
        }
    }

    pub fn setup_init_mem(&self, hints: &[u32]) -> crate::e2e::InitMemState {
        let Some(ctx) = self.pk.program_ctx.as_ref() else {
            panic!("empty program ctx")
        };
        ctx.setup_init_mem(hints)
    }
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
> ZKVMProver<E, PCS, PB, PD>
{
    /// create proof for zkvm execution
    #[tracing::instrument(
        skip_all,
        name = "ZKVM_create_proof",
        fields(profiling_1),
        level = "trace"
    )]
    pub fn create_proof(
        &self,
        shard_ctx: &ShardContext,
        witnesses: ZKVMWitnesses<E>,
        pi: PublicValues,
        mut transcript: impl ForkableTranscript<E> + 'static,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        // Pre-extract fixed_mles before entering the tracing scope to avoid lifetime issues with std::thread::scope
        let fixed_mles_preload = self
            .get_device_proving_key(shard_ctx)
            .map(|dpk| dpk.fixed_mles.clone())
            .unwrap_or_default();

        info_span!(
            "[ceno] create_proof_of_shard",
            shard_id = shard_ctx.shard_id
        )
        .in_scope(|| {
            let span = entered_span!("commit_to_pi", profiling_1 = true);
            // Include transcript-visible public values in canonical circuit order.
            // The order must match verifier and recursion verifier exactly.
            for (_, circuit_pk) in self.pk.circuit_pks.iter() {
                for instance_value in circuit_pk.get_cs().zkvm_v1_css.instance.iter() {
                    transcript.append_field_element(&pi.query_by_index::<E>(instance_value.0));
                }
            }

            exit_span!(span);

            // commit to fixed commitment
            let span = entered_span!("commit_to_fixed_commit", profiling_1 = true);
            if let Some(fixed_commit) = self.pk.fixed_commit.as_ref() {
                PCS::write_commitment(fixed_commit, &mut transcript)
                    .map_err(ZKVMError::PCSError)?;
            }
            if let Some(fixed_commit) = self.pk.fixed_no_omc_init_commit.as_ref() {
                PCS::write_commitment(fixed_commit, &mut transcript)
                    .map_err(ZKVMError::PCSError)?;
            }
            exit_span!(span);

            // only keep track of circuits that have non-zero instances
            for (name, chip_inputs) in &witnesses.witnesses {
                let pk = self.pk.circuit_pks.get(name).ok_or(ZKVMError::VKNotFound(
                    format!("proving key for circuit {} not found", name).into(),
                ))?;

                // include omc init tables iff it's in first shard
                if !shard_ctx.is_first_shard() && pk.get_cs().with_omc_init_only() {
                    continue;
                }

                // num_instance from witness might include rotation
                let num_instances = chip_inputs
                    .iter()
                    .flat_map(|chip_input| chip_input.num_instances)
                    .collect_vec();

                if num_instances.iter().sum::<usize>() == 0 {
                    continue;
                }

                let circuit_idx = self.pk.circuit_name_to_index.get(name).unwrap();
                // write (circuit_idx, num_var) to transcript
                transcript.append_field_element(&E::BaseField::from_canonical_usize(*circuit_idx));
                for num_instance in num_instances {
                    transcript
                        .append_field_element(&E::BaseField::from_canonical_usize(num_instance));
                }
            }

            // extract chip meta info before consuming witnesses
            // (circuit_name, num_instances)
            let name_and_instances = witnesses.get_witnesses_name_instance();

            let commit_to_traces_span = entered_span!("batch commit to traces", profiling_1 = true);
            let mut wits_rmms = BTreeMap::new();
            #[cfg(feature = "gpu")]
            let mut deferred_gpu_traces = BTreeMap::new();

            let mut structural_rmms = Vec::with_capacity(name_and_instances.len());
            #[cfg(feature = "gpu")]
            let mut gpu_replay_plans = Vec::with_capacity(name_and_instances.len());
            // commit to opcode circuits first and then commit to table circuits, sorted by name
            for (i, chip_input) in witnesses.into_iter_sorted().enumerate() {
                let crate::structs::ChipInput {
                    witness_rmms,
                    gpu_replay_plan,
                    ..
                } = chip_input;
                let [witness_rmm, structural_witness_rmm] = witness_rmms;

                #[cfg(feature = "gpu")]
                let use_deferred_gpu_commit = crate::instructions::gpu::config::is_gpu_witgen_enabled()
                    && !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit();

                #[cfg(feature = "gpu")]
                if use_deferred_gpu_commit {
                    if let Some(plan) = gpu_replay_plan.clone() {
                        deferred_gpu_traces
                            .insert(i, crate::scheme::gpu::DeferredGpuTrace::Replay(plan));
                    } else if witness_rmm.num_instances() > 0 {
                        deferred_gpu_traces
                            .insert(i, crate::scheme::gpu::DeferredGpuTrace::Eager(witness_rmm));
                    }
                } else if witness_rmm.num_instances() > 0 {
                    wits_rmms.insert(i, witness_rmm);
                }

                #[cfg(not(feature = "gpu"))]
                if witness_rmm.num_instances() > 0 {
                    wits_rmms.insert(i, witness_rmm);
                }
                structural_rmms.push(structural_witness_rmm);
                #[cfg(feature = "gpu")]
                gpu_replay_plans.push(gpu_replay_plan);
            }

            tracing::debug!(
                "witness rmm in {} MB",
                wits_rmms
                    .values()
                    .map(|v| v.values.len() * std::mem::size_of::<E::BaseField>())
                    .sum::<usize>() as f64
                    / (1024.0 * 1024.0)
            );

            // Build trace index map: maps circuit enum index -> trace index in pcs_data.
            // BTreeMap iterates in key order, so trace indices match insertion order.
            // GPU uses this for deferred witness extraction; CPU ignores it.
            let circuit_trace_indices: Vec<Option<usize>> = {
                let mut next_trace = 0usize;
                (0..name_and_instances.len())
                    .map(|i| {
                        #[cfg(feature = "gpu")]
                        let has_trace = if crate::instructions::gpu::config::is_gpu_witgen_enabled()
                            && !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit()
                        {
                            deferred_gpu_traces.contains_key(&i)
                        } else {
                            wits_rmms.contains_key(&i)
                        };
                        #[cfg(not(feature = "gpu"))]
                        let has_trace = wits_rmms.contains_key(&i);
                        if has_trace {
                            let idx = next_trace;
                            next_trace += 1;
                            Some(idx)
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            #[cfg(feature = "gpu")]
            let use_deferred_gpu_commit = crate::instructions::gpu::config::is_gpu_witgen_enabled()
                && !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit()
                && std::any::TypeId::of::<PB>()
                    == std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>();
            #[cfg(not(feature = "gpu"))]
            let use_deferred_gpu_commit = false;

            // commit to witness traces in batch
            let (witness_mles, mut witness_data, witin_commit): (
                Vec<PB::MultilinearPoly<'_>>,
                PB::PcsData,
                PCS::Commitment,
            ) = if use_deferred_gpu_commit {
                info_span!("[ceno] commit_traces").in_scope(|| {
                    let gpu_device: &gkr_iop::gpu::GpuProver<gkr_iop::gpu::GpuBackend<E, PCS>> =
                        unsafe { std::mem::transmute(&self.device) };
                    let (gpu_witness_mles, gpu_witness_data, witin_commit) =
                        crate::scheme::gpu::commit_traces_deferred_cache_none::<E, PCS>(
                            gpu_device,
                            deferred_gpu_traces,
                        );
                    let witness_mles = unsafe { std::mem::transmute(gpu_witness_mles) };
                    let witness_data = unsafe { std::mem::transmute_copy(&gpu_witness_data) };
                    std::mem::forget(gpu_witness_data);
                    (witness_mles, witness_data, witin_commit)
                })
            } else {
                info_span!("[ceno] commit_traces").in_scope(|| self.device.commit_traces(wits_rmms))
            };
            PCS::write_commitment(&witin_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
            exit_span!(commit_to_traces_span);

            // Use pre-loaded fixed_mles (extracted before in_scope to avoid lifetime issues)
            let fixed_mles = fixed_mles_preload.clone();

            // squeeze two challenges from transcript
            let challenges = [
                transcript.read_challenge().elements,
                transcript.read_challenge().elements,
            ];
            tracing::debug!("global challenges in prover: {:?}", challenges);

            let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);

            // Phase 1: Build all ChipTasks
            let build_tasks_span = entered_span!("build_chip_tasks", profiling_1 = true);
            let tasks = self.build_chip_tasks(
                shard_ctx,
                name_and_instances,
                structural_rmms,
                #[cfg(feature = "gpu")]
                gpu_replay_plans,
                witness_mles,
                &witness_data,
                fixed_mles,
                challenges,
                &pi,
                &circuit_trace_indices,
            );
            #[cfg(feature = "gpu")]
            let replayable_traces: Vec<(usize, crate::structs::GpuReplayPlan<E>)> = tasks
                .iter()
                .filter_map(|task| {
                    task.gpu_replay_plan
                        .as_ref()
                        .and_then(|plan| plan.trace_idx.map(|trace_idx| (trace_idx, plan.clone())))
                })
                .collect();
            #[cfg(feature = "gpu")]
            if crate::instructions::gpu::config::is_gpu_witgen_enabled()
                && !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit()
            {
                if std::any::TypeId::of::<PB>()
                    == std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>()
                {
                    let gpu_witness_data: &mut <gkr_iop::gpu::GpuBackend<E, PCS> as ProverBackend>::PcsData =
                        unsafe { std::mem::transmute(&mut witness_data) };
                    crate::scheme::gpu::clear_replayable_trace_device_backing::<E, PCS>(
                        gpu_witness_data,
                        &replayable_traces,
                    );
                }
            }
            #[cfg(feature = "gpu")]
            if std::any::TypeId::of::<PB>()
                == std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>()
            {
                if let Some(active_dpk) = self.get_device_proving_key(shard_ctx) {
                    let active_fixed_pcs: &<gkr_iop::gpu::GpuBackend<E, PCS> as ProverBackend>::PcsData =
                        unsafe { std::mem::transmute(active_dpk.pcs_data.as_ref()) };
                    crate::scheme::gpu::log_gpu_pcs_baseline::<E, PCS>(
                        if shard_ctx.is_first_shard() {
                            "fixed_active_first"
                        } else {
                            "fixed_active_non_first"
                        },
                        active_fixed_pcs,
                    );
                }
                let inactive_dpk = if shard_ctx.is_first_shard() {
                    self.device_non_first_shard_pk.as_ref()
                } else {
                    self.device_first_shard_pk.as_ref()
                };
                if let Some(inactive_dpk) = inactive_dpk {
                    let inactive_fixed_pcs: &<gkr_iop::gpu::GpuBackend<E, PCS> as ProverBackend>::PcsData =
                        unsafe { std::mem::transmute(inactive_dpk.pcs_data.as_ref()) };
                    crate::scheme::gpu::log_gpu_pcs_baseline::<E, PCS>(
                        if shard_ctx.is_first_shard() {
                            "fixed_inactive_non_first"
                        } else {
                            "fixed_inactive_first"
                        },
                        inactive_fixed_pcs,
                    );
                }
                let gpu_witness_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as ProverBackend>::PcsData =
                    unsafe { std::mem::transmute(&witness_data) };
                let gpu_fixed_mles: &[std::sync::Arc<gkr_iop::gpu::MultilinearExtensionGpu<'static, E>>] =
                    unsafe { std::mem::transmute(fixed_mles_preload.as_slice()) };
                let task_structural_device_bytes = tasks
                    .iter()
                    .filter_map(|task| task.structural_rmm.as_ref())
                    .filter(|rmm| rmm.has_device_backing())
                    .map(|rmm| rmm.height() * rmm.width() * std::mem::size_of::<E::BaseField>())
                    .sum::<usize>();
                let task_structural_device_count = tasks
                    .iter()
                    .filter_map(|task| task.structural_rmm.as_ref())
                    .filter(|rmm| rmm.has_device_backing())
                    .count();
                let task_structural_device_mb =
                    task_structural_device_bytes as f64 / (1024.0 * 1024.0);
                let task_shard_ram_replay_raw_bytes = tasks
                    .iter()
                    .filter_map(|task| task.gpu_replay_plan.as_ref())
                    .filter_map(|plan| plan.shard_ram_records.as_ref())
                    .map(|buf| buf.len() * std::mem::size_of::<u32>())
                    .sum::<usize>();
                let task_shard_ram_replay_raw_count = tasks
                    .iter()
                    .filter_map(|task| task.gpu_replay_plan.as_ref())
                    .filter(|plan| plan.shard_ram_records.is_some())
                    .count();
                let task_shard_ram_replay_raw_mb =
                    task_shard_ram_replay_raw_bytes as f64 / (1024.0 * 1024.0);
                tracing::info!(
                    "[gpu baseline][before_scheduler] task_structural_device={:.2}MB ({})",
                    task_structural_device_mb,
                    task_structural_device_count,
                );
                tracing::info!(
                    "[gpu baseline][before_scheduler] task_shard_ram_replay_raw={:.2}MB ({})",
                    task_shard_ram_replay_raw_mb,
                    task_shard_ram_replay_raw_count,
                );
                crate::scheme::gpu::log_gpu_proof_baseline::<E, PCS>(
                    "before_scheduler",
                    gpu_witness_data,
                    gpu_fixed_mles,
                );
            }
            exit_span!(build_tasks_span);

            // Phase 2: Execute chip proof tasks
            // GPU concurrent: memory-aware backfilling with standalone impl.
            // Sequential (GPU + CPU): unified path via self.create_chip_proof.
            let execute_tasks_span = entered_span!("execute_chip_tasks", profiling_1 = true);
            let (results, forked_samples) =
                self.run_chip_proofs(tasks, &transcript, &witness_data)?;
            exit_span!(execute_tasks_span);

            // Phase 3: Collect results
            let collect_results_span = entered_span!("collect_chip_results", profiling_1 = true);
            let (chip_proofs, points, evaluations) = Self::collect_chip_results(results);
            exit_span!(collect_results_span);
            exit_span!(main_proofs_span);

            // merge forked transcript samples into main transcript
            for sample in forked_samples {
                transcript.append_field_element_ext(&sample);
            }

            // batch opening pcs
            // generate static info from prover key for expected num variable
            let pcs_opening = entered_span!("pcs_opening", profiling_1 = true);
            #[cfg(feature = "gpu")]
            if crate::instructions::gpu::config::is_gpu_witgen_enabled()
                && !crate::instructions::gpu::config::should_retain_witness_device_backing_after_commit()
                && std::any::TypeId::of::<PB>()
                    == std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>()
            {
                let gpu_witness_data: &mut <gkr_iop::gpu::GpuBackend<E, PCS> as ProverBackend>::PcsData =
                    unsafe { std::mem::transmute(&mut witness_data) };
                crate::scheme::gpu::restore_replayable_trace_device_backing::<E, PCS>(
                    gpu_witness_data,
                    &replayable_traces,
                )?;
            }
            let mpcs_opening_proof = info_span!("[ceno] pcs_opening").in_scope(|| {
                #[cfg(feature = "gpu")]
                {
                }
                self.device.open(
                    witness_data,
                    self.get_device_proving_key(shard_ctx)
                        .map(|dpk| dpk.pcs_data.clone()),
                    points,
                    evaluations,
                    &mut transcript,
                )
            });
            exit_span!(pcs_opening);

            let vm_proof = ZKVMProof::new(pi, chip_proofs, witin_commit, mpcs_opening_proof);

            Ok(vm_proof)
        })
    }

    /// Phase 2: Execute all chip proof tasks via scheduler.
    ///
    /// Sequential mode (GPU + CPU): uses `self.create_chip_proof` via trait dispatch.
    /// Concurrent mode (GPU only): uses standalone `create_chip_proof_gpu_impl`.
    ///
    /// Handles transcript forking and sampling internally via the scheduler.
    fn run_chip_proofs<'data, T: Transcript<E> + Clone>(
        &self,
        tasks: Vec<ChipTask<'data, PB>>,
        transcript: &T,
        witness_data: &PB::PcsData,
    ) -> Result<(Vec<ChipTaskResult<E>>, Vec<E>), ZKVMError> {
        let scheduler = ChipScheduler::new();

        #[cfg(feature = "gpu")]
        {
            if ChipScheduler::is_concurrent_mode() {
                // GPU concurrent: standalone function path (no &self needed for Send+Sync)
                // Verify at runtime that PB is indeed GpuBackend<E, PCS> before transmuting.
                assert_eq!(
                    std::any::TypeId::of::<PB>(),
                    std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>(),
                    "Concurrent GPU path requires PB = GpuBackend<E, PCS>"
                );
                // SAFETY: TypeId check above guarantees PB = GpuBackend<E, PCS>, so PcsData types match.
                let gpu_witness_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as gkr_iop::hal::ProverBackend>::PcsData =
                    unsafe { std::mem::transmute(witness_data) };

                // SAFETY: pcs_data is only read (via get_trace) during concurrent execution.
                use crate::scheme::utils::SyncRef;
                let gpu_wd = SyncRef(gpu_witness_data);

                return scheduler.execute(tasks, transcript, |task, transcript| {
                    // Append circuit_idx to per-task forked transcript (matching verifier)
                    transcript.append_field_element(&E::BaseField::from_canonical_u64(
                        task.circuit_idx as u64,
                    ));

                    // SAFETY: TypeId check above (before closure) guarantees PB = GpuBackend<E, PCS>.
                    let gpu_input: ProofInput<'static, gkr_iop::gpu::GpuBackend<E, PCS>> =
                        unsafe { std::mem::transmute(task.input) };

                    let (proof, opening_evals, input_opening_point) =
                        create_chip_proof_gpu_impl::<E, PCS>(
                            task.circuit_name.as_str(),
                            task.pk,
                            gpu_input,
                            transcript,
                            &task.challenges,
                            gpu_wd.0,
                            task.witness_trace_idx,
                            task.gpu_replay_plan.clone(),
                            task.num_witin,
                            task.structural_rmm,
                        )?;

                    Ok(ChipTaskResult {
                        task_id: task.task_id,
                        circuit_idx: task.circuit_idx,
                        proof,
                        opening_evals,
                        input_opening_point,
                        has_witness_or_fixed: task.has_witness_or_fixed,
                    })
                });
            }
        }

        // Sequential path (GPU + CPU unified):
        // Uses execute_sequentially directly to avoid Send+Sync requirement on the closure.
        scheduler.execute_sequentially(tasks, transcript, |mut task, transcript| {
            // Append circuit_idx to per-task forked transcript (matching verifier)
            transcript
                .append_field_element(&E::BaseField::from_canonical_u64(task.circuit_idx as u64));

            // Prepare: deferred extraction for GPU, no-op for CPU
            self.device.prepare_chip_input(&mut task, witness_data);

            let (proof, opening_evals, input_opening_point) =
                self.create_chip_proof(&task, transcript)?;

            Ok(ChipTaskResult {
                task_id: task.task_id,
                circuit_idx: task.circuit_idx,
                proof,
                opening_evals,
                input_opening_point,
                has_witness_or_fixed: task.has_witness_or_fixed,
            })
        })
    }

    /// create proof for opcode and table circuits
    ///
    /// for each read/write/logup expression, we pack all records of that type
    /// into a single tower tree, and then feed these trees into tower prover.
    #[tracing::instrument(skip_all, name = "create_chip_proof", fields(table_name=%task.circuit_name, profiling_2
    ), level = "trace")]
    pub fn create_chip_proof(
        &self,
        task: &ChipTask<'_, PB>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<CreateTableProof<E>, ZKVMError> {
        let circuit_pk = task.pk;
        let input = &task.input;
        let challenges = &task.challenges;

        let cs = circuit_pk.get_cs();
        let log2_num_instances = input.log2_num_instances();
        let num_var_with_rotation = log2_num_instances + cs.rotation_vars().unwrap_or(0);

        // run ecc quark prover
        let ecc_proof = if !cs.zkvm_v1_css.ec_final_sum.is_empty() {
            let span = entered_span!("run_ecc_final_sum", profiling_2 = true);
            let ec_point_exprs = &cs.zkvm_v1_css.ec_point_exprs;
            assert_eq!(ec_point_exprs.len(), SEPTIC_EXTENSION_DEGREE * 2);
            let mut xs_ys = ec_point_exprs
                .iter()
                .map(|expr| match expr {
                    Expression::WitIn(id) => input.witness[*id as usize].clone(),
                    _ => unreachable!("ec point's expression must be WitIn"),
                })
                .collect_vec();
            let ys = xs_ys.split_off(SEPTIC_EXTENSION_DEGREE);
            let xs = xs_ys;
            let slopes = cs
                .zkvm_v1_css
                .ec_slope_exprs
                .iter()
                .map(|expr| match expr {
                    Expression::WitIn(id) => input.witness[*id as usize].clone(),
                    _ => unreachable!("slope's expression must be WitIn"),
                })
                .collect_vec();
            let ecc_proof = Some(info_span!("[ceno] prove_ec_sum_quark").in_scope(|| {
                self.device
                    .prove_ec_sum_quark(input.num_instances(), xs, ys, slopes, transcript)
            })?);
            exit_span!(span);
            ecc_proof
        } else {
            None
        };

        // build main witness
        let records = info_span!("[ceno] build_main_witness")
            .in_scope(|| build_main_witness::<E, PCS, PB, PD>(cs, input, challenges));

        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        // prove the product and logup sum relation between layers in tower
        // (internally calls build_tower_witness)
        let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) =
            info_span!("[ceno] prove_tower_relation").in_scope(|| {
                self.device
                    .prove_tower_relation(cs, input, &records, challenges, transcript)
            });
        exit_span!(span);

        assert_eq!(
            rt_tower.len(), // num var length should equal to max_num_instance
            num_var_with_rotation,
        );

        // 1. prove the main constraints among witness polynomials
        // 2. prove the relation between last layer in the tower and read/write/logup records
        let span = entered_span!("prove_main_constraints", profiling_2 = true);
        let (input_opening_point, evals, main_sumcheck_proofs, gkr_iop_proof) =
            info_span!("[ceno] prove_main_constraints").in_scope(|| {
                self.device
                    .prove_main_constraints(rt_tower, input, cs, challenges, transcript)
            })?;
        let MainSumcheckEvals {
            wits_in_evals,
            fixed_in_evals,
        } = evals;
        exit_span!(span);

        Ok((
            ZKVMChipProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                main_sumcheck_proofs,
                gkr_iop_proof,
                tower_proof,
                ecc_proof,
                num_instances: input.num_instances,
            },
            MainSumcheckEvals {
                wits_in_evals,
                fixed_in_evals,
            },
            input_opening_point,
        ))
    }

    /// Phase 1: Build ChipTasks from witness data.
    /// All #[cfg] for eager vs deferred extraction are contained here.
    #[allow(clippy::too_many_arguments)]
    fn build_chip_tasks<'data>(
        &self,
        shard_ctx: &ShardContext,
        name_and_instances: Vec<(String, [usize; 2])>,
        structural_rmms: Vec<witness::RowMajorMatrix<E::BaseField>>,
        #[cfg(feature = "gpu")] gpu_replay_plans: Vec<Option<crate::structs::GpuReplayPlan<E>>>,
        #[allow(unused_mut)] mut witness_mles: Vec<PB::MultilinearPoly<'data>>,
        witness_data: &PB::PcsData,
        mut fixed_mles: Vec<Arc<PB::MultilinearPoly<'data>>>,
        challenges: [E; 2],
        pi: &PublicValues,
        circuit_trace_indices: &[Option<usize>],
    ) -> Vec<ChipTask<'_, PB>> {
        // CPU path: eagerly extract witness MLEs from pcs_data
        #[cfg(not(feature = "gpu"))]
        let mut witness_iter = self
            .device
            .extract_witness_mles(&mut witness_mles, witness_data);

        #[cfg(feature = "gpu")]
        let _ = (&witness_mles, witness_data); // suppress unused warnings on GPU path

        let mut tasks: Vec<ChipTask<'_, PB>> = Vec::new();
        let mut task_id = 0usize;

        for (circuit_enum_idx, ((circuit_name, num_instances), structural_rmm)) in
            name_and_instances
                .into_iter()
                .zip_eq(structural_rmms.into_iter())
                .enumerate()
        {
            let this_idx = circuit_enum_idx;

            let circuit_idx = self
                .pk
                .circuit_name_to_index
                .get(&circuit_name)
                .cloned()
                .expect("invalid circuit {} not exist in ceno zkvm");
            let pk = self.pk.circuit_pks.get(&circuit_name).unwrap();
            let cs = pk.get_cs();
            if !shard_ctx.is_first_shard() && cs.with_omc_init_only() {
                assert_eq!(num_instances, [0, 0]);
                // skip drain respective fixed because we use different set of fixed commitment
                continue;
            }
            if num_instances.iter().sum::<usize>() == 0 {
                // we need to drain respective fixed when num_instances is 0
                if cs.num_fixed() > 0 {
                    let _ = fixed_mles.drain(..cs.num_fixed()).collect_vec();
                }
                continue;
            }

            // GPU path: defer witness and structural witness extraction to task execution
            #[cfg(feature = "gpu")]
            let (witness_mle, structural_witness, task_structural_rmm) = {
                let _ = &structural_rmm; // suppress unused warning on structural_rmm binding
                let keep_structural_rmm = gpu_replay_plans[this_idx].is_none();
                (
                    vec![],
                    vec![],
                    if keep_structural_rmm {
                        Some(structural_rmm)
                    } else {
                        None
                    },
                )
            };

            // CPU path: eagerly extract witness and structural witness
            #[cfg(not(feature = "gpu"))]
            let (witness_mle, structural_witness, task_structural_rmm) = {
                let witness_mle = info_span!("[ceno] extract_witness_mles").in_scope(|| {
                    if cs.num_witin() > 0 {
                        let mles = witness_iter.by_ref().take(cs.num_witin()).collect_vec();
                        assert_eq!(
                            mles.len(),
                            cs.num_witin(),
                            "insufficient witness mles for circuit {}",
                            circuit_name
                        );
                        mles
                    } else {
                        vec![]
                    }
                });
                let structural_witness = info_span!("[ceno] transport_structural_witness")
                    .in_scope(|| {
                        let structural_mles = structural_rmm.to_mles();
                        self.device.transport_mles(&structural_mles)
                    });
                (witness_mle, structural_witness, None)
            };

            let fixed = fixed_mles.drain(..cs.num_fixed()).collect_vec();

            let circuit_pi = cs
                .zkvm_v1_css
                .instance
                .iter()
                .map(|Instance(idx)| Either::Left(pi.query_by_index::<E>(*idx)))
                .collect_vec();

            let input_temp: ProofInput<'_, PB> = ProofInput {
                witness: witness_mle,
                fixed,
                structural_witness,
                pi: circuit_pi,
                num_instances,
                has_ecc_ops: cs.has_ecc_ops(),
            };
            // SAFETY: All Arcs in ProofInput contain 'static data:
            // - GPU path: `witness` and `structural_witness` are empty vecs (deferred extraction),
            //   `fixed` originates from `DeviceProvingKey<'static, PB>`.
            // - CPU path: `witness_mle` may borrow non-'static data, but the CPU path always
            //   uses sequential execution (never enters the concurrent scheduler), so the data
            //   remains valid for the lifetime of `build_chip_tasks`'s caller.
            // The inferred lifetime is shorter than 'static only because the compiler cannot
            // prove the Arc contents are 'static across both cfg paths.
            let input = unsafe {
                std::mem::transmute::<ProofInput<'_, PB>, ProofInput<'static, PB>>(input_temp)
            };

            // Estimate memory for this task
            #[cfg(feature = "gpu")]
            let estimated_memory = {
                // SAFETY: TypeId check in run_chip_proofs guarantees PB = GpuBackend<E, PCS>.
                debug_assert_eq!(
                    std::any::TypeId::of::<PB>(),
                    std::any::TypeId::of::<gkr_iop::gpu::GpuBackend<E, PCS>>(),
                    "GPU memory estimation requires PB = GpuBackend<E, PCS>"
                );
                let gpu_input: &ProofInput<'_, gkr_iop::gpu::GpuBackend<E, PCS>> =
                    unsafe { std::mem::transmute(&input) };
                estimate_chip_proof_memory::<E, PCS>(
                    cs,
                    gpu_input,
                    &circuit_name,
                    gpu_replay_plans[this_idx].is_some(),
                )
            };
            #[cfg(not(feature = "gpu"))]
            let estimated_memory = 0u64; // CPU path doesn't need memory tracking

            // Look up trace index for deferred extraction (GPU uses this; CPU ignores it)
            let witness_trace_idx = if cs.num_witin() > 0 {
                circuit_trace_indices[this_idx]
            } else {
                None
            };
            #[cfg(feature = "gpu")]
            let gpu_replay_plan = gpu_replay_plans[this_idx].clone().map(|mut plan| {
                plan.trace_idx = witness_trace_idx;
                plan
            });

            tasks.push(ChipTask {
                task_id,
                circuit_name: circuit_name.clone(),
                circuit_idx,
                pk,
                input,
                estimated_memory_bytes: estimated_memory,
                has_witness_or_fixed: cs.num_witin() > 0 || cs.num_fixed() > 0,
                challenges,
                witness_trace_idx,
                #[cfg(feature = "gpu")]
                gpu_replay_plan,
                num_witin: cs.num_witin(),
                structural_rmm: task_structural_rmm,
            });
            task_id += 1;
        }
        #[cfg(not(feature = "gpu"))]
        drop(witness_iter);

        tasks
    }

    /// Phase 3: Collect chip proof results into proof components.
    #[allow(clippy::type_complexity)]
    fn collect_chip_results(
        results: Vec<ChipTaskResult<E>>,
    ) -> (
        BTreeMap<usize, Vec<ZKVMChipProof<E>>>,
        Vec<Point<E>>,
        Vec<Vec<Vec<E>>>,
    ) {
        let mut chip_proofs = BTreeMap::new();
        let mut points = Vec::new();
        let mut evaluations = Vec::new();

        for result in results {
            tracing::trace!(
                "generated proof for circuit {} with circuit_idx={}",
                result.circuit_idx,
                result.task_id
            );

            if result.has_witness_or_fixed {
                points.push(result.input_opening_point);
                evaluations.push(vec![
                    result.opening_evals.wits_in_evals,
                    result.opening_evals.fixed_in_evals,
                ]);
            }
            chip_proofs
                .entry(result.circuit_idx)
                .or_insert(vec![])
                .push(result.proof);
        }

        (chip_proofs, points, evaluations)
    }
}

/// GPU-specific standalone function for create_chip_proof that doesn't require &self.
/// Uses the _impl functions directly, avoiding Send/Sync requirements on ZKVMProver.
/// This enables parallel execution in the scheduler without capturing &self.
#[cfg(feature = "gpu")]
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, name = "create_chip_proof_gpu_impl", fields(table_name=name, profiling_2), level = "trace")]
pub fn create_chip_proof_gpu_impl<'a, E, PCS>(
    name: &str,
    circuit_pk: &ProvingKey<E>,
    mut input: ProofInput<'a, gkr_iop::gpu::GpuBackend<E, PCS>>,
    transcript: &mut impl Transcript<E>,
    challenges: &[E; 2],
    // Deferred extraction params:
    pcs_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as gkr_iop::hal::ProverBackend>::PcsData,
    witness_trace_idx: Option<usize>,
    #[cfg(feature = "gpu")] gpu_replay_plan: Option<crate::structs::GpuReplayPlan<E>>,
    num_witin: usize,
    structural_rmm: Option<witness::RowMajorMatrix<<E as ExtensionField>::BaseField>>,
) -> Result<CreateTableProof<E>, ZKVMError>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    use crate::{
        instructions::gpu::dispatch::GpuWitgenKind,
        scheme::{
            constants::NUM_FANIN,
            gpu::{
                build_tower_witness_gpu, check_gpu_mem_estimation,
                estimate_replay_materialization_bytes, estimate_tower_stage_bytes,
                extract_out_evals_from_gpu_towers, extract_witness_mles_for_trace,
                log_gpu_pool_usage, prove_ec_sum_quark_impl, prove_main_constraints_impl,
                prove_tower_relation_impl, transport_structural_witness_to_gpu,
            },
        },
    };
    use gkr_iop::gpu::{GpuBackend, get_cuda_hal};

    let cuda_hal = get_cuda_hal().expect("Failed to get CUDA HAL");
    let _stream = cuda_hal
        .inner
        .get_pool_stream()
        .expect("should acquire stream");
    let _thread_stream_guard = gkr_iop::gpu::bind_thread_stream(_stream.clone());
    let keccak_stage_split = gpu_replay_plan
        .as_ref()
        .is_some_and(|plan| matches!(plan.kind, GpuWitgenKind::Keccak));
    let structural_from_replay = structural_rmm.is_none();

    // Deferred witness extraction: extract from committed pcs_data just-in-time
    #[cfg(feature = "gpu")]
    let materialize_replay_input =
        |input: &mut ProofInput<'a, GpuBackend<E, PCS>>| -> Result<(), ZKVMError> {
            let Some(replay_plan) = gpu_replay_plan.as_ref() else {
                return Ok(());
            };
            let gpu_mem_tracker =
                crate::scheme::gpu::init_gpu_mem_tracker(&cuda_hal, "replay_gpu_witness_from_raw");
            let num_vars =
                input.log2_num_instances() + circuit_pk.get_cs().rotation_vars().unwrap_or(0);
            let estimated_replay_bytes = estimate_replay_materialization_bytes(
                circuit_pk.get_cs().zkvm_v1_css.num_witin as usize,
                circuit_pk.get_cs().zkvm_v1_css.num_structural_witin as usize,
                num_vars,
            );
            let estimated_replay_mb = estimated_replay_bytes as f64 / (1024.0 * 1024.0);
            tracing::info!(
                "[gpu] replaying witness from raw: circuit={}, estimated={:.2}MB",
                name,
                estimated_replay_mb,
            );
            log_gpu_pool_usage(&format!("{name}:before_replay"));
            let [witness_rmm, structural_rmm_from_replay] = replay_plan.replay()?;
            check_gpu_mem_estimation(gpu_mem_tracker, estimated_replay_bytes);
            input.witness = info_span!("[ceno] replay_gpu_witness_from_raw").in_scope(|| {
                crate::scheme::gpu::extract_witness_mles_for_trace_rmm::<E>(witness_rmm)
            });
            if structural_from_replay {
                input.structural_witness = info_span!("[ceno] transport_structural_witness")
                    .in_scope(|| {
                        transport_structural_witness_to_gpu::<E>(
                            structural_rmm_from_replay,
                            circuit_pk.get_cs().zkvm_v1_css.num_structural_witin as usize,
                            input.log2_num_instances()
                                + circuit_pk.get_cs().rotation_vars().unwrap_or(0),
                        )
                    });
            }
            log_gpu_pool_usage(&format!("{name}:after_replay"));
            Ok(())
        };

    #[cfg(feature = "gpu")]
    let clear_materialized_input = |input: &mut ProofInput<'a, GpuBackend<E, PCS>>| {
        input.witness = vec![];
        input.structural_witness = vec![];
    };

    #[cfg(feature = "gpu")]
    if !keccak_stage_split {
        if gpu_replay_plan.is_some() {
            materialize_replay_input(&mut input)?;
        } else if let Some(trace_idx) = witness_trace_idx {
            let num_vars =
                input.log2_num_instances() + circuit_pk.get_cs().rotation_vars().unwrap_or(0);
            input.witness = info_span!("[ceno] extract_witness_mles").in_scope(|| {
                extract_witness_mles_for_trace::<E, PCS>(pcs_data, trace_idx, num_witin, num_vars)
            });
        }
    }

    #[cfg(not(feature = "gpu"))]
    if let Some(trace_idx) = witness_trace_idx {
        let num_vars =
            input.log2_num_instances() + circuit_pk.get_cs().rotation_vars().unwrap_or(0);
        input.witness = info_span!("[ceno] extract_witness_mles").in_scope(|| {
            extract_witness_mles_for_trace::<E, PCS>(pcs_data, trace_idx, num_witin, num_vars)
        });
    }

    let cs = circuit_pk.get_cs();
    let log2_num_instances = input.log2_num_instances();
    let num_var_with_rotation = log2_num_instances + cs.rotation_vars().unwrap_or(0);

    // Deferred structural witness transport: CPU -> GPU just-in-time
    if !keccak_stage_split {
        if let Some(rmm) = structural_rmm {
            let num_structural_witin = cs.zkvm_v1_css.num_structural_witin as usize;
            input.structural_witness =
                info_span!("[ceno] transport_structural_witness").in_scope(|| {
                    transport_structural_witness_to_gpu::<E>(
                        rmm,
                        num_structural_witin,
                        num_var_with_rotation,
                    )
                });
        }
    }

    if keccak_stage_split {
        materialize_replay_input(&mut input)?;
        let cs = circuit_pk.get_cs();

        let ecc_proof = if !cs.zkvm_v1_css.ec_final_sum.is_empty() {
            let span = entered_span!("run_ecc_final_sum", profiling_2 = true);
            let ec_point_exprs = &cs.zkvm_v1_css.ec_point_exprs;
            assert_eq!(ec_point_exprs.len(), SEPTIC_EXTENSION_DEGREE * 2);
            let mut xs_ys = ec_point_exprs
                .iter()
                .map(|expr| match expr {
                    Expression::WitIn(id) => input.witness[*id as usize].clone(),
                    _ => unreachable!("ec point's expression must be WitIn"),
                })
                .collect_vec();
            let ys = xs_ys.split_off(SEPTIC_EXTENSION_DEGREE);
            let xs = xs_ys;
            let slopes = cs
                .zkvm_v1_css
                .ec_slope_exprs
                .iter()
                .map(|expr| match expr {
                    Expression::WitIn(id) => input.witness[*id as usize].clone(),
                    _ => unreachable!("slope's expression must be WitIn"),
                })
                .collect_vec();
            let ecc_proof = Some(info_span!("[ceno] prove_ec_sum_quark").in_scope(|| {
                prove_ec_sum_quark_impl::<E, PCS>(input.num_instances(), xs, ys, slopes, transcript)
            })?);
            exit_span!(span);
            ecc_proof
        } else {
            None
        };

        let records = info_span!("[ceno] build_main_witness").in_scope(|| {
            build_main_witness::<
                E,
                PCS,
                GpuBackend<E, PCS>,
                gkr_iop::gpu::GpuProver<GpuBackend<E, PCS>>,
            >(cs, &input, challenges)
        });
        log_gpu_pool_usage(&format!("{name}:after_build_main_witness"));

        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        let r_set_len =
            cs.zkvm_v1_css.r_expressions.len() + cs.zkvm_v1_css.r_table_expressions.len();
        let (tower_build_estimated_bytes, tower_prove_estimated_bytes) =
            estimate_tower_stage_bytes::<E, PCS>(cs, &input);
        tracing::info!(
            "[gpu tower][{}] estimated: build_tower={:.2}MB, prove_tower={:.2}MB",
            name,
            tower_build_estimated_bytes as f64 / (1024.0 * 1024.0),
            tower_prove_estimated_bytes as f64 / (1024.0 * 1024.0),
        );
        let tower_build_mem_tracker =
            crate::scheme::gpu::init_gpu_mem_tracker(&cuda_hal, "build_tower_witness_gpu");
        let mut big_buffers = Vec::new();
        let mut ones_buffer = Vec::new();
        let mut view_last_layers = Vec::new();
        log_gpu_pool_usage(&format!("{name}:before_build_tower_witness"));
        let (prod_gpu, logup_gpu, lk_out_evals, w_out_evals, r_out_evals) =
            info_span!("[ceno] build_tower_witness_gpu").in_scope(|| {
                let (prod_gpu, logup_gpu) = build_tower_witness_gpu(
                    cs,
                    &input,
                    &records,
                    challenges,
                    &cuda_hal,
                    &mut big_buffers,
                    &mut ones_buffer,
                    &mut view_last_layers,
                )
                .map_err(|e| {
                    ZKVMError::InvalidWitness(format!("build_tower_witness_gpu failed: {e}").into())
                })?;
                let (r_out_evals, w_out_evals, lk_out_evals) =
                    extract_out_evals_from_gpu_towers(&prod_gpu, &logup_gpu, r_set_len);
                Ok::<_, ZKVMError>((prod_gpu, logup_gpu, lk_out_evals, w_out_evals, r_out_evals))
            })?;
        check_gpu_mem_estimation(tower_build_mem_tracker, tower_build_estimated_bytes);
        log_gpu_pool_usage(&format!("{name}:after_build_tower_witness"));

        for eval in r_out_evals
            .iter()
            .chain(w_out_evals.iter())
            .chain(lk_out_evals.iter())
            .flatten()
        {
            transcript.append_field_element_ext(eval);
        }

        clear_materialized_input(&mut input);

        let basic_tr = crate::scheme::gpu::expect_basic_transcript(transcript);
        let tower_input = ceno_gpu::TowerInput {
            prod_specs: prod_gpu,
            logup_specs: logup_gpu,
        };
        let tower_prove_mem_tracker =
            crate::scheme::gpu::init_gpu_mem_tracker(&cuda_hal, "prove_tower_relation_gpu");
        log_gpu_pool_usage(&format!("{name}:before_prove_tower"));
        let (rt_tower_gl, tower_proof_gpu) = info_span!("[ceno] prove_tower_relation_gpu")
            .in_scope(|| {
                cuda_hal
                    .tower
                    .create_proof(
                        &cuda_hal,
                        &tower_input,
                        NUM_FANIN,
                        basic_tr,
                        gkr_iop::gpu::get_thread_stream().as_ref(),
                    )
                    .expect("gpu tower create_proof failed")
            });
        log_gpu_pool_usage(&format!("{name}:after_prove_tower"));
        let rt_tower: Point<E> = unsafe { std::mem::transmute(rt_tower_gl) };
        let tower_proof: TowerProofs<E> = unsafe { std::mem::transmute(tower_proof_gpu) };
        check_gpu_mem_estimation(tower_prove_mem_tracker, tower_prove_estimated_bytes);
        drop(records);
        exit_span!(span);

        assert_eq!(rt_tower.len(), num_var_with_rotation);

        materialize_replay_input(&mut input)?;
        let span = entered_span!("prove_main_constraints", profiling_2 = true);
        let (input_opening_point, evals, main_sumcheck_proofs, gkr_iop_proof) =
            info_span!("[ceno] prove_main_constraints").in_scope(|| {
                prove_main_constraints_impl::<E, PCS>(rt_tower, &input, cs, challenges, transcript)
            })?;
        let MainSumcheckEvals {
            wits_in_evals,
            fixed_in_evals,
        } = evals;
        clear_materialized_input(&mut input);
        exit_span!(span);

        return Ok((
            ZKVMChipProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                main_sumcheck_proofs,
                gkr_iop_proof,
                tower_proof,
                ecc_proof,
                num_instances: input.num_instances,
            },
            MainSumcheckEvals {
                wits_in_evals,
                fixed_in_evals,
            },
            input_opening_point,
        ));
    }

    // run ecc quark prover using _impl function
    let ecc_proof = if !cs.zkvm_v1_css.ec_final_sum.is_empty() {
        let span = entered_span!("run_ecc_final_sum", profiling_2 = true);
        let ec_point_exprs = &cs.zkvm_v1_css.ec_point_exprs;
        assert_eq!(ec_point_exprs.len(), SEPTIC_EXTENSION_DEGREE * 2);
        let mut xs_ys = ec_point_exprs
            .iter()
            .map(|expr| match expr {
                Expression::WitIn(id) => input.witness[*id as usize].clone(),
                _ => unreachable!("ec point's expression must be WitIn"),
            })
            .collect_vec();
        let ys = xs_ys.split_off(SEPTIC_EXTENSION_DEGREE);
        let xs = xs_ys;
        let slopes = cs
            .zkvm_v1_css
            .ec_slope_exprs
            .iter()
            .map(|expr| match expr {
                Expression::WitIn(id) => input.witness[*id as usize].clone(),
                _ => unreachable!("slope's expression must be WitIn"),
            })
            .collect_vec();
        let ecc_proof = Some(info_span!("[ceno] prove_ec_sum_quark").in_scope(|| {
            prove_ec_sum_quark_impl::<E, PCS>(input.num_instances(), xs, ys, slopes, transcript)
        })?);
        exit_span!(span);
        ecc_proof
    } else {
        None
    };

    // build main witness
    let records =
        info_span!("[ceno] build_main_witness").in_scope(|| {
            build_main_witness::<
                E,
                PCS,
                GpuBackend<E, PCS>,
                gkr_iop::gpu::GpuProver<GpuBackend<E, PCS>>,
            >(cs, &input, challenges)
        });

    let span = entered_span!("prove_tower_relation", profiling_2 = true);
    // prove the product and logup sum relation between layers in tower using _impl function
    let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) =
        info_span!("[ceno] prove_tower_relation").in_scope(|| {
            prove_tower_relation_impl::<E, PCS>(
                cs, &input, &records, challenges, transcript, &cuda_hal,
            )
        });
    exit_span!(span);

    assert_eq!(rt_tower.len(), num_var_with_rotation,);

    // prove main constraints using _impl function
    let span = entered_span!("prove_main_constraints", profiling_2 = true);
    let (input_opening_point, evals, main_sumcheck_proofs, gkr_iop_proof) =
        info_span!("[ceno] prove_main_constraints").in_scope(|| {
            prove_main_constraints_impl::<E, PCS>(rt_tower, &input, cs, challenges, transcript)
        })?;
    let MainSumcheckEvals {
        wits_in_evals,
        fixed_in_evals,
    } = evals;
    exit_span!(span);

    Ok((
        ZKVMChipProof {
            r_out_evals,
            w_out_evals,
            lk_out_evals,
            main_sumcheck_proofs,
            gkr_iop_proof,
            tower_proof,
            ecc_proof,
            num_instances: input.num_instances,
        },
        MainSumcheckEvals {
            wits_in_evals,
            fixed_in_evals,
        },
        input_opening_point,
    ))
}

/// TowerProofs
impl<E: ExtensionField> TowerProofs<E> {
    pub fn new(prod_spec_size: usize, logup_spec_size: usize) -> Self {
        TowerProofs {
            proofs: vec![],
            prod_specs_eval: vec![vec![]; prod_spec_size],
            logup_specs_eval: vec![vec![]; logup_spec_size],
            prod_specs_points: vec![vec![]; prod_spec_size],
            logup_specs_points: vec![vec![]; logup_spec_size],
        }
    }
    pub fn push_sumcheck_proofs(&mut self, proofs: Vec<IOPProverMessage<E>>) {
        self.proofs.push(proofs);
    }

    pub fn push_prod_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.prod_specs_eval[spec_index].push(evals);
        self.prod_specs_points[spec_index].push(point);
    }

    pub fn push_logup_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.logup_specs_eval[spec_index].push(evals);
        self.logup_specs_points[spec_index].push(point);
    }

    pub fn prod_spec_size(&self) -> usize {
        self.prod_specs_eval.len()
    }

    pub fn logup_spec_size(&self) -> usize {
        self.logup_specs_eval.len()
    }
}
