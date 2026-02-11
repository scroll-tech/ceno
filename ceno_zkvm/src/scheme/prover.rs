use ff_ext::ExtensionField;
use gkr_iop::{
    cpu::{CpuBackend, CpuProver},
    hal::ProverBackend,
};
use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
    sync::Arc,
};

use crate::scheme::{
    constants::SEPTIC_EXTENSION_DEGREE,
    hal::MainSumcheckEvals,
    scheduler::{ChipScheduler, ChipTask, ChipTaskResult},
};
#[cfg(feature = "gpu")]
use crate::scheme::gpu::estimate_chip_proof_memory;
use either::Either;
use gkr_iop::hal::MultilinearPolynomial;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, Instance,
    mle::{IntoMLE, MultilinearExtension},
};
use p3::field::FieldAlgebra;
use std::iter::Iterator;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use tracing::info_span;
use transcript::{ForkableTranscript, Transcript};

use super::{PublicValues, ZKVMChipProof, ZKVMProof, hal::ProverDevice};
use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    scheme::{
        hal::{DeviceProvingKey, ProofInput},
        utils::build_main_witness,
    },
    structs::{ProvingKey, TowerProofs, ZKVMProvingKey, ZKVMWitnesses},
};

type CreateTableProof<E> = (ZKVMChipProof<E>, HashMap<usize, E>, Point<E>);

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

    pub fn setup_init_mem(&self, hints: &[u32], public_io: &[u32]) -> crate::e2e::InitMemState {
        let Some(ctx) = self.pk.program_ctx.as_ref() else {
            panic!("empty program ctx")
        };
        ctx.setup_init_mem(hints, public_io)
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
            let raw_pi = pi.to_vec::<E>();
            let mut pi_evals = ZKVMProof::<E, PCS>::pi_evals(&raw_pi);
            let mut chip_proofs = BTreeMap::new();

            let span = entered_span!("commit_to_pi", profiling_1 = true);
            // including raw public input to transcript
            for v in raw_pi.iter().flatten() {
                transcript.append_field_element(v);
            }
            exit_span!(span);

            let pi: Vec<MultilinearExtension<E>> =
                raw_pi.iter().map(|p| p.to_vec().into_mle()).collect();

            // commit to fixed commitment
            let span = entered_span!("commit_to_fixed_commit", profiling_1 = true);
            if let Some(fixed_commit) = &self.pk.fixed_commit
                && shard_ctx.is_first_shard()
            {
                PCS::write_commitment(fixed_commit, &mut transcript)
                    .map_err(ZKVMError::PCSError)?;
            } else if let Some(fixed_commit) = &self.pk.fixed_no_omc_init_commit
                && !shard_ctx.is_first_shard()
            {
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
                    .flat_map(|chip_input| &chip_input.num_instances)
                    .collect_vec();

                if num_instances.is_empty() {
                    continue;
                }

                let circuit_idx = self.pk.circuit_name_to_index.get(name).unwrap();
                // write (circuit_idx, num_var) to transcript
                transcript.append_field_element(&E::BaseField::from_canonical_usize(*circuit_idx));
                for num_instance in num_instances {
                    transcript
                        .append_field_element(&E::BaseField::from_canonical_usize(*num_instance));
                }
            }

            // extract chip meta info before consuming witnesses
            // (circuit_name, num_instances)
            let name_and_instances = witnesses.get_witnesses_name_instance();

            let commit_to_traces_span = entered_span!("batch commit to traces", profiling_1 = true);
            let mut wits_rmms = BTreeMap::new();

            let mut structural_rmms = Vec::with_capacity(name_and_instances.len());
            // commit to opcode circuits first and then commit to table circuits, sorted by name
            for (i, chip_input) in witnesses.into_iter_sorted().enumerate() {
                let [witness_rmm, structural_witness_rmm] = chip_input.witness_rmms;

                if witness_rmm.num_instances() > 0 {
                    wits_rmms.insert(i, witness_rmm);
                }
                structural_rmms.push(structural_witness_rmm);
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
            #[cfg(feature = "gpu")]
            let circuit_trace_indices: Vec<Option<usize>> = {
                let mut next_trace = 0usize;
                (0..name_and_instances.len())
                    .map(|i| {
                        if wits_rmms.contains_key(&i) {
                            let idx = next_trace;
                            next_trace += 1;
                            Some(idx)
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            // commit to witness traces in batch
            #[allow(unused_mut, unused_variables)]
            let (mut witness_mles, witness_data, witin_commit) = info_span!("[ceno] commit_traces")
                .in_scope(|| self.device.commit_traces(wits_rmms));
            PCS::write_commitment(&witin_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
            exit_span!(commit_to_traces_span);

            // Use pre-loaded fixed_mles (extracted before in_scope to avoid lifetime issues)
            let mut fixed_mles = fixed_mles_preload;

            // squeeze two challenges from transcript
            let challenges = [
                transcript.read_challenge().elements,
                transcript.read_challenge().elements,
            ];
            tracing::debug!("global challenges in prover: {:?}", challenges);

            let public_input_span = entered_span!("public_input", profiling_1 = true);
            let public_input = self.device.transport_mles(&pi);
            exit_span!(public_input_span);

            let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);

            let mut points = Vec::new();
            let mut evaluations = Vec::new();
            // CPU path: eagerly extract witness MLEs from pcs_data
            #[cfg(not(feature = "gpu"))]
            let mut witness_iter = self
                .device
                .extract_witness_mles(&mut witness_mles, &witness_data);

            // Phase 1: Build all ChipTasks (sequential extraction of witnesses/fixed)
            let build_tasks_span = entered_span!("build_chip_tasks", profiling_1 = true);
            let mut tasks: Vec<ChipTask<'_, PB>> = Vec::new();
            let mut task_id = 0usize;
            let mut circuit_enum_idx = 0usize;

            for ((circuit_name, num_instances), structural_rmm) in name_and_instances
                .into_iter()
                .zip_eq(structural_rmms.into_iter())
            {
                #[allow(unused_variables)]
                let this_idx = circuit_enum_idx;
                circuit_enum_idx += 1;

                let circuit_idx = self
                    .pk
                    .circuit_name_to_index
                    .get(&circuit_name)
                    .cloned()
                    .expect("invalid circuit {} not exist in ceno zkvm");
                let pk = self.pk.circuit_pks.get(&circuit_name).unwrap();
                let cs = pk.get_cs();
                if !shard_ctx.is_first_shard() && cs.with_omc_init_only() {
                    assert!(num_instances.is_empty());
                    // skip drain respective fixed because we use different set of fixed commitment
                    continue;
                }
                if num_instances.is_empty() {
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
                    (vec![], vec![], Some(structural_rmm))
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
                let input_temp: ProofInput<'_, PB> = ProofInput {
                    witness: witness_mle,
                    fixed,
                    structural_witness,
                    public_input: public_input.clone(),
                    pub_io_evals: pi_evals.iter().map(|p| Either::Right(*p)).collect(),
                    num_instances: num_instances.clone(),
                    has_ecc_ops: cs.has_ecc_ops(),
                };
                // SAFETY: All data in ProofInput is Arc-owned or cloned, and the underlying
                // MultilinearPoly data is 'static (from DeviceProvingKey<'static, PB>).
                // We erase the shorter inferred lifetime to satisfy 'static requirements.
                let input = unsafe {
                    std::mem::transmute::<ProofInput<'_, PB>, ProofInput<'static, PB>>(input_temp)
                };

                // Estimate memory for this task
                #[cfg(feature = "gpu")]
                let estimated_memory = {
                    // SAFETY: When feature = "gpu", PB = GpuBackend<E, PCS>
                    let gpu_input: &ProofInput<'_, gkr_iop::gpu::GpuBackend<E, PCS>> =
                        unsafe { std::mem::transmute(&input) };
                    estimate_chip_proof_memory::<E, PCS>(cs, gpu_input, &circuit_name)
                };
                #[cfg(not(feature = "gpu"))]
                let estimated_memory = 0u64; // CPU path doesn't need memory tracking

                // GPU path: look up trace index for deferred extraction
                #[cfg(feature = "gpu")]
                let witness_trace_idx = circuit_trace_indices[this_idx];
                #[cfg(not(feature = "gpu"))]
                let witness_trace_idx = None;

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
                    num_witin: cs.num_witin(),
                    structural_rmm: task_structural_rmm,
                });
                task_id += 1;
            }
            #[cfg(not(feature = "gpu"))]
            drop(witness_iter);
            exit_span!(build_tasks_span);

            // Phase 2: Execute tasks using the scheduler
            let execute_tasks_span = entered_span!("execute_chip_tasks", profiling_1 = true);
            let scheduler = ChipScheduler::new();

            // GPU path: Initialize pool booking for memory-aware scheduling
            #[cfg(feature = "gpu")]
            let pool = {
                use gkr_iop::gpu::gpu_prover::CudaHal;
                let cuda_hal = gkr_iop::gpu::get_cuda_hal().expect("Failed to get CUDA HAL");
                let p = cuda_hal.inner().mem_pool().clone();
                p.init_booking_baseline().expect("Failed to init booking baseline");
                p
            };

            // Execute chip proof tasks via unified scheduler.
            // GPU: concurrent scheduling with memory-aware backfilling.
            // CPU: sequential execution.
            // Transcript forking and sampling are handled internally by the scheduler.
            #[cfg(feature = "gpu")]
            let (results, forked_samples) = {
                // SAFETY: When feature = "gpu", PB = GpuBackend<E, PCS>, so PcsData types match.
                let gpu_witness_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as gkr_iop::hal::ProverBackend>::PcsData =
                    unsafe { std::mem::transmute(&witness_data) };

                // SAFETY: pcs_data is only read (via get_trace) during concurrent execution.
                use crate::scheme::utils::SyncRef;
                let gpu_wd = SyncRef(gpu_witness_data);

                scheduler.execute(tasks, &transcript, &pool, |task, transcript| {
                    // Append circuit_idx to per-task forked transcript (matching verifier)
                    transcript.append_field_element(&E::BaseField::from_canonical_u64(task.circuit_idx as u64));

                    // SAFETY: When feature = "gpu", PB = GpuBackend<E, PCS> and the types are compatible.
                    let gpu_input: ProofInput<'static, gkr_iop::gpu::GpuBackend<E, PCS>> =
                        unsafe { std::mem::transmute(task.input) };

                    let (proof, pi_in_evals, input_opening_point) = create_chip_proof_gpu_impl::<E, PCS>(
                        task.circuit_name.as_str(),
                        task.pk,
                        gpu_input,
                        transcript,
                        &task.challenges,
                        gpu_wd.0,
                        task.witness_trace_idx,
                        task.num_witin,
                        task.structural_rmm,
                    )?;

                    Ok(ChipTaskResult {
                        task_id: task.task_id,
                        circuit_idx: task.circuit_idx,
                        proof,
                        pi_in_evals,
                        input_opening_point,
                        has_witness_or_fixed: task.has_witness_or_fixed,
                    })
                })?
            };

            #[cfg(not(feature = "gpu"))]
            let (results, forked_samples) = scheduler.execute(
                tasks,
                &transcript,
                |task, transcript| {
                    // Append circuit_idx to per-task forked transcript (matching verifier)
                    transcript.append_field_element(
                        &E::BaseField::from_canonical_u64(task.circuit_idx as u64),
                    );

                    let (proof, pi_in_evals, input_opening_point) = self.create_chip_proof(
                        task.circuit_name.as_str(),
                        task.pk,
                        task.input,
                        transcript,
                        &task.challenges,
                    )?;

                    Ok(ChipTaskResult {
                        task_id: task.task_id,
                        circuit_idx: task.circuit_idx,
                        proof,
                        pi_in_evals,
                        input_opening_point,
                        has_witness_or_fixed: task.has_witness_or_fixed,
                    })
                },
            )?;
            exit_span!(execute_tasks_span);

            // Phase 3: Collect results (sorted by task_id to maintain order)
            let collect_results_span = entered_span!("collect_chip_results", profiling_1 = true);
            for result in results {
                tracing::trace!(
                    "generated proof for circuit {} with circuit_idx={}",
                    result.circuit_idx,
                    result.task_id
                );

                if result.has_witness_or_fixed {
                    points.push(result.input_opening_point);
                    evaluations.push(vec![
                        result.proof.wits_in_evals.clone(),
                        result.proof.fixed_in_evals.clone(),
                    ]);
                } else {
                    assert!(result.proof.wits_in_evals.is_empty());
                    assert!(result.proof.fixed_in_evals.is_empty());
                }
                chip_proofs
                    .entry(result.circuit_idx)
                    .or_insert(vec![])
                    .push(result.proof);
                for (idx, eval) in result.pi_in_evals {
                    pi_evals[idx] = eval;
                }
            }
            exit_span!(collect_results_span);
            exit_span!(main_proofs_span);

            // merge forked transcript samples into main transcript
            for sample in forked_samples {
                transcript.append_field_element_ext(&sample);
            }

            // batch opening pcs
            // generate static info from prover key for expected num variable
            let pcs_opening = entered_span!("pcs_opening", profiling_1 = true);
            let mpcs_opening_proof = info_span!("[ceno] pcs_opening").in_scope(|| {
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

            let vm_proof = ZKVMProof::new(
                raw_pi,
                pi_evals,
                chip_proofs,
                witin_commit,
                mpcs_opening_proof,
            );

            Ok(vm_proof)
        })
    }

    /// create proof for opcode and table circuits
    ///
    /// for each read/write/logup expression, we pack all records of that type
    /// into a single tower tree, and then feed these trees into tower prover.
    #[tracing::instrument(skip_all, name = "create_chip_proof", fields(table_name=name, profiling_2
    ), level = "trace")]
    pub fn create_chip_proof<'a>(
        &self,
        name: &str,
        circuit_pk: &ProvingKey<E>,
        input: ProofInput<'a, PB>,
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<CreateTableProof<E>, ZKVMError> {
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
            .in_scope(|| build_main_witness::<E, PCS, PB, PD>(cs, &input, challenges));

        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        // prove the product and logup sum relation between layers in tower
        // (internally calls build_tower_witness)
        let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) =
            info_span!("[ceno] prove_tower_relation").in_scope(|| {
                self.device
                    .prove_tower_relation(cs, &input, &records, challenges, transcript)
            });
        exit_span!(span);

        assert_eq!(
            rt_tower.len(), // num var length should equal to max_num_instance
            num_var_with_rotation,
        );

        // TODO: batch reduction into main sumcheck
        // x[rt,0] = \sum_b eq([rt,0], b) * x[b]
        // x[rt,1] = \sum_b eq([rt,1], b) * x[b]
        // x[1,rt] = \sum_b eq([1,rt], b) * x[b]
        // y[rt,0] = \sum_b eq([rt,0], b) * y[b]
        // y[rt,1] = \sum_b eq([rt,1], b) * y[b]
        // y[1,rt] = \sum_b eq([1,rt], b) * y[b]
        // s[0,rt] = \sum_b eq([0,rt], b) * s[b]

        // 1. prove the main constraints among witness polynomials
        // 2. prove the relation between last layer in the tower and read/write/logup records
        let span = entered_span!("prove_main_constraints", profiling_2 = true);
        let (input_opening_point, evals, main_sumcheck_proofs, gkr_iop_proof) =
            info_span!("[ceno] prove_main_constraints").in_scope(|| {
                self.device
                    .prove_main_constraints(rt_tower, &input, cs, challenges, transcript)
            })?;
        let MainSumcheckEvals {
            wits_in_evals,
            fixed_in_evals,
        } = evals;
        exit_span!(span);

        // evaluate pi if there is instance query
        let mut pi_in_evals: HashMap<usize, E> = HashMap::new();
        if !cs.instance_openings().is_empty() {
            let span = entered_span!("pi::evals", profiling_2 = true);
            for &Instance(idx) in cs.instance_openings() {
                let poly = &input.public_input[idx];
                pi_in_evals.insert(
                    idx,
                    poly.eval(input_opening_point[..poly.num_vars()].to_vec()),
                );
            }
            exit_span!(span);
        }

        Ok((
            ZKVMChipProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                main_sumcheck_proofs,
                gkr_iop_proof,
                tower_proof,
                ecc_proof,
                fixed_in_evals,
                wits_in_evals,
                num_instances: input.num_instances,
            },
            pi_in_evals,
            input_opening_point,
        ))
    }
}

/// GPU-specific standalone function for create_chip_proof that doesn't require &self.
/// Uses the _impl functions directly, avoiding Send/Sync requirements on ZKVMProver.
/// This enables parallel execution in the scheduler without capturing &self.
#[cfg(feature = "gpu")]
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
    num_witin: usize,
    structural_rmm: Option<witness::RowMajorMatrix<<E as ExtensionField>::BaseField>>,
) -> Result<CreateTableProof<E>, ZKVMError>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    use crate::scheme::gpu::{
        extract_witness_mles_for_trace, prove_ec_sum_quark_impl, prove_main_constraints_impl,
        prove_tower_relation_impl, transport_structural_witness_to_gpu,
    };
    use gkr_iop::gpu::{GpuBackend, get_cuda_hal};

    let cuda_hal = get_cuda_hal().expect("Failed to get CUDA HAL");
    let _stream = cuda_hal.inner.get_pool_stream().expect("should acquire stream");
    let _thread_stream_guard = gkr_iop::gpu::bind_thread_stream(_stream.clone());

    // Deferred witness extraction: extract from committed pcs_data just-in-time
    if let Some(trace_idx) = witness_trace_idx {
        input.witness = info_span!("[ceno] extract_witness_mles").in_scope(|| {
            extract_witness_mles_for_trace::<E, PCS>(pcs_data, trace_idx, num_witin)
        });
    }

    // Deferred structural witness transport: CPU -> GPU just-in-time
    if let Some(rmm) = structural_rmm {
        input.structural_witness = info_span!("[ceno] transport_structural_witness").in_scope(|| {
            transport_structural_witness_to_gpu::<E>(rmm)
        });
    }

    let cs = circuit_pk.get_cs();
    let log2_num_instances = input.log2_num_instances();
    let num_var_with_rotation = log2_num_instances + cs.rotation_vars().unwrap_or(0);

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
    let records = info_span!("[ceno] build_main_witness").in_scope(|| {
        build_main_witness::<E, PCS, GpuBackend<E, PCS>, gkr_iop::gpu::GpuProver<GpuBackend<E, PCS>>>(
            cs, &input, challenges
        )
    });

    let span = entered_span!("prove_tower_relation", profiling_2 = true);
    // prove the product and logup sum relation between layers in tower using _impl function
    let (rt_tower, tower_proof, lk_out_evals, w_out_evals, r_out_evals) =
        info_span!("[ceno] prove_tower_relation").in_scope(|| {
            prove_tower_relation_impl::<E, PCS>(cs, &input, &records, challenges, transcript, &cuda_hal)
        });
    exit_span!(span);

    assert_eq!(
        rt_tower.len(),
        num_var_with_rotation,
    );

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

    // evaluate pi if there is instance query
    let mut pi_in_evals: HashMap<usize, E> = HashMap::new();
    if !cs.instance_openings().is_empty() {
        let span = entered_span!("pi::evals", profiling_2 = true);
        for &Instance(idx) in cs.instance_openings() {
            let poly = &input.public_input[idx];
            pi_in_evals.insert(
                idx,
                poly.eval(input_opening_point[..poly.num_vars()].to_vec()),
            );
        }
        exit_span!(span);
    }

    Ok((
        ZKVMChipProof {
            r_out_evals,
            w_out_evals,
            lk_out_evals,
            main_sumcheck_proofs,
            gkr_iop_proof,
            tower_proof,
            ecc_proof,
            fixed_in_evals,
            wits_in_evals,
            num_instances: input.num_instances,
        },
        pi_in_evals,
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
