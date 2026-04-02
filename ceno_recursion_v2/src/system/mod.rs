pub mod frame;
mod preflight;
mod types;

pub use crate::proof_shape::ProofShapeModule;
pub use preflight::{
    BatchConstraintPreflight, ChipTranscriptRange, ForkTranscriptLog, MainPreflight, Preflight,
    ProofShapePreflight, TowerChipTranscriptRange, TowerPreflight, TraceVData,
};
pub use recursion_circuit::system::{
    AirModule, BusIndexManager, GlobalTraceGenCtx, TraceGenModule, VerifierConfig,
    VerifierExternalData,
};
mod bus_inventory;
pub mod utils;

pub use bus_inventory::BusInventory;
pub use types::{
    RecursionField, RecursionPcs, RecursionProof, RecursionVk, convert_proof_from_zkvm,
    convert_vk_from_zkvm,
};

use std::{iter, mem, sync::Arc};

use crate::{
    batch_constraint::{self, BatchConstraintModule},
    main::MainModule,
    tower::TowerModule,
    transcript::TranscriptModule,
};
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkEngine, StarkProtocolConfig, TranscriptHistory,
    interaction::BusIndex,
    p3_maybe_rayon::prelude::*,
    prover::{AirProvingContext, CommittedTraceData, ProverBackend},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use recursion_circuit::primitives::{
    exp_bits_len::{ExpBitsLenAir, ExpBitsLenTraceGenerator},
    pow::{PowerCheckerAir, PowerCheckerCpuTraceGenerator},
};
use tracing::Span;

pub const POW_CHECKER_HEIGHT: usize = 32;

/// Local override of the upstream CPU tracegen context so modules accept ZKVM proofs.
pub struct GlobalCtxCpu;

impl GlobalTraceGenCtx for GlobalCtxCpu {
    type ChildVerifyingKey = RecursionVk;
    type MultiProof = [RecursionProof];
    type PreflightRecords = [Preflight];
}

/// Local fork of AggregationSubCircuit so ceno modules depend on local BusInventory.
pub trait AggregationSubCircuit {
    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>>;

    fn bus_inventory(&self) -> &BusInventory;

    fn next_bus_idx(&self) -> BusIndex;

    fn max_num_proofs(&self) -> usize;
}

pub trait VerifierTraceGen<PB: ProverBackend, SC: StarkProtocolConfig<F = F>> {
    fn new(child_vk: Arc<RecursionVk>, config: VerifierConfig) -> Self;

    fn commit_child_vk<E: StarkEngine<SC = SC, PB = PB>>(
        &self,
        engine: &E,
        child_vk: &RecursionVk,
    ) -> CommittedTraceData<PB>;

    #[allow(clippy::ptr_arg)]
    fn generate_proving_ctxs<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    >(
        &self,
        child_vk: &RecursionVk,
        child_vk_pcs_data: CommittedTraceData<PB>,
        proofs: &[RecursionProof],
        external_data: &mut VerifierExternalData<'_>,
        initial_transcripts: Vec<TS>,
    ) -> Option<Vec<AirProvingContext<PB>>>;

    fn generate_proving_ctxs_base<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>
            + Clone,
    >(
        &self,
        child_vk: &RecursionVk,
        child_vk_pcs_data: CommittedTraceData<PB>,
        proofs: &[RecursionProof],
        initial_transcript: TS,
    ) -> Vec<AirProvingContext<PB>> {
        let poseidon2_compress_inputs = vec![];
        let poseidon2_permute_inputs = vec![];
        let range_check_inputs = vec![];

        let mut external_data = VerifierExternalData {
            poseidon2_compress_inputs: &poseidon2_compress_inputs,
            poseidon2_permute_inputs: &poseidon2_permute_inputs,
            range_check_inputs: &range_check_inputs,
            required_heights: None,
            final_transcript_state: None,
        };

        self.generate_proving_ctxs::<TS>(
            child_vk,
            child_vk_pcs_data,
            proofs,
            &mut external_data,
            vec![initial_transcript; proofs.len()],
        )
        .unwrap()
    }
}

/// The recursive verifier sub-circuit consists of multiple chips, grouped into **modules**.
///
/// This struct is stateful.
pub struct VerifierSubCircuit<const MAX_NUM_PROOFS: usize> {
    pub(crate) bus_inventory: BusInventory,
    pub(crate) bus_idx_manager: BusIndexManager,
    pub(crate) transcript: TranscriptModule,
    pub(crate) proof_shape: ProofShapeModule,
    pub(crate) main_module: MainModule,
    pub(crate) gkr: TowerModule,
    #[allow(dead_code)]
    pub(crate) batch_constraint: BatchConstraintModule,
}

#[derive(Copy, Clone)]
enum TraceModuleRef<'a> {
    Transcript(&'a TranscriptModule),
    ProofShape(&'a ProofShapeModule),
    Main(&'a MainModule),
    Tower(&'a TowerModule),
    #[allow(dead_code)]
    BatchConstraint(&'a BatchConstraintModule),
}

impl<'a> TraceModuleRef<'a> {
    fn name(self) -> &'static str {
        match self {
            TraceModuleRef::Transcript(_) => "Transcript",
            TraceModuleRef::ProofShape(_) => "ProofShape",
            TraceModuleRef::Main(_) => "Main",
            TraceModuleRef::Tower(_) => "Tower",
            TraceModuleRef::BatchConstraint(_) => "BatchConstraint",
        }
    }

    #[tracing::instrument(name = "wrapper.run_preflight", level = "trace", skip_all)]
    fn run_preflight<TS>(
        self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        sponge: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        match self {
            TraceModuleRef::Main(module) => {
                module.run_preflight(child_vk, proof, preflight, sponge)
            }
            TraceModuleRef::Tower(module) => {
                module.run_preflight(child_vk, proof, preflight, sponge)
            }
            TraceModuleRef::BatchConstraint(module) => {
                module.run_preflight(child_vk, proof, preflight, sponge)
            }
            TraceModuleRef::Transcript(_) | TraceModuleRef::ProofShape(_) => {
                panic!(
                    "{} module does not participate in per-module preflight",
                    self.name()
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(name = "wrapper.generate_proving_ctxs", level = "trace", skip_all)]
    fn generate_cpu_ctxs<SC: StarkProtocolConfig<F = F>>(
        self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        pow_checker_gen: &Arc<PowerCheckerCpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
        exp_bits_len_gen: &ExpBitsLenTraceGenerator,
        external_data: &VerifierExternalData<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        match self {
            TraceModuleRef::Transcript(module) => module.generate_proving_ctxs(
                child_vk,
                proofs,
                preflights,
                &(
                    external_data.poseidon2_permute_inputs.as_slice(),
                    external_data.poseidon2_compress_inputs.as_slice(),
                ),
                required_heights,
            ),
            TraceModuleRef::ProofShape(module) => module.generate_proving_ctxs(
                child_vk,
                proofs,
                preflights,
                &(
                    pow_checker_gen.clone(),
                    external_data.range_check_inputs.as_slice(),
                ),
                required_heights,
            ),
            TraceModuleRef::Main(module) => {
                module.generate_proving_ctxs(child_vk, proofs, preflights, &(), required_heights)
            }
            TraceModuleRef::Tower(module) => module.generate_proving_ctxs(
                child_vk,
                proofs,
                preflights,
                exp_bits_len_gen,
                required_heights,
            ),
            TraceModuleRef::BatchConstraint(module) => {
                module.generate_proving_ctxs(child_vk, proofs, preflights, &(), required_heights)
            }
        }
    }
}

impl<const MAX_NUM_PROOFS: usize> VerifierSubCircuit<MAX_NUM_PROOFS> {
    pub fn new(child_vk: Arc<RecursionVk>) -> Self {
        Self::new_with_options(child_vk, VerifierConfig::default())
    }

    pub fn new_with_options(child_vk: Arc<RecursionVk>, config: VerifierConfig) -> Self {
        // let child_mvk = convert_vk_from_zkvm(child_vk.as_ref());
        // let proof_shape_constraint = LinearConstraint {
        //     coefficients: child_mvk
        //         .inner
        //         .per_air
        //         .iter()
        //         .map(|avk| avk.num_interactions() as u32)
        //         .collect(),
        //     threshold: child_mvk.inner.params.logup.max_interaction_count,
        // };
        // for (i, constraint) in child_mvk.inner.trace_height_constraints.iter().enumerate() {
        //     assert!(
        //         constraint.is_implied_by(&proof_shape_constraint),
        //         "child_vk trace_height_constraint[{i}] is not implied by ProofShapeAir's check. \
        //          The recursion circuit cannot enforce this constraint. \
        //          Constraint: coefficients={:?}, threshold={}",
        //         constraint.coefficients,
        //         constraint.threshold,
        //     );
        // }

        let mut bus_idx_manager = BusIndexManager::new();
        let bus_inventory = BusInventory::new(&mut bus_idx_manager);
        let transcript =
            TranscriptModule::new(bus_inventory.clone(), config.final_state_bus_enabled);
        let proof_shape = ProofShapeModule::new(
            child_vk.as_ref(),
            &mut bus_idx_manager,
            bus_inventory.clone(),
            config.continuations_enabled,
        );
        let main_module = MainModule::new(&mut bus_idx_manager, bus_inventory.clone());
        let gkr = TowerModule::new(
            child_vk.as_ref(),
            &mut bus_idx_manager,
            bus_inventory.clone(),
        );
        let batch_constraint =
            BatchConstraintModule::new(&mut bus_idx_manager, bus_inventory.clone(), MAX_NUM_PROOFS);

        VerifierSubCircuit {
            bus_inventory,
            bus_idx_manager,
            transcript,
            proof_shape,
            main_module,
            gkr,
            batch_constraint,
        }
    }

    /// Runs preflight for a single proof, with proper transcript forking.
    ///
    /// This mirrors the native verifier's `verify_proof_validity` fork protocol:
    /// 1. Trunk: proof-shape (per-AIR shape + α/β)
    /// 2. Fork: clone sponge per chip, observe fork index, run Tower + Main
    /// 3. Merge: each fork samples 1 ext element → observe into trunk
    #[tracing::instrument(name = "execute_preflight", skip_all)]
    fn run_preflight<TS>(
        &self,
        mut sponge: TS,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
    ) -> Preflight
    where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let mut preflight = Preflight::default();

        // Phase 1: Trunk operations.
        // Proof-shape metadata and alpha/beta sampling after pre-verifier transcript observes.
        self.proof_shape
            .run_preflight(child_vk, proof, &mut preflight, &mut sponge);

        // Phase 2: Fork — clone sponge for each chip proof instance.
        let chip_proof_list: Vec<(
            usize,
            usize,
            &ceno_zkvm::scheme::ZKVMChipProof<RecursionField>,
        )> = proof
            .chip_proofs
            .iter()
            .flat_map(|(&chip_idx, instances)| {
                instances
                    .iter()
                    .enumerate()
                    .map(move |(instance_idx, chip_proof)| (chip_idx, instance_idx, chip_proof))
            })
            .collect();

        let num_forks = chip_proof_list.len();
        let fork_offset = sponge.len(); // tidx of the fork point in the trunk

        let mut fork_sponges: Vec<TS> = (0..num_forks)
            .map(|i| {
                let mut forked = sponge.clone();
                forked.observe(F::from_u64(i as u64));
                forked
            })
            .collect();

        // Phase 3: Run Tower + Main on each fork.
        // Each fork sponge processes independently. We record fork-local tidx
        // directly — global offsets are computed on the fly at trace gen time.

        for (fork_idx, &(chip_idx, instance_idx, chip_proof)) in chip_proof_list.iter().enumerate()
        {
            let fs = &mut fork_sponges[fork_idx];
            let fork_start_len = fs.len();
            // Observe circuit_idx into the fork transcript.
            // Mirrors v1 verifier: transcript.append_field_element(circuit_idx)
            fs.observe(F::from_u64(chip_idx as u64));

            // Fork-local tidx: position within the fork's extracted log.
            let tower_local = fs.len() - fork_start_len;
            let _ = crate::tower::record_gkr_transcript(fs, chip_idx, chip_proof);

            let tower_replay = match crate::tower::circuit_vk_for_idx(child_vk, chip_idx) {
                Some(circuit_vk) => {
                    match crate::tower::replay_tower_proof(chip_proof, circuit_vk) {
                        Ok(replay) => replay,
                        Err(_err) => crate::tower::TowerReplayResult::default(),
                    }
                }
                None => crate::tower::TowerReplayResult::default(),
            };

            // Record tower with fork-local tidx.
            // Fork log layout: [0]=fork_id observe, [1..]=circuit_idx + tower + main.
            // tower_local is relative to fork_start_len (after fork_id), so
            // fork-log-local position = 1 (fork_id) + tower_local.
            preflight.gkr.chips.push(TowerChipTranscriptRange {
                chip_idx,
                instance_idx,
                tidx: 1 + tower_local,
                fork_idx,
                tower_replay,
            });

            // Main preflight for this chip.
            let main_local = fs.len() - fork_start_len;
            crate::main::record_main_transcript(fs, chip_idx, chip_proof);

            preflight.main.chips.push(ChipTranscriptRange {
                chip_idx,
                instance_idx,
                tidx: 1 + main_local,
                fork_idx,
            });
        }

        // Phase 4: Merge — sample 1 ext element from each fork, observe into trunk.
        for (i, fork_sponge) in fork_sponges.iter_mut().enumerate() {
            let sample: <BabyBearPoseidon2Config as StarkProtocolConfig>::EF =
                FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(fork_sponge);
            sponge.observe_ext(sample);
        }

        // The trunk log now contains pre-fork ops (0..fork_offset) and merge
        // ops (fork_offset..trunk_len). The merge phase adds D_EF samples per
        // fork (from sample_ext on each fork) and D_EF observations per fork
        // (from observe_ext on trunk).
        let trunk_log = sponge.into_log();

        preflight.proof_shape.fork_start_tidx = fork_offset;

        // Compute the sponge state at the fork point by replaying the trunk log.
        preflight.proof_shape.fork_start_state =
            crate::utils::replay_sponge_state_from_log(&trunk_log, fork_offset);

        // Store fork transcript logs. Each fork sponge log contains the
        // trunk's history (0..fork_offset) followed by fork-only operations
        // (fork_id observe + phase 3 ops + phase 4 sample_ext). Extract the
        // fork portion. Global offsets are NOT stored — they are computed on
        // the fly via Preflight::fork_global_offset().
        for (_fork_idx, fork_sponge) in fork_sponges.into_iter().enumerate() {
            let full_fork_log = fork_sponge.into_log();
            let fork_values = full_fork_log.values()[fork_offset..].to_vec();
            let fork_samples = full_fork_log.samples()[fork_offset..].to_vec();
            let fork_log = openvm_stark_backend::TranscriptLog::new(fork_values, fork_samples);

            // Compute the fork's initial sponge state by replaying the
            // full log up to fork_offset + 1 (trunk ops + fork_id observe).
            let initial_state =
                crate::utils::replay_sponge_state_from_log(&full_fork_log, fork_offset + 1);

            preflight.fork_transcripts.push(ForkTranscriptLog {
                log: fork_log,
                initial_state,
                fork_id: _fork_idx + 1, // 1-based fork IDs (0 = trunk)
            });
        }

        preflight.transcript = trunk_log;
        preflight
    }

    #[allow(clippy::type_complexity)]
    fn split_required_heights<'a>(
        &self,
        required_heights: Option<&'a [usize]>,
    ) -> (Vec<Option<&'a [usize]>>, Option<usize>, Option<usize>) {
        let t_n = self.transcript.num_airs();
        let ps_n = self.proof_shape.num_airs();
        let gkr_n = self.gkr.num_airs();
        let main_n = self.main_module.num_airs();
        let module_air_counts = [t_n, ps_n, gkr_n, main_n];

        let Some(heights) = required_heights else {
            return (vec![None; module_air_counts.len()], None, None);
        };

        let total_module_airs: usize = module_air_counts.iter().sum();
        let total = total_module_airs + 2;
        assert_eq!(heights.len(), total);

        let mut offset = 0usize;
        let mut per_module = Vec::with_capacity(module_air_counts.len());
        for n in module_air_counts {
            per_module.push(Some(&heights[offset..offset + n]));
            offset += n;
        }
        debug_assert_eq!(heights.len() - offset, 2);

        (per_module, Some(heights[offset]), Some(heights[offset + 1]))
    }
}

impl<SC: StarkProtocolConfig<F = F>, const MAX_NUM_PROOFS: usize>
    VerifierTraceGen<CpuBackend<SC>, SC> for VerifierSubCircuit<MAX_NUM_PROOFS>
{
    fn new(child_vk: Arc<RecursionVk>, config: VerifierConfig) -> Self {
        Self::new_with_options(child_vk, config)
    }

    fn commit_child_vk<E: StarkEngine<SC = SC, PB = CpuBackend<SC>>>(
        &self,
        engine: &E,
        child_vk: &RecursionVk,
    ) -> CommittedTraceData<CpuBackend<SC>> {
        batch_constraint::commit_child_vk(engine, child_vk)
    }

    #[tracing::instrument(name = "subcircuit_generate_proving_ctxs", skip_all)]
    fn generate_proving_ctxs<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    >(
        &self,
        child_vk: &RecursionVk,
        _child_vk_pcs_data: CommittedTraceData<CpuBackend<SC>>,
        proofs: &[RecursionProof],
        external_data: &mut VerifierExternalData<'_>,
        initial_transcripts: Vec<TS>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        debug_assert!(proofs.len() <= MAX_NUM_PROOFS);
        if initial_transcripts.len() != proofs.len() {
            return None;
        }

        let span = Span::current();
        let child_vk_recursion = child_vk;
        let this = self;
        let preflights = std::thread::scope(|s| {
            let handles: Vec<_> = proofs
                .iter()
                .zip(initial_transcripts)
                .map(|(zk_proof, sponge)| {
                    let child_vk = child_vk_recursion;
                    let span = span.clone();
                    s.spawn(move || {
                        let _guard = span.enter();
                        this.run_preflight(sponge, child_vk, zk_proof)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });

        if let Some(final_transcript_state) = &mut external_data.final_transcript_state {
            final_transcript_state.fill(F::ZERO);
        }

        let power_checker_gen =
            Arc::new(PowerCheckerCpuTraceGenerator::<2, POW_CHECKER_HEIGHT>::default());
        let exp_bits_len_gen = ExpBitsLenTraceGenerator::default();

        let (module_required, power_checker_required, exp_bits_len_required) =
            self.split_required_heights(external_data.required_heights);

        let modules = [
            TraceModuleRef::Transcript(&self.transcript),
            TraceModuleRef::ProofShape(&self.proof_shape),
            TraceModuleRef::Tower(&self.gkr),
            TraceModuleRef::Main(&self.main_module),
            // TODO(batch-constraint): re-enable once batch tracegen/preflight alignment is fixed.
            // TraceModuleRef::BatchConstraint(&self.batch_constraint),
        ];

        let span = Span::current();
        let ctxs_by_module = modules
            .into_par_iter()
            .zip(module_required)
            .map(|(module, required_heights)| {
                let _guard = span.enter();
                module.generate_cpu_ctxs(
                    child_vk,
                    proofs,
                    &preflights,
                    &power_checker_gen,
                    &exp_bits_len_gen,
                    external_data,
                    required_heights,
                )
            })
            .collect::<Vec<_>>();

        for (module, module_ctxs) in modules.into_iter().zip(ctxs_by_module.iter()) {
            if module_ctxs.is_none() {}
        }

        let ctxs_by_module: Vec<Vec<AirProvingContext<CpuBackend<SC>>>> =
            ctxs_by_module.into_iter().collect::<Option<Vec<_>>>()?;
        let mut ctx_per_trace = ctxs_by_module.into_iter().flatten().collect::<Vec<_>>();
        if power_checker_required.is_some_and(|h| h != POW_CHECKER_HEIGHT) {
            return None;
        }
        let power_height = power_checker_required.unwrap_or(POW_CHECKER_HEIGHT);
        let power_trace = power_checker_gen.generate_trace_row_major();
        if power_trace.height() != power_height {
            return None;
        }
        ctx_per_trace.push(AirProvingContext::simple_no_pis(power_trace));

        let exp_bits_height = exp_bits_len_required;
        let exp_bits_trace = exp_bits_len_gen.generate_trace_row_major(exp_bits_height)?;
        ctx_per_trace.push(AirProvingContext::simple_no_pis(exp_bits_trace));
        Some(ctx_per_trace)
    }
}

fn peek_bus_idx(manager: &BusIndexManager) -> BusIndex {
    // SAFETY: BusIndexManager is currently a transparent wrapper around a single BusIndex field.
    unsafe { mem::transmute::<BusIndexManager, BusIndex>(*manager) }
}

impl<const MAX_NUM_PROOFS: usize> AggregationSubCircuit for VerifierSubCircuit<MAX_NUM_PROOFS> {
    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let exp_bits_len_air = ExpBitsLenAir::new(
            self.bus_inventory.exp_bits_len_bus,
            self.bus_inventory.right_shift_bus,
        );
        let power_checker_air = PowerCheckerAir::<2, POW_CHECKER_HEIGHT> {
            pow_bus: self.bus_inventory.power_checker_bus,
            range_bus: self.bus_inventory.range_checker_bus,
        };

        iter::empty()
            .chain(self.transcript.airs())
            .chain(self.proof_shape.airs())
            .chain(self.gkr.airs())
            .chain(self.main_module.airs())
            // TODO(batch-constraint): re-chain batch AIRs after BatchConstraintModule is stable.
            // .chain(self.batch_constraint.airs())
            .chain([
                Arc::new(power_checker_air) as AirRef<_>,
                Arc::new(exp_bits_len_air) as AirRef<_>,
            ])
            .collect()
    }

    fn bus_inventory(&self) -> &BusInventory {
        &self.bus_inventory
    }

    fn next_bus_idx(&self) -> BusIndex {
        peek_bus_idx(&self.bus_idx_manager)
    }

    fn max_num_proofs(&self) -> usize {
        MAX_NUM_PROOFS
    }
}
