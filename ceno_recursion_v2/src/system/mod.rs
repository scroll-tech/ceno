pub mod frame;
mod preflight;
mod types;

pub use crate::proof_shape::ProofShapeModule;
pub use preflight::{
    BatchConstraintPreflight, ChipTranscriptRange, MainPreflight, Preflight, ProofShapePreflight,
    TowerChipTranscriptRange, TowerPreflight, TraceVData,
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

use self::utils::test_system_params_zero_pow;
use crate::{batch_constraint, main::MainModule, tower::TowerModule, transcript::TranscriptModule};
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
        initial_transcript: TS,
    ) -> Option<Vec<AirProvingContext<PB>>>;

    fn generate_proving_ctxs_base<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
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
            initial_transcript,
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
}

#[derive(Copy, Clone)]
enum TraceModuleRef<'a> {
    Transcript(&'a TranscriptModule),
    ProofShape(&'a ProofShapeModule),
    Main(&'a MainModule),
    Tower(&'a TowerModule),
}

impl<'a> TraceModuleRef<'a> {
    fn name(self) -> &'static str {
        match self {
            TraceModuleRef::Transcript(_) => "Transcript",
            TraceModuleRef::ProofShape(_) => "ProofShape",
            TraceModuleRef::Main(_) => "Main",
            TraceModuleRef::Tower(_) => "Tower",
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
            TraceModuleRef::ProofShape(module) => {
                module.run_preflight(child_vk, proof, preflight, sponge)
            }
            TraceModuleRef::Main(module) => {
                module.run_preflight(child_vk, proof, preflight, sponge)
            }
            TraceModuleRef::Tower(module) => {
                module.run_preflight(child_vk, proof, preflight, sponge)
            }
            TraceModuleRef::Transcript(_) => {
                panic!("Transcript module does not participate in preflight")
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
        let system_params = test_system_params_zero_pow(2, 8, 3);

        let transcript = TranscriptModule::new(
            bus_inventory.clone(),
            system_params,
            config.final_state_bus_enabled,
        );
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

        VerifierSubCircuit {
            bus_inventory,
            bus_idx_manager,
            transcript,
            proof_shape,
            main_module,
            gkr,
        }
    }

    /// Runs preflight for a single proof.
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
        let modules = [
            TraceModuleRef::ProofShape(&self.proof_shape),
            TraceModuleRef::Main(&self.main_module),
            TraceModuleRef::Tower(&self.gkr),
        ];
        for module in modules {
            module.run_preflight(child_vk, proof, &mut preflight, &mut sponge);
        }
        preflight.transcript = sponge.into_log();
        preflight
    }

    #[allow(clippy::type_complexity)]
    fn split_required_heights<'a>(
        &self,
        required_heights: Option<&'a [usize]>,
    ) -> (Vec<Option<&'a [usize]>>, Option<usize>, Option<usize>) {
        let t_n = self.transcript.num_airs();
        let ps_n = self.proof_shape.num_airs();
        let main_n = self.main_module.num_airs();
        let gkr_n = self.gkr.num_airs();
        let module_air_counts = [t_n, ps_n, main_n, gkr_n];

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
        initial_transcript: TS,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        debug_assert!(proofs.len() <= MAX_NUM_PROOFS);

        let span = Span::current();
        let child_vk_recursion = child_vk;
        let this = self;
        let preflights = std::thread::scope(|s| {
            let handles: Vec<_> = proofs
                .iter()
                .map(|zk_proof| {
                    let child_vk = child_vk_recursion;
                    let sponge = initial_transcript.clone();
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
            TraceModuleRef::Main(&self.main_module),
            TraceModuleRef::Tower(&self.gkr),
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
            if module_ctxs.is_none() {
                eprintln!(
                    "subcircuit_generate_proving_ctxs: module {} returned None",
                    module.name()
                );
            }
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
    unsafe { mem::transmute::<BusIndexManager, BusIndex>(manager.clone()) }
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
            .chain(self.main_module.airs())
            .chain(self.gkr.airs())
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
