pub mod frame;
mod preflight;
mod types;

pub use crate::{batch_constraint::BatchConstraintModule, proof_shape::ProofShapeModule};
pub use preflight::{GkrPreflight, Preflight, ProofShapePreflight};
pub use recursion_circuit::system::{
    AggregationSubCircuit, AirModule, BusIndexManager, GlobalTraceGenCtx, TraceGenModule,
    VerifierConfig, VerifierExternalData,
};
mod bus_inventory;
pub use bus_inventory::BusInventory;
pub use types::{
    RecursionField, RecursionPcs, RecursionProof, RecursionVk, convert_proof_from_zkvm,
    convert_vk_from_zkvm,
};

use std::sync::Arc;

use crate::{
    batch_constraint::{
        BatchConstraintModule as LocalBatchConstraintModule, CachedTraceRecord,
        LOCAL_SYMBOLIC_EXPRESSION_AIR_IDX,
    },
    gkr::GkrModule,
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
use p3_matrix::dense::RowMajorMatrix;
use recursion_circuit::{
    primitives::{exp_bits_len::ExpBitsLenTraceGenerator, pow::PowerCheckerCpuTraceGenerator},
    transcript::TranscriptModule,
};
use tracing::Span;

pub const POW_CHECKER_HEIGHT: usize = 32;
const BATCH_CONSTRAINT_MOD_IDX: usize = 0;

/// Local override of the upstream CPU tracegen context so modules accept ZKVM proofs.
pub struct GlobalCtxCpu;

impl GlobalTraceGenCtx for GlobalCtxCpu {
    type ChildVerifyingKey = RecursionVk;
    type MultiProof = [RecursionProof];
    type PreflightRecords = [Preflight];
}

pub trait VerifierTraceGen<PB: ProverBackend, SC: StarkProtocolConfig<F = F>> {
    fn new(child_vk: Arc<RecursionVk>, config: VerifierConfig) -> Self;

    fn commit_child_vk<E: StarkEngine<SC = SC, PB = PB>>(
        &self,
        engine: &E,
        child_vk: &RecursionVk,
    ) -> CommittedTraceData<PB>;

    fn cached_trace_record(&self, child_vk: &RecursionVk) -> CachedTraceRecord;

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
    pub(crate) gkr: GkrModule,
    pub(crate) batch_constraint: LocalBatchConstraintModule,
}

#[derive(Copy, Clone)]
enum TraceModuleRef<'a> {
    Transcript(&'a TranscriptModule),
    ProofShape(&'a ProofShapeModule),
    Gkr(&'a GkrModule),
    BatchConstraint(&'a LocalBatchConstraintModule),
}

impl<'a> TraceModuleRef<'a> {
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
            TraceModuleRef::Gkr(module) => module.run_preflight(child_vk, proof, preflight, sponge),
            TraceModuleRef::BatchConstraint(module) => {
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
            TraceModuleRef::Transcript(module) => {
                let air_count = required_heights
                    .map(|heights| heights.len())
                    .unwrap_or_else(|| module.num_airs());
                Some(
                    (0..air_count)
                        .map(|idx| {
                            let height = required_heights
                                .and_then(|heights| heights.get(idx).copied())
                                .unwrap_or(1);
                            zero_air_ctx(height)
                        })
                        .collect(),
                )
            }
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
            TraceModuleRef::Gkr(module) => module.generate_proving_ctxs(
                child_vk,
                proofs,
                preflights,
                exp_bits_len_gen,
                required_heights,
            ),
            TraceModuleRef::BatchConstraint(module) => module.generate_proving_ctxs(
                child_vk,
                proofs,
                preflights,
                &pow_checker_gen,
                required_heights,
            ),
        }
    }
}

impl<const MAX_NUM_PROOFS: usize> VerifierSubCircuit<MAX_NUM_PROOFS> {
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
            TraceModuleRef::Gkr(&self.gkr),
            TraceModuleRef::BatchConstraint(&self.batch_constraint),
        ];
        for module in modules {
            module.run_preflight(child_vk, proof, &mut preflight, &mut sponge);
        }
        preflight
    }

    #[allow(clippy::type_complexity)]
    fn split_required_heights<'a>(
        &self,
        required_heights: Option<&'a [usize]>,
    ) -> (Vec<Option<&'a [usize]>>, Option<usize>, Option<usize>) {
        let bc_n = self.batch_constraint.num_airs();
        let t_n = self.transcript.num_airs();
        let ps_n = self.proof_shape.num_airs();
        let gkr_n = self.gkr.num_airs();
        let module_air_counts = [bc_n, t_n, ps_n, gkr_n];

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
    fn new(_child_vk: Arc<RecursionVk>, _config: VerifierConfig) -> Self {
        unimplemented!("VerifierSubCircuit::new placeholder")
    }

    fn commit_child_vk<E: StarkEngine<SC = SC, PB = CpuBackend<SC>>>(
        &self,
        _engine: &E,
        _child_vk: &RecursionVk,
    ) -> CommittedTraceData<CpuBackend<SC>> {
        unimplemented!("VerifierSubCircuit::commit_child_vk placeholder")
    }

    fn cached_trace_record(&self, _child_vk: &RecursionVk) -> CachedTraceRecord {
        unimplemented!("VerifierSubCircuit::cached_trace_record placeholder")
    }

    #[tracing::instrument(name = "subcircuit_generate_proving_ctxs", skip_all)]
    fn generate_proving_ctxs<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    >(
        &self,
        child_vk: &RecursionVk,
        child_vk_pcs_data: CommittedTraceData<CpuBackend<SC>>,
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

        let modules = vec![
            TraceModuleRef::BatchConstraint(&self.batch_constraint),
            TraceModuleRef::Transcript(&self.transcript),
            TraceModuleRef::ProofShape(&self.proof_shape),
            TraceModuleRef::Gkr(&self.gkr),
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

        let mut ctxs_by_module: Vec<Vec<AirProvingContext<CpuBackend<SC>>>> =
            ctxs_by_module.into_iter().collect::<Option<Vec<_>>>()?;
        if !ctxs_by_module.is_empty() && !ctxs_by_module[BATCH_CONSTRAINT_MOD_IDX].is_empty() {
            ctxs_by_module[BATCH_CONSTRAINT_MOD_IDX][LOCAL_SYMBOLIC_EXPRESSION_AIR_IDX]
                .cached_mains = vec![child_vk_pcs_data];
        }

        let mut ctx_per_trace = ctxs_by_module.into_iter().flatten().collect::<Vec<_>>();
        let power_height = power_checker_required.unwrap_or(POW_CHECKER_HEIGHT);
        ctx_per_trace.push(zero_air_ctx(power_height));
        let exp_bits_height = exp_bits_len_required.unwrap_or(1);
        ctx_per_trace.push(zero_air_ctx(exp_bits_height));
        Some(ctx_per_trace)
    }
}

impl<const MAX_NUM_PROOFS: usize> AggregationSubCircuit for VerifierSubCircuit<MAX_NUM_PROOFS> {
    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        unimplemented!("VerifierSubCircuit::airs placeholder")
    }

    fn bus_inventory(&self) -> &recursion_circuit::system::BusInventory {
        self.bus_inventory.inner()
    }

    fn next_bus_idx(&self) -> BusIndex {
        unimplemented!("VerifierSubCircuit::next_bus_idx placeholder")
    }

    fn max_num_proofs(&self) -> usize {
        MAX_NUM_PROOFS
    }
}

fn zero_air_ctx<SC: StarkProtocolConfig<F = F>>(
    height: usize,
) -> AirProvingContext<CpuBackend<SC>> {
    let rows = height.max(1);
    let matrix = RowMajorMatrix::new(vec![F::ZERO; rows], 1);
    AirProvingContext::simple_no_pis(matrix)
}
