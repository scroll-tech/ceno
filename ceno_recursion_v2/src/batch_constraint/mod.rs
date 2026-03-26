use std::sync::Arc;

use ceno_zkvm::scheme::ZKVMChipProof;
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkEngine, StarkProtocolConfig, TranscriptHistory,
    prover::{CommittedTraceData, TraceCommitter},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    batch_constraint::{
        bus::{
            BatchConstraintConductorBus, ConstraintsFoldingBus, EqNOuterBus, ExpressionClaimBus,
            InteractionsFoldingBus, SymbolicExpressionBus,
        },
        expr_eval::{
            ConstraintsFoldingAir, ConstraintsFoldingCols,
            symbolic_expression::{
                CachedSymbolicExpressionColumns, SingleMainSymbolicExpressionColumns,
                SymbolicExpressionAir,
            },
        },
        expression_claim::{ExpressionClaimAir, ExpressionClaimCols},
    },
    bus::{AirPresenceBus, ColumnClaimsBus, SelHypercubeBus, SelUniBus},
    system::{
        AirModule, BatchConstraintPreflight, BusIndexManager, BusInventory, GlobalCtxCpu,
        Preflight, RecursionField, RecursionProof, RecursionVk, TraceGenModule,
    },
};

pub mod expr_eval;
pub mod expression_claim;
pub mod bus {
    use p3_field::PrimeCharacteristicRing;
    pub use recursion_circuit::batch_constraint::bus::*;

    #[repr(u8)]
    #[derive(Debug, Copy, Clone)]
    pub enum BatchConstraintInnerMessageType {
        R,
        Xi,
        Mu,
    }

    impl BatchConstraintInnerMessageType {
        pub fn to_field<T: PrimeCharacteristicRing>(self) -> T {
            T::from_u8(self as u8)
        }
    }
}

pub use expr_eval::CachedTraceRecord;

pub struct BatchConstraintModule {
    transcript_bus: crate::bus::TranscriptBus,
    hyperdim_bus: crate::bus::HyperdimBus,
    air_shape_bus: crate::bus::AirShapeBus,
    air_presence_bus: AirPresenceBus,
    column_claims_bus: ColumnClaimsBus,
    public_values_bus: crate::bus::PublicValuesBus,
    sel_hypercube_bus: SelHypercubeBus,
    sel_uni_bus: SelUniBus,

    expression_claim_n_max_bus: crate::bus::ExpressionClaimNMaxBus,
    n_lift_bus: crate::bus::NLiftBus,
    main_expression_claim_bus: crate::bus::MainExpressionClaimBus,
    power_checker_bus: recursion_circuit::primitives::bus::PowerCheckerBus,

    batch_constraint_conductor_bus: BatchConstraintConductorBus,
    eq_n_outer_bus: EqNOuterBus,
    symbolic_expression_bus: SymbolicExpressionBus,
    expression_claim_bus: ExpressionClaimBus,
    interactions_folding_bus: InteractionsFoldingBus,
    constraints_folding_bus: ConstraintsFoldingBus,

    max_num_proofs: usize,
}

impl BatchConstraintModule {
    pub fn new(
        b: &mut BusIndexManager,
        bus_inventory: BusInventory,
        max_num_proofs: usize,
    ) -> Self {
        Self {
            transcript_bus: bus_inventory.transcript_bus,
            hyperdim_bus: bus_inventory.hyperdim_bus,
            air_shape_bus: bus_inventory.air_shape_bus,
            air_presence_bus: AirPresenceBus::new(b.new_bus_idx()),
            column_claims_bus: ColumnClaimsBus::new(b.new_bus_idx()),
            public_values_bus: bus_inventory.public_values_bus,
            sel_hypercube_bus: SelHypercubeBus::new(b.new_bus_idx()),
            sel_uni_bus: SelUniBus::new(b.new_bus_idx()),

            expression_claim_n_max_bus: bus_inventory.expression_claim_n_max_bus,
            n_lift_bus: bus_inventory.n_lift_bus,
            main_expression_claim_bus: bus_inventory.main_expression_claim_bus,
            power_checker_bus: bus_inventory.power_checker_bus,

            batch_constraint_conductor_bus: BatchConstraintConductorBus::new(b.new_bus_idx()),
            eq_n_outer_bus: EqNOuterBus::new(b.new_bus_idx()),
            symbolic_expression_bus: SymbolicExpressionBus::new(b.new_bus_idx()),
            expression_claim_bus: ExpressionClaimBus::new(b.new_bus_idx()),
            interactions_folding_bus: InteractionsFoldingBus::new(b.new_bus_idx()),
            constraints_folding_bus: ConstraintsFoldingBus::new(b.new_bus_idx()),
            max_num_proofs,
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub fn run_preflight<TS>(
        &self,
        _child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        // Constraint batching challenge.
        let lambda_tidx = ts.len();
        let _lambda = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);

        // Replay a lightweight subset of batch-constraint transcript observes from per-chip
        // sumcheck messages, then sample mu.
        for chip_proof in proof
            .chip_proofs
            .values()
            .flat_map(|instances| instances.iter())
        {
            observe_main_sumcheck_msgs(ts, chip_proof);
        }
        let _mu = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        let tidx_before_univariate = ts.len();

        let mut sumcheck_rnd = vec![];
        for chip_proof in proof
            .chip_proofs
            .values()
            .flat_map(|instances| instances.iter())
        {
            if let Some(layer) = chip_proof
                .gkr_iop_proof
                .as_ref()
                .and_then(|proof| proof.0.first())
            {
                for msg in &layer.main.proof.proofs {
                    for eval in msg.evaluations.iter().take(3) {
                        ts.observe_ext(*eval);
                    }
                    sumcheck_rnd.push(FiatShamirTranscript::<BabyBearPoseidon2Config>::sample(ts));
                }
            }
        }
        if sumcheck_rnd.is_empty() {
            // Keep downstream preflight consumers shape-safe when this bridge has no rounds.
            sumcheck_rnd.push(F::ZERO);
        }

        let n_max = preflight
            .proof_shape
            .sorted_trace_vdata
            .iter()
            .map(|(_, v)| v.log_height)
            .max()
            .unwrap_or(0);
        let eq_ns_frontloaded = vec![EF::ONE; n_max + 1];
        let eq_sharp_ns_frontloaded = vec![EF::ONE; n_max + 1];

        // TODO(recursion-proof-bridge): replace placeholder eq vectors with verifier-equivalent
        // frontloaded eq_n / eq_sharp_n computation derived from xi and sumcheck randomness.
        preflight.batch_constraint = BatchConstraintPreflight {
            lambda_tidx,
            tidx_before_univariate,
            sumcheck_rnd,
            eq_ns_frontloaded,
            eq_sharp_ns_frontloaded,
        };
    }

    fn placeholder_air_widths(&self) -> [usize; 3] {
        [
            CachedSymbolicExpressionColumns::<u8>::width()
                + SingleMainSymbolicExpressionColumns::<u8>::width() * self.max_num_proofs,
            ConstraintsFoldingCols::<u8>::width(),
            ExpressionClaimCols::<u8>::width(),
        ]
    }
}

impl AirModule for BatchConstraintModule {
    fn num_airs(&self) -> usize {
        3
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let symbolic_expression_air = SymbolicExpressionAir {
            expr_bus: self.symbolic_expression_bus,
            hyperdim_bus: self.hyperdim_bus,
            air_shape_bus: self.air_shape_bus,
            air_presence_bus: self.air_presence_bus,
            column_claims_bus: self.column_claims_bus,
            interactions_folding_bus: self.interactions_folding_bus,
            constraints_folding_bus: self.constraints_folding_bus,
            public_values_bus: self.public_values_bus,
            sel_hypercube_bus: self.sel_hypercube_bus,
            sel_uni_bus: self.sel_uni_bus,
            cnt_proofs: self.max_num_proofs,
        };
        let constraints_folding_air = ConstraintsFoldingAir {
            transcript_bus: self.transcript_bus,
            constraint_bus: self.constraints_folding_bus,
            expression_claim_bus: self.expression_claim_bus,
            eq_n_outer_bus: self.eq_n_outer_bus,
            n_lift_bus: self.n_lift_bus,
        };
        let expression_claim_air = ExpressionClaimAir {
            expression_claim_n_max_bus: self.expression_claim_n_max_bus,
            expr_claim_bus: self.expression_claim_bus,
            mu_bus: self.batch_constraint_conductor_bus,
            main_claim_bus: self.main_expression_claim_bus,
            eq_n_outer_bus: self.eq_n_outer_bus,
            pow_checker_bus: self.power_checker_bus,
            hyperdim_bus: self.hyperdim_bus,
        };
        vec![
            Arc::new(symbolic_expression_air) as AirRef<_>,
            Arc::new(constraints_folding_air) as AirRef<_>,
            Arc::new(expression_claim_air) as AirRef<_>,
        ]
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>>
    for BatchConstraintModule
{
    type ModuleSpecificCtx<'a> = ();

    #[tracing::instrument(skip_all)]
    fn generate_proving_ctxs(
        &self,
        _child_vk: &RecursionVk,
        _proofs: &[RecursionProof],
        _preflights: &[Preflight],
        _ctx: &Self::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<openvm_stark_backend::prover::AirProvingContext<CpuBackend<SC>>>> {
        let widths = self.placeholder_air_widths();
        let air_count = required_heights
            .map(|heights| heights.len())
            .unwrap_or(self.num_airs());

        (0..air_count)
            .map(|idx| {
                let height = required_heights
                    .and_then(|heights| heights.get(idx).copied())
                    .unwrap_or(1);
                if required_heights.is_some() && height < 2 {
                    return None;
                }
                let width = widths.get(idx).copied().unwrap_or(1);
                let rows = height.max(2);
                let cols = width.max(1);
                let matrix = RowMajorMatrix::new(vec![F::ZERO; rows * cols], cols);
                Some(openvm_stark_backend::prover::AirProvingContext::simple_no_pis(matrix))
            })
            .collect::<Option<Vec<_>>>()
    }
}

fn observe_main_sumcheck_msgs<TS>(ts: &mut TS, chip_proof: &ZKVMChipProof<RecursionField>)
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    if let Some(proofs) = &chip_proof.main_sumcheck_proofs {
        for msg in proofs {
            for eval in msg.evaluations.iter().take(3) {
                ts.observe_ext(*eval);
            }
        }
    }
}

pub fn cached_trace_record(child_vk: &RecursionVk) -> CachedTraceRecord {
    expr_eval::symbolic_expression::build_cached_trace_record(child_vk)
}

pub fn commit_child_vk<E, SC>(
    engine: &E,
    child_vk: &RecursionVk,
) -> CommittedTraceData<CpuBackend<SC>>
where
    E: StarkEngine<SC = SC, PB = CpuBackend<SC>>,
    SC: StarkProtocolConfig<F = F>,
{
    let cached_trace = expr_eval::symbolic_expression::generate_symbolic_expr_cached_trace(
        &cached_trace_record(child_vk),
    );
    let (commitment, data) = engine.device().commit(&[&cached_trace]).unwrap();
    CommittedTraceData {
        commitment,
        data: Arc::new(data),
        trace: cached_trace,
    }
}
