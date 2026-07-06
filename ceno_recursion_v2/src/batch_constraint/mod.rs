use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, BaseAirWithPublicValues, FiatShamirTranscript, PartitionedBaseAir, StarkProtocolConfig,
    TranscriptHistory, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::F;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    main::{
        MainCollectedRecords, MainModule,
        eval_absorb::{MainEvalAbsorbAir, MainEvalAbsorbTraceGenerator},
        final_claim::{MainFinalClaimAir, MainFinalClaimTraceGenerator},
        frontload::{MainFrontloadTermAir, MainFrontloadTermTraceGenerator},
        global_sumcheck::{MainGlobalSumcheckAir, MainGlobalSumcheckTraceGenerator},
        tower_point::{MainTowerPointEqAir, MainTowerPointEqTraceGenerator},
    },
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, Preflight, RecursionProof,
        RecursionVk, TraceGenModule,
    },
    tracegen::{ModuleChip, RowMajorChip},
};

pub struct BatchConstraintModule {
    transcript_bus: crate::bus::TranscriptBus,
    global_claim_bus: crate::bus::MainGlobalClaimBus,
    global_point_bus: crate::bus::MainGlobalPointBus,
    eval_bus: crate::bus::MainEvalBus,
    contribution_bus: crate::bus::MainContributionBus,
    tower_point_bus: crate::bus::TowerMainPointBus,
}

impl BatchConstraintModule {
    pub fn new(
        _b: &mut BusIndexManager,
        bus_inventory: BusInventory,
        _max_num_proofs: usize,
    ) -> Self {
        Self {
            transcript_bus: bus_inventory.transcript_bus,
            global_claim_bus: bus_inventory.main_global_claim_bus,
            global_point_bus: bus_inventory.main_global_point_bus,
            eval_bus: bus_inventory.main_eval_bus,
            contribution_bus: bus_inventory.main_contribution_bus,
            tower_point_bus: bus_inventory.tower_main_point_bus,
        }
    }

    pub fn run_preflight<TS>(
        &self,
        _child_vk: &RecursionVk,
        _proof: &RecursionProof,
        _preflight: &mut Preflight,
        _ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<
                openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config,
            > + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let _ = self;
    }
}

impl AirModule for BatchConstraintModule {
    fn num_airs(&self) -> usize {
        8
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        vec![
            Arc::new(MainGlobalSumcheckAir {
                transcript_bus: self.transcript_bus,
                global_claim_bus: self.global_claim_bus,
                global_point_bus: self.global_point_bus,
            }) as AirRef<_>,
            Arc::new(MainEvalAbsorbAir {
                transcript_bus: self.transcript_bus,
                eval_bus: self.eval_bus,
            }) as AirRef<_>,
            Arc::new(MainTowerPointEqAir {
                global_point_bus: self.global_point_bus,
                tower_point_bus: self.tower_point_bus,
            }) as AirRef<_>,
            Arc::new(MainFrontloadTermAir {
                eval_bus: self.eval_bus,
                global_point_bus: self.global_point_bus,
                contribution_bus: self.contribution_bus,
            }) as AirRef<_>,
            Arc::new(MainFinalClaimAir {
                global_claim_bus: self.global_claim_bus,
                contribution_bus: self.contribution_bus,
            }) as AirRef<_>,
            // TODO(recursion-proof-bridge): replace these deterministic placeholders
            // with the OpenVM cached/batch-constraint AIRs once PCS/cached-commit
            // replay is fully migrated.
            Arc::new(SymbolicExpressionAir) as AirRef<_>,
            Arc::new(ConstraintsFoldingAir) as AirRef<_>,
            Arc::new(ExpressionClaimAir) as AirRef<_>,
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
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        _ctx: &Self::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let mut records = MainModule::collect_records(child_vk, proofs, preflights).ok()?;
        records
            .global_sumcheck_records
            .sort_by_key(|record| record.proof_idx);
        records
            .eval_records
            .sort_by_key(|record| (record.proof_idx, record.idx, record.eval_idx));
        records
            .tower_point_eq_records
            .sort_by_key(|record| (record.proof_idx, record.idx, record.round_idx));
        records
            .frontload_term_records
            .sort_by_key(|record| (record.proof_idx, record.idx, record.row_idx));
        records
            .final_claim_records
            .sort_by_key(|record| (record.proof_idx, record.idx));

        let ctx = BatchConstraintTraceCtx { records: &records };
        let chips = [
            BatchConstraintModuleChip::GlobalSumcheck,
            BatchConstraintModuleChip::EvalAbsorb,
            BatchConstraintModuleChip::TowerPointEq,
            BatchConstraintModuleChip::FrontloadTerm,
            BatchConstraintModuleChip::FinalClaim,
            BatchConstraintModuleChip::SymbolicExpression,
            BatchConstraintModuleChip::ConstraintsFolding,
            BatchConstraintModuleChip::ExpressionClaim,
        ];
        chips
            .into_iter()
            .enumerate()
            .map(|(idx, chip)| {
                chip.generate_proving_ctx(
                    &ctx,
                    required_heights.and_then(|heights| heights.get(idx).copied()),
                )
            })
            .collect()
    }
}

struct BatchConstraintTraceCtx<'a> {
    records: &'a MainCollectedRecords,
}

enum BatchConstraintModuleChip {
    GlobalSumcheck,
    EvalAbsorb,
    TowerPointEq,
    FrontloadTerm,
    FinalClaim,
    SymbolicExpression,
    ConstraintsFolding,
    ExpressionClaim,
}

impl RowMajorChip<F> for BatchConstraintModuleChip {
    type Ctx<'a> = BatchConstraintTraceCtx<'a>;

    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
        match self {
            BatchConstraintModuleChip::GlobalSumcheck => MainGlobalSumcheckTraceGenerator
                .generate_trace(
                    &ctx.records.global_sumcheck_records.as_slice(),
                    required_height,
                ),
            BatchConstraintModuleChip::EvalAbsorb => MainEvalAbsorbTraceGenerator
                .generate_trace(&ctx.records.eval_records.as_slice(), required_height),
            BatchConstraintModuleChip::TowerPointEq => MainTowerPointEqTraceGenerator
                .generate_trace(
                    &ctx.records.tower_point_eq_records.as_slice(),
                    required_height,
                ),
            BatchConstraintModuleChip::FrontloadTerm => MainFrontloadTermTraceGenerator
                .generate_trace(
                    &ctx.records.frontload_term_records.as_slice(),
                    required_height,
                ),
            BatchConstraintModuleChip::FinalClaim => MainFinalClaimTraceGenerator
                .generate_trace(&ctx.records.final_claim_records.as_slice(), required_height),
            BatchConstraintModuleChip::SymbolicExpression
            | BatchConstraintModuleChip::ConstraintsFolding
            | BatchConstraintModuleChip::ExpressionClaim => {
                PlaceholderTraceGenerator.generate_trace(&(), required_height)
            }
        }
    }
}

pub struct SymbolicExpressionAir;
pub struct ConstraintsFoldingAir;
pub struct ExpressionClaimAir;

macro_rules! impl_placeholder_air {
    ($air:ty) => {
        impl<F: Field> BaseAir<F> for $air {
            fn width(&self) -> usize {
                1
            }
        }

        impl<F: Field> BaseAirWithPublicValues<F> for $air {}
        impl<F: Field> PartitionedBaseAir<F> for $air {}

        impl<AB: AirBuilder> Air<AB> for $air
        where
            AB::F: Field,
        {
            fn eval(&self, builder: &mut AB) {
                let main = builder.main();
                let local_row = main.row_slice(0).expect("main row exists");
                builder.assert_zero(local_row[0].clone());
            }
        }
    };
}

impl_placeholder_air!(SymbolicExpressionAir);
impl_placeholder_air!(ConstraintsFoldingAir);
impl_placeholder_air!(ExpressionClaimAir);

struct PlaceholderTraceGenerator;

impl RowMajorChip<F> for PlaceholderTraceGenerator {
    type Ctx<'a> = ();

    fn generate_trace(
        &self,
        _ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let height = required_height.unwrap_or(1);
        if height == 0 {
            return None;
        }
        Some(RowMajorMatrix::new(vec![F::ZERO; height], 1))
    }
}
