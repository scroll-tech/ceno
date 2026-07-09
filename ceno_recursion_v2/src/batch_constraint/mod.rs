use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::F;

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

#[cfg(feature = "cuda")]
mod cuda;

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
        5
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
        }
    }
}

#[cfg(feature = "cuda")]
mod cuda_tracegen {
    use openvm_cuda_backend::GpuBackend;

    use super::*;
    use crate::{
        cuda::{GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, vk::VerifyingKeyGpu},
        tracegen::{ModuleChip, cuda::generate_gpu_proving_ctx},
    };

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for BatchConstraintModule {
        type ModuleSpecificCtx<'a> = ();

        #[tracing::instrument(skip_all)]
        fn generate_proving_ctxs(
            &self,
            child_vk: &VerifyingKeyGpu,
            proofs: &[ProofGpu],
            preflights: &[PreflightGpu],
            _ctx: &Self::ModuleSpecificCtx<'_>,
            required_heights: Option<&[usize]>,
        ) -> Option<Vec<AirProvingContext<GpuBackend>>> {
            let proofs_cpu = proofs
                .iter()
                .map(|proof| proof.cpu.clone())
                .collect::<Vec<_>>();
            let preflights_cpu = preflights
                .iter()
                .map(|preflight| preflight.cpu.clone())
                .collect::<Vec<_>>();
            let mut records =
                MainModule::collect_records(&child_vk.cpu, &proofs_cpu, &preflights_cpu).ok()?;
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
            ];
            chips
                .iter()
                .enumerate()
                .map(|(idx, chip)| {
                    let required_height =
                        required_heights.and_then(|heights| heights.get(idx).copied());
                    match chip {
                        BatchConstraintModuleChip::EvalAbsorb => {
                            crate::batch_constraint::cuda::MainEvalAbsorbGpuTraceGenerator
                                .generate_proving_ctx(
                                    &ctx.records.eval_records.as_slice(),
                                    required_height,
                                )
                        }
                        _ => generate_gpu_proving_ctx(chip, &ctx, required_height),
                    }
                })
                .collect()
        }
    }
}
