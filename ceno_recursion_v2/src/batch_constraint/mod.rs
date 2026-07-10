use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::F;

use crate::{
    main::{
        MainBatchConstraintRecords, MainModule,
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
        let mut records =
            MainModule::collect_batch_constraint_records(child_vk, proofs, preflights).ok()?;
        let _sort_stats = ensure_batch_constraint_record_order(&mut records);

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
    records: &'a MainBatchConstraintRecords,
}

#[derive(Default)]
struct BatchConstraintSortStats {
    global_sumcheck: bool,
    eval_absorb: bool,
    tower_point_eq: bool,
    frontload_term: bool,
    final_claim: bool,
}

fn ensure_batch_constraint_record_order(
    records: &mut MainBatchConstraintRecords,
) -> BatchConstraintSortStats {
    let mut stats = BatchConstraintSortStats::default();

    if !records
        .global_sumcheck_records
        .windows(2)
        .all(|w| w[0].proof_idx <= w[1].proof_idx)
    {
        records
            .global_sumcheck_records
            .sort_unstable_by_key(|record| record.proof_idx);
        stats.global_sumcheck = true;
    }
    if !records.eval_records.windows(2).all(|w| {
        (w[0].proof_idx, w[0].idx, w[0].eval_idx) <= (w[1].proof_idx, w[1].idx, w[1].eval_idx)
    }) {
        records
            .eval_records
            .sort_unstable_by_key(|record| (record.proof_idx, record.idx, record.eval_idx));
        stats.eval_absorb = true;
    }
    if !records.tower_point_eq_records.windows(2).all(|w| {
        (w[0].proof_idx, w[0].idx, w[0].round_idx) <= (w[1].proof_idx, w[1].idx, w[1].round_idx)
    }) {
        records
            .tower_point_eq_records
            .sort_unstable_by_key(|record| (record.proof_idx, record.idx, record.round_idx));
        stats.tower_point_eq = true;
    }
    if !records.frontload_term_records.windows(2).all(|w| {
        (w[0].proof_idx, w[0].idx, w[0].row_idx) <= (w[1].proof_idx, w[1].idx, w[1].row_idx)
    }) {
        records
            .frontload_term_records
            .sort_unstable_by_key(|record| (record.proof_idx, record.idx, record.row_idx));
        stats.frontload_term = true;
    }
    if !records
        .final_claim_records
        .windows(2)
        .all(|w| (w[0].proof_idx, w[0].idx) <= (w[1].proof_idx, w[1].idx))
    {
        records
            .final_claim_records
            .sort_unstable_by_key(|record| (record.proof_idx, record.idx));
        stats.final_claim = true;
    }

    stats
}

enum BatchConstraintModuleChip {
    GlobalSumcheck,
    EvalAbsorb,
    TowerPointEq,
    FrontloadTerm,
    FinalClaim,
}

#[cfg(feature = "cuda")]
impl BatchConstraintModuleChip {
    fn stable_name(&self) -> &'static str {
        match self {
            BatchConstraintModuleChip::GlobalSumcheck => "GlobalSumcheck",
            BatchConstraintModuleChip::EvalAbsorb => "EvalAbsorb",
            BatchConstraintModuleChip::TowerPointEq => "TowerPointEq",
            BatchConstraintModuleChip::FrontloadTerm => "FrontloadTerm",
            BatchConstraintModuleChip::FinalClaim => "FinalClaim",
        }
    }

    fn record_count(&self, ctx: &BatchConstraintTraceCtx<'_>) -> usize {
        match self {
            BatchConstraintModuleChip::GlobalSumcheck => ctx.records.global_sumcheck_records.len(),
            BatchConstraintModuleChip::EvalAbsorb => ctx.records.eval_records.len(),
            BatchConstraintModuleChip::TowerPointEq => ctx.records.tower_point_eq_records.len(),
            BatchConstraintModuleChip::FrontloadTerm => ctx.records.frontload_term_records.len(),
            BatchConstraintModuleChip::FinalClaim => ctx.records.final_claim_records.len(),
        }
    }
}

impl RowMajorChip<F> for BatchConstraintModuleChip {
    type Ctx<'a> = BatchConstraintTraceCtx<'a>;

    #[cfg(feature = "cuda")]
    fn trace_name(&self) -> &'static str {
        match self {
            BatchConstraintModuleChip::GlobalSumcheck => "MainGlobalSumcheckAir",
            BatchConstraintModuleChip::EvalAbsorb => "MainEvalAbsorbAir",
            BatchConstraintModuleChip::TowerPointEq => "MainTowerPointEqAir",
            BatchConstraintModuleChip::FrontloadTerm => "MainFrontloadTermAir",
            BatchConstraintModuleChip::FinalClaim => "MainFinalClaimAir",
        }
    }

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
            let collect_start = std::time::Instant::now();
            let mut records = MainModule::collect_batch_constraint_records(
                &child_vk.cpu,
                &proofs_cpu,
                &preflights_cpu,
            )
            .ok()?;
            tracing::info!(
                elapsed_ms = collect_start.elapsed().as_secs_f64() * 1000.0,
                global_sumcheck = records.global_sumcheck_records.len(),
                eval_absorb = records.eval_records.len(),
                tower_point_eq = records.tower_point_eq_records.len(),
                frontload_term = records.frontload_term_records.len(),
                final_claim = records.final_claim_records.len(),
                "batch_constraint.collect_records"
            );
            let sort_start = std::time::Instant::now();
            let sort_stats = ensure_batch_constraint_record_order(&mut records);
            tracing::info!(
                elapsed_ms = sort_start.elapsed().as_secs_f64() * 1000.0,
                sorted_global_sumcheck = sort_stats.global_sumcheck,
                sorted_eval_absorb = sort_stats.eval_absorb,
                sorted_tower_point_eq = sort_stats.tower_point_eq,
                sorted_frontload_term = sort_stats.frontload_term,
                sorted_final_claim = sort_stats.final_claim,
                global_sumcheck = records.global_sumcheck_records.len(),
                eval_absorb = records.eval_records.len(),
                tower_point_eq = records.tower_point_eq_records.len(),
                frontload_term = records.frontload_term_records.len(),
                final_claim = records.final_claim_records.len(),
                "batch_constraint.sort_records"
            );

            let trace_ctx = BatchConstraintTraceCtx { records: &records };
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
                    let chip_start = std::time::Instant::now();
                    let proving_ctx = match chip {
                        BatchConstraintModuleChip::EvalAbsorb => {
                            crate::batch_constraint::cuda::MainEvalAbsorbGpuTraceGenerator
                                .generate_proving_ctx(
                                    &trace_ctx.records.eval_records.as_slice(),
                                    required_height,
                                )
                        }
                        BatchConstraintModuleChip::TowerPointEq => {
                            crate::batch_constraint::cuda::MainTowerPointEqGpuTraceGenerator
                                .generate_proving_ctx(
                                    &trace_ctx.records.tower_point_eq_records.as_slice(),
                                    required_height,
                                )
                        }
                        BatchConstraintModuleChip::FrontloadTerm => {
                            crate::batch_constraint::cuda::MainFrontloadTermGpuTraceGenerator
                                .generate_proving_ctx(
                                    &trace_ctx.records.frontload_term_records.as_slice(),
                                    required_height,
                                )
                        }
                        _ => generate_gpu_proving_ctx(chip, &trace_ctx, required_height),
                    };
                    tracing::info!(
                        elapsed_ms = chip_start.elapsed().as_secs_f64() * 1000.0,
                        chip = chip.stable_name(),
                        air = chip.trace_name(),
                        required_height,
                        record_count = chip.record_count(&trace_ctx),
                        path = if matches!(
                            chip,
                            BatchConstraintModuleChip::EvalAbsorb
                                | BatchConstraintModuleChip::TowerPointEq
                                | BatchConstraintModuleChip::FrontloadTerm
                        ) {
                            "gpu_direct"
                        } else {
                            "row_major_fallback"
                        },
                        has_trace = proving_ctx.is_some(),
                        "batch_constraint.chip_tracegen"
                    );
                    if proving_ctx.is_none() {
                        tracing::warn!(
                            air = chip.trace_name(),
                            required_height,
                            "batch constraint gpu tracegen returned none"
                        );
                    }
                    proving_ctx
                })
                .collect()
        }
    }
}
