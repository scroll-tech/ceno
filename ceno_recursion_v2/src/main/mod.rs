mod air;
pub(crate) mod ecc_rt;
pub(crate) mod eval_absorb;
pub(crate) mod final_claim;
pub(crate) mod frontload;
pub(crate) mod global_sumcheck;
pub(crate) mod selector;
pub(crate) mod tower_point;
mod trace;
mod transcript_bind;

use std::{iter, sync::Arc};

use eyre::{Result, bail, eyre};
use ff_ext::ExtensionField;
use itertools::{Either, Itertools, chain};
use multilinear_extensions::{
    Expression, StructuralWitIn,
    StructuralWitInType::{
        Empty, EqualDistanceDynamicSequence, EqualDistanceSequence,
        InnerRepeatingIncrementalSequence, OuterRepeatingIncrementalSequence,
        StackedConstantSequence, StackedIncrementalSequence,
    },
    mle::PointAndEval,
    util::ceil_log2,
    utils::{eval_by_expr, eval_by_expr_with_instance},
};
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, D_EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use sumcheck::util::extrapolate_uni_poly;
use witness::next_pow2_instance_padding;

use self::{
    air::MainAir,
    ecc_rt::{
        MainEccRtAir, MainEccRtChallengeAir, MainEccRtChallengeTraceGenerator,
        MainEccRtEquationAir, MainEccRtEquationTraceGenerator, MainEccRtQuarkAir,
        MainEccRtQuarkTraceGenerator, MainEccRtSumcheckAir, MainEccRtSumcheckTraceGenerator,
        MainEccRtTraceGenerator,
    },
    selector::{
        MAX_SELECTOR_POINT_VARS, MAX_SELECTOR_SPARSE_INDICES, MainSelectorEvalAir,
        MainSelectorEvalTraceGenerator, MainSelectorFormulaAir, MainSelectorFormulaTraceGenerator,
        MainSelectorPointAir, MainSelectorPointTraceGenerator,
        selector_formula_global_point_lookups, selector_formula_point_lookup_counts,
    },
    trace::{MainRecord, MainTraceGenerator},
    transcript_bind::{MainTranscriptBindAir, MainTranscriptBindTraceGenerator},
};
use crate::{
    bus::{
        AirPresenceBus, EccRtBus, ForkedTranscriptBus, MainBus, MainEccRtChallengeBus,
        MainEccRtEquationTotalsBus, MainEccRtQuarkFinalBus, MainEccRtSumcheckFinalBus, MainEvalBus,
        MainExpressionClaimBus, MainGlobalPointBus, MainSelectorPointBus, MainSelectorResultBus,
        MainSelectorShapeBus, MainSelectorSparseIndexShapeBus, TowerMainPointBus, TranscriptBus,
    },
    system::{
        AirModule, BusIndexManager, BusInventory, EccReplayClaims, GlobalCtxCpu, MainEccRtRecord,
        MainEvalRecord, MainFinalClaimRecord, MainFrontloadTermRecord, MainSelectorEvalRecord,
        MainSelectorKind, MainSelectorPointDeriveKind, MainSelectorPointRecord,
        MainSelectorPointSourceKind, MainTowerPointEqRecord, PcsOpeningClaimRecord,
        PcsOpeningCommitKind, PcsOpeningEvalRecord, PcsOpeningPointRecord, Preflight,
        RecursionField, RecursionProof, RecursionVk, RotationReplayClaims, TraceGenModule,
    },
    tower::{
        TowerInputRecord, TowerReplayResult, build_tower_input_records,
        build_tower_main_point_records, tower_transcript_len,
    },
    tracegen::{ModuleChip, RowMajorChip},
    utils::transcript_observe_label,
};

pub use air::MainCols;

#[derive(Clone)]
pub struct MainModule {
    main_bus: MainBus,
    expression_claim_bus: MainExpressionClaimBus,
    transcript_bus: TranscriptBus,
    forked_transcript_bus: ForkedTranscriptBus,
    air_presence_bus: AirPresenceBus,
    main_global_point_bus: MainGlobalPointBus,
    main_eval_bus: MainEvalBus,
    main_selector_point_bus: MainSelectorPointBus,
    main_selector_result_bus: MainSelectorResultBus,
    main_selector_shape_bus: MainSelectorShapeBus,
    main_selector_sparse_index_shape_bus: MainSelectorSparseIndexShapeBus,
    main_ecc_rt_challenge_bus: MainEccRtChallengeBus,
    main_ecc_rt_sumcheck_final_bus: MainEccRtSumcheckFinalBus,
    main_ecc_rt_equation_totals_bus: MainEccRtEquationTotalsBus,
    main_ecc_rt_quark_final_bus: MainEccRtQuarkFinalBus,
    ecc_rt_bus: EccRtBus,
    tower_main_point_bus: TowerMainPointBus,
}

impl MainModule {
    pub fn new(b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        let _ = b;
        let main_bus = bus_inventory.main_bus;
        let expression_claim_bus = bus_inventory.main_expression_claim_bus;
        let transcript_bus = bus_inventory.transcript_bus;
        let forked_transcript_bus = bus_inventory.forked_transcript_bus;
        let air_presence_bus = bus_inventory.air_presence_bus;
        let main_global_point_bus = bus_inventory.main_global_point_bus;
        let main_eval_bus = bus_inventory.main_eval_bus;
        let main_selector_point_bus = bus_inventory.main_selector_point_bus;
        let main_selector_result_bus = bus_inventory.main_selector_result_bus;
        let main_selector_shape_bus = bus_inventory.main_selector_shape_bus;
        let main_selector_sparse_index_shape_bus =
            bus_inventory.main_selector_sparse_index_shape_bus;
        let main_ecc_rt_challenge_bus = bus_inventory.main_ecc_rt_challenge_bus;
        let main_ecc_rt_sumcheck_final_bus = bus_inventory.main_ecc_rt_sumcheck_final_bus;
        let main_ecc_rt_equation_totals_bus = bus_inventory.main_ecc_rt_equation_totals_bus;
        let main_ecc_rt_quark_final_bus = bus_inventory.main_ecc_rt_quark_final_bus;
        let ecc_rt_bus = bus_inventory.ecc_rt_bus;
        let tower_main_point_bus = bus_inventory.tower_main_point_bus;
        Self {
            main_bus,
            expression_claim_bus,
            transcript_bus,
            forked_transcript_bus,
            air_presence_bus,
            main_global_point_bus,
            main_eval_bus,
            main_selector_point_bus,
            main_selector_result_bus,
            main_selector_shape_bus,
            main_selector_sparse_index_shape_bus,
            main_ecc_rt_challenge_bus,
            main_ecc_rt_sumcheck_final_bus,
            main_ecc_rt_equation_totals_bus,
            main_ecc_rt_quark_final_bus,
            ecc_rt_bus,
            tower_main_point_bus,
        }
    }

    pub(crate) fn collect_records(
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
    ) -> Result<MainCollectedRecords> {
        if proofs.len() != preflights.len() {
            bail!(
                "proof/preflight length mismatch ({} proofs vs {} preflights)",
                proofs.len(),
                preflights.len()
            );
        }

        let tower_input_records = build_tower_input_records(child_vk, proofs, preflights)
            .map_err(|err| eyre!("failed to build tower input records for main prefix: {err}"))?;
        let tower_main_point_records = build_tower_main_point_records(child_vk, proofs, preflights)
            .map_err(|err| eyre!("failed to build tower point records for main prefix: {err}"))?;

        let mut main_records = Vec::new();
        for input in &tower_input_records {
            let tidx = main_tidx_from_tower_input(input);
            main_records.push(MainRecord {
                is_present: input.n_logup != 0,
                proof_idx: input.proof_idx,
                idx: input.idx,
                tidx,
                claim: input.input_layer_claim,
            });
        }

        if main_records.is_empty() {
            main_records.push(MainRecord::default());
        }

        let mut global_sumcheck_records = Vec::new();
        let mut eval_records = Vec::new();
        let mut selector_eval_records = Vec::new();
        let mut tower_point_eq_records = Vec::new();
        let mut frontload_term_records = Vec::new();
        let mut final_claim_records = Vec::new();
        for (proof_idx, preflight) in preflights.iter().enumerate() {
            if let Some(mut record) = preflight.main.global_sumchecks.last().cloned() {
                record.proof_idx = proof_idx;
                global_sumcheck_records.push(record);
            }
            eval_records.extend(preflight.main.evals.iter().cloned().map(move |mut record| {
                record.proof_idx = proof_idx;
                record
            }));
            selector_eval_records.extend(preflight.main.selector_evals.iter().cloned().map(
                move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                },
            ));
            frontload_term_records.extend(preflight.main.frontload_terms.iter().cloned().map(
                move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                },
            ));
            final_claim_records.extend(preflight.main.final_claims.iter().cloned().map(
                move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                },
            ));
        }
        if final_claim_records.is_empty() {
            final_claim_records.push(MainFinalClaimRecord::default());
        }
        if global_sumcheck_records.is_empty() {
            global_sumcheck_records.push(crate::system::MainGlobalSumcheckRecord::default());
        }
        let global_by_proof = global_sumcheck_records
            .iter()
            .map(|record| {
                (
                    record.proof_idx,
                    record
                        .rounds
                        .iter()
                        .map(|round| round.challenge)
                        .collect_vec(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut eq_acc_by_chip =
            std::collections::BTreeMap::<(usize, usize), RecursionField>::new();
        for tower_point in &tower_main_point_records {
            let Some(global_point) = global_by_proof
                .get(&tower_point.proof_idx)
                .and_then(|points| points.get(tower_point.round_idx))
                .copied()
            else {
                continue;
            };
            let acc = eq_acc_by_chip
                .entry((tower_point.proof_idx, tower_point.idx))
                .or_insert(RecursionField::ONE);
            let eq_in = *acc;
            *acc *= global_point * tower_point.value
                + (RecursionField::ONE - global_point) * (RecursionField::ONE - tower_point.value);
            tower_point_eq_records.push(MainTowerPointEqRecord {
                proof_idx: tower_point.proof_idx,
                idx: tower_point.idx,
                round_idx: tower_point.round_idx,
                global_value: global_point,
                tower_value: tower_point.value,
                eq_in,
                eq_out: *acc,
            });
        }
        let mut global_lookup_counts = std::collections::BTreeMap::<(usize, usize), usize>::new();
        for record in &tower_point_eq_records {
            *global_lookup_counts
                .entry((record.proof_idx, record.round_idx))
                .or_default() += 1;
        }
        for record in &frontload_term_records {
            if record.has_global_factor {
                *global_lookup_counts
                    .entry((record.proof_idx, record.global_round_idx))
                    .or_default() += 1;
            }
        }
        for (proof_idx, round_idx) in selector_formula_global_point_lookups(&selector_eval_records)
        {
            *global_lookup_counts
                .entry((proof_idx, round_idx))
                .or_default() += 1;
        }
        for (proof_idx, preflight) in preflights.iter().enumerate() {
            for record in &preflight.pcs.opening_points {
                *global_lookup_counts
                    .entry((proof_idx, record.global_round_idx))
                    .or_default() += 1;
            }
            for record in &preflight.pcs.suffix_products {
                if record.has_factor {
                    *global_lookup_counts
                        .entry((proof_idx, record.coord_idx))
                        .or_default() += 1;
                }
            }
            for record in &preflight.pcs.jagged_assist_h {
                if record.has_z_row {
                    *global_lookup_counts
                        .entry((proof_idx, record.robp_idx))
                        .or_default() += 1;
                }
            }
        }
        let mut eval_lookup_counts =
            std::collections::BTreeMap::<(usize, usize, usize), usize>::new();
        for record in &frontload_term_records {
            if record.has_eval_factor {
                *eval_lookup_counts
                    .entry((record.proof_idx, record.idx, record.eval_idx))
                    .or_default() += 1;
            }
        }
        for record in &selector_eval_records {
            if !record.has_eval {
                continue;
            }
            *eval_lookup_counts
                .entry((record.proof_idx, record.idx, record.eval_idx))
                .or_default() += 1;
        }
        for (proof_idx, preflight) in preflights.iter().enumerate() {
            for record in &preflight.pcs.opening_evals {
                *eval_lookup_counts
                    .entry((proof_idx, record.main_idx, record.main_eval_idx))
                    .or_default() += 1;
            }
        }
        for record in &mut eval_records {
            record.lookup_count = eval_lookup_counts
                .get(&(record.proof_idx, record.idx, record.eval_idx))
                .copied()
                .unwrap_or(0);
        }
        let tower_idx_by_air = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, preflight)| {
                let sorted_idx_by_chip: std::collections::BTreeMap<usize, usize> = preflight
                    .proof_shape
                    .sorted_trace_vdata
                    .iter()
                    .enumerate()
                    .map(|(sorted_idx, (chip_idx, _))| (*chip_idx, sorted_idx))
                    .collect();
                let mut entries = preflight.gkr.chips.iter().collect_vec();
                entries.sort_by_key(|entry| {
                    (
                        sorted_idx_by_chip
                            .get(&entry.chip_idx)
                            .copied()
                            .unwrap_or(usize::MAX),
                        entry.chip_idx,
                    )
                });
                entries
                    .into_iter()
                    .enumerate()
                    .map(move |(tower_idx, entry)| ((proof_idx, entry.chip_idx), tower_idx))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let selector_point_records =
            build_main_selector_point_records(&selector_eval_records, &tower_idx_by_air);
        let ecc_rt_records = build_main_ecc_rt_records(
            proofs,
            preflights,
            &tower_idx_by_air,
            &selector_point_records,
        );
        for global in &mut global_sumcheck_records {
            for (round_idx, round) in global.rounds.iter_mut().enumerate() {
                round.point_lookup_count = global_lookup_counts
                    .get(&(global.proof_idx, round_idx))
                    .copied()
                    .unwrap_or(0);
            }
        }
        let mut transcript_records = Vec::new();
        for (proof_idx, preflight) in preflights.iter().enumerate() {
            let eval_tidxs = eval_records
                .iter()
                .filter(|record| record.proof_idx == proof_idx)
                .flat_map(|record| record.tidx..record.tidx + D_EF)
                .collect::<std::collections::BTreeSet<_>>();
            let global_challenge_tidxs = global_sumcheck_records
                .iter()
                .filter(|record| record.proof_idx == proof_idx)
                .flat_map(|record| {
                    record
                        .rounds
                        .iter()
                        .flat_map(|round| round.challenge_tidx..round.challenge_tidx + D_EF)
                })
                .collect::<std::collections::BTreeSet<_>>();
            let semantic_trunk_tidxs = selector_point_records
                .iter()
                .filter(|record| {
                    record.proof_idx == proof_idx
                        && record.has_transcript
                        && record.source_kind == MainSelectorPointSourceKind::EccXY
                })
                .flat_map(|record| record.transcript_tidx..record.transcript_tidx + D_EF)
                .collect::<std::collections::BTreeSet<_>>();
            let values = preflight.transcript.values();
            let samples = preflight.transcript.samples();
            for tidx in preflight.main.transcript_start..preflight.main.transcript_end {
                if eval_tidxs.contains(&tidx)
                    || global_challenge_tidxs.contains(&tidx)
                    || semantic_trunk_tidxs.contains(&tidx)
                {
                    continue;
                }
                transcript_records.push(crate::system::MainTranscriptRecord {
                    proof_idx,
                    fork_id: 0,
                    is_fork: false,
                    tidx,
                    value: values[tidx],
                    is_sample: samples[tidx],
                });
            }
        }
        let semantic_fork_tidxs = selector_point_records
            .iter()
            .filter(|record| {
                record.has_transcript
                    && record.source_kind == MainSelectorPointSourceKind::RotationOrigin
            })
            .flat_map(|record| {
                (0..D_EF).map(move |offset| {
                    (
                        record.proof_idx,
                        record.fork_id,
                        record.transcript_tidx + offset,
                    )
                })
            })
            .chain(ecc_rt_records.iter().flat_map(|record| {
                (0..D_EF).flat_map(move |offset| {
                    [
                        (record.proof_idx, record.fork_id, record.tidx + offset),
                        (record.proof_idx, record.fork_id, record.out_tidx + offset),
                        (record.proof_idx, record.fork_id, record.alpha_tidx + offset),
                    ]
                })
            }))
            .collect::<std::collections::BTreeSet<_>>();
        for input in tower_input_records
            .iter()
            .filter(|record| record.n_logup != 0)
        {
            let Some(fork) = preflights
                .get(input.proof_idx)
                .and_then(|preflight| preflight.fork_transcripts.get(input.fork_id))
            else {
                continue;
            };
            let fork_values = fork.log.values();
            let fork_samples = fork.log.samples();
            let tail_start = main_tidx_from_tower_input(input);
            let tail_end = fork.log.len().saturating_sub(D_EF);
            for tidx in tail_start..tail_end {
                if semantic_fork_tidxs.contains(&(input.proof_idx, input.fork_id, tidx)) {
                    continue;
                }
                transcript_records.push(crate::system::MainTranscriptRecord {
                    proof_idx: input.proof_idx,
                    fork_id: input.fork_id,
                    is_fork: true,
                    tidx,
                    value: fork_values[tidx],
                    is_sample: fork_samples[tidx],
                });
            }
        }
        if transcript_records.is_empty() {
            transcript_records.push(crate::system::MainTranscriptRecord::default());
        }

        Ok(MainCollectedRecords {
            main_records,
            global_sumcheck_records,
            eval_records,
            selector_eval_records,
            selector_point_records,
            ecc_rt_records,
            tower_point_eq_records,
            frontload_term_records,
            final_claim_records,
            transcript_records,
        })
    }
}

pub(crate) struct MainCollectedRecords {
    pub(crate) main_records: Vec<MainRecord>,
    pub(crate) global_sumcheck_records: Vec<crate::system::MainGlobalSumcheckRecord>,
    pub(crate) eval_records: Vec<MainEvalRecord>,
    pub(crate) selector_eval_records: Vec<MainSelectorEvalRecord>,
    pub(crate) selector_point_records: Vec<MainSelectorPointRecord>,
    pub(crate) ecc_rt_records: Vec<MainEccRtRecord>,
    pub(crate) tower_point_eq_records: Vec<MainTowerPointEqRecord>,
    pub(crate) frontload_term_records: Vec<MainFrontloadTermRecord>,
    pub(crate) final_claim_records: Vec<MainFinalClaimRecord>,
    pub(crate) transcript_records: Vec<crate::system::MainTranscriptRecord>,
}

impl AirModule for MainModule {
    fn num_airs(&self) -> usize {
        10
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let main_air = MainAir {
            main_bus: self.main_bus,
            expression_claim_bus: self.expression_claim_bus,
            send_expression_claim: false,
        };
        vec![
            Arc::new(main_air) as AirRef<_>,
            Arc::new(MainTranscriptBindAir {
                transcript_bus: self.transcript_bus,
                forked_transcript_bus: self.forked_transcript_bus,
            }) as AirRef<_>,
            Arc::new(MainEccRtChallengeAir {
                forked_transcript_bus: self.forked_transcript_bus,
                ecc_rt_bus: self.ecc_rt_bus,
                challenge_bus: self.main_ecc_rt_challenge_bus,
            }) as AirRef<_>,
            Arc::new(MainEccRtEquationAir {
                challenge_bus: self.main_ecc_rt_challenge_bus,
                equation_totals_bus: self.main_ecc_rt_equation_totals_bus,
            }) as AirRef<_>,
            Arc::new(MainEccRtSumcheckAir {
                challenge_bus: self.main_ecc_rt_challenge_bus,
                sumcheck_final_bus: self.main_ecc_rt_sumcheck_final_bus,
            }) as AirRef<_>,
            Arc::new(MainEccRtQuarkAir {
                challenge_bus: self.main_ecc_rt_challenge_bus,
                quark_final_bus: self.main_ecc_rt_quark_final_bus,
            }) as AirRef<_>,
            Arc::new(MainEccRtAir {
                challenge_bus: self.main_ecc_rt_challenge_bus,
                sumcheck_final_bus: self.main_ecc_rt_sumcheck_final_bus,
                equation_totals_bus: self.main_ecc_rt_equation_totals_bus,
                quark_final_bus: self.main_ecc_rt_quark_final_bus,
            }) as AirRef<_>,
            Arc::new(MainSelectorPointAir {
                selector_point_bus: self.main_selector_point_bus,
                tower_point_bus: self.tower_main_point_bus,
                transcript_bus: self.transcript_bus,
                forked_transcript_bus: self.forked_transcript_bus,
                ecc_rt_bus: self.ecc_rt_bus,
            }) as AirRef<_>,
            Arc::new(MainSelectorFormulaAir {
                global_point_bus: self.main_global_point_bus,
                selector_point_bus: self.main_selector_point_bus,
                air_presence_bus: self.air_presence_bus,
                selector_result_bus: self.main_selector_result_bus,
                selector_shape_bus: self.main_selector_shape_bus,
                selector_sparse_index_shape_bus: self.main_selector_sparse_index_shape_bus,
            }) as AirRef<_>,
            Arc::new(MainSelectorEvalAir {
                eval_bus: self.main_eval_bus,
                selector_result_bus: self.main_selector_result_bus,
            }) as AirRef<_>,
        ]
    }
}

impl MainModule {
    pub fn run_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let _ = self;
        preflight.main.transcript_start = ts.len();
        match replay_batched_main_preflight(child_vk, proof, ts, preflight) {
            Ok(()) => {}
            Err(err) => {
                panic!("main preflight replay failed: {err}");
            }
        }
        preflight.main.transcript_end = ts.len();
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>> for MainModule {
    type ModuleSpecificCtx<'a> = ();

    fn generate_proving_ctxs(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        _ctx: &Self::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let mut records = Self::collect_records(child_vk, proofs, preflights).ok()?;
        let MainCollectedRecords {
            ref mut main_records,
            global_sumcheck_records: _,
            eval_records: _,
            ref mut selector_eval_records,
            ref mut selector_point_records,
            ref mut ecc_rt_records,
            tower_point_eq_records: _,
            frontload_term_records: _,
            final_claim_records: _,
            ref mut transcript_records,
        } = records;
        main_records.sort_by_key(|record| (record.proof_idx, record.idx));
        selector_eval_records.sort_by_key(|record| {
            (
                record.proof_idx,
                record.idx,
                record.air_idx,
                record.selector_idx,
            )
        });
        selector_point_records.sort_by_key(|record| {
            (
                record.proof_idx,
                record.idx,
                record.air_idx,
                record.selector_idx,
                record.round_idx,
            )
        });
        ecc_rt_records
            .sort_by_key(|record| (record.proof_idx, record.idx, record.round_idx, record.tidx));
        transcript_records.sort_by_key(|record| (record.proof_idx, record.tidx));
        let ctx = MainTraceCtx {
            main_records: &main_records,
            selector_eval_records: &selector_eval_records,
            selector_point_records: &selector_point_records,
            ecc_rt_records: &ecc_rt_records,
            transcript_records: &transcript_records,
        };
        let chips = [
            MainModuleChip::Main,
            MainModuleChip::TranscriptBind,
            MainModuleChip::EccRtChallenge,
            MainModuleChip::EccRtEquation,
            MainModuleChip::EccRtSumcheck,
            MainModuleChip::EccRtQuark,
            MainModuleChip::EccRt,
            MainModuleChip::SelectorPoint,
            MainModuleChip::SelectorFormula,
            MainModuleChip::SelectorEval,
        ];
        let span = tracing::Span::current();
        let contexts = chips
            .into_iter()
            .enumerate()
            .map(|(idx, chip)| {
                let _guard = span.enter();
                chip.generate_proving_ctx(
                    &ctx,
                    required_heights.and_then(|heights| heights.get(idx).copied()),
                )
            })
            .collect::<Option<Vec<_>>>()?;

        Some(contexts)
    }
}

struct MainTraceCtx<'a> {
    main_records: &'a [MainRecord],
    selector_eval_records: &'a [MainSelectorEvalRecord],
    selector_point_records: &'a [MainSelectorPointRecord],
    ecc_rt_records: &'a [MainEccRtRecord],
    transcript_records: &'a [crate::system::MainTranscriptRecord],
}

enum MainModuleChip {
    Main,
    TranscriptBind,
    EccRtChallenge,
    EccRtEquation,
    EccRtSumcheck,
    EccRtQuark,
    EccRt,
    SelectorPoint,
    SelectorFormula,
    SelectorEval,
}

impl RowMajorChip<F> for MainModuleChip {
    type Ctx<'a> = MainTraceCtx<'a>;

    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        match self {
            MainModuleChip::Main => {
                MainTraceGenerator.generate_trace(&ctx.main_records, required_height)
            }
            MainModuleChip::TranscriptBind => MainTranscriptBindTraceGenerator
                .generate_trace(&ctx.transcript_records, required_height),
            MainModuleChip::EccRtChallenge => MainEccRtChallengeTraceGenerator
                .generate_trace(&ctx.ecc_rt_records, required_height),
            MainModuleChip::EccRtEquation => {
                MainEccRtEquationTraceGenerator.generate_trace(&ctx.ecc_rt_records, required_height)
            }
            MainModuleChip::EccRtSumcheck => {
                MainEccRtSumcheckTraceGenerator.generate_trace(&ctx.ecc_rt_records, required_height)
            }
            MainModuleChip::EccRtQuark => {
                MainEccRtQuarkTraceGenerator.generate_trace(&ctx.ecc_rt_records, required_height)
            }
            MainModuleChip::EccRt => {
                MainEccRtTraceGenerator.generate_trace(&ctx.ecc_rt_records, required_height)
            }
            MainModuleChip::SelectorPoint => MainSelectorPointTraceGenerator
                .generate_trace(&ctx.selector_point_records, required_height),
            MainModuleChip::SelectorFormula => MainSelectorFormulaTraceGenerator
                .generate_trace(&ctx.selector_eval_records, required_height),
            MainModuleChip::SelectorEval => MainSelectorEvalTraceGenerator
                .generate_trace(&ctx.selector_eval_records, required_height),
        }
    }
}

fn main_tidx_from_tower_input(record: &TowerInputRecord) -> usize {
    let tidx_after_alpha_beta = record.tidx + tower_transcript_len::ALPHA_BETA_LEN;
    let read_active_layers = record.read_tower_vars - usize::from(record.has_read_out);
    let write_active_layers = record.write_tower_vars - usize::from(record.has_write_out);
    let logup_active_layers = record.logup_tower_vars - usize::from(record.has_logup_out);
    let claim_span =
        (read_active_layers + write_active_layers) * 2 * D_EF + logup_active_layers * 4 * D_EF;
    let num_layers = record.n_logup;
    let fixed_span =
        num_layers * (tower_transcript_len::SUMCHECK_INIT_LEN + tower_transcript_len::MERGE_LEN);
    let round_span = num_layers * (num_layers + 1) * (tower_transcript_len::ROUND_LEN / 2);
    let alpha_span = num_layers * tower_transcript_len::ALPHA_LEN;
    tidx_after_alpha_beta + fixed_span + round_span + alpha_span + claim_span
}

pub(crate) fn replay_chip_pre_main_tail_transcript<TS>(
    ts: &mut TS,
    child_vk: &RecursionVk,
    chip_idx: usize,
    chip_proof: &ceno_zkvm::scheme::ZKVMChipProof<RecursionField>,
    tower_replay: &TowerReplayResult,
    challenges: [RecursionField; 2],
) -> Result<(Option<RotationReplayClaims>, Option<EccReplayClaims>)>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    let name = child_vk
        .circuit_index_to_name
        .get(&chip_idx)
        .ok_or_else(|| eyre!("missing circuit name for chip index {chip_idx}"))?;
    let circuit_vk = child_vk
        .circuit_vks
        .get(name)
        .ok_or_else(|| eyre!("missing circuit vk for {name}"))?;
    let composed_cs = circuit_vk.get_cs();

    let mut ecc_replay = None;
    if composed_cs.has_ecc_ops() {
        let ecc_proof = chip_proof
            .ecc_proof
            .as_ref()
            .ok_or_else(|| eyre!("{name} missing ecc proof"))?;
        let num_vars = ceil_log2(next_pow2_instance_padding(ecc_proof.num_instances));
        let (_, out_rt_tidxs) = sample_vec_with_tidxs(ts, b"ecc", num_vars);
        let (_, alpha_tidx) = sample_challenge_pows_with_tidx(
            ts,
            7 * ceno_zkvm::scheme::constants::SEPTIC_EXTENSION_DEGREE,
            b"ecc_alpha",
        );
        let (_, _, rt_tidxs) = replay_main_sumcheck(
            ts,
            RecursionField::ZERO,
            &ecc_proof.zerocheck_proof,
            num_vars,
            3,
        )?;
        ecc_replay = Some(EccReplayClaims {
            out_rt_tidxs,
            alpha_tidx,
            rt_tidxs,
        });
    }

    let gkr_circuit = composed_cs
        .gkr_circuit
        .as_ref()
        .ok_or_else(|| eyre!("{name} missing gkr circuit in vk"))?;
    let first_layer = gkr_circuit
        .layers
        .first()
        .ok_or_else(|| eyre!("{name} empty gkr circuit layers"))?;
    if first_layer.rotation_exprs.1.is_empty() {
        return Ok((None, ecc_replay));
    }

    let rotation_proof = chip_proof
        .rotation_proof
        .as_ref()
        .ok_or_else(|| eyre!("{name} missing rotation proof"))?;
    let num_rotations = first_layer.rotation_exprs.1.len();
    if rotation_proof.evals.len() != num_rotations * 3 {
        bail!(
            "{name} rotation eval length mismatch: {} != {}",
            rotation_proof.evals.len(),
            num_rotations * 3
        );
    }

    let num_instances: usize = chip_proof.num_instances.iter().sum();
    let mut log2_num_instances = ceil_log2(next_pow2_instance_padding(num_instances));
    if composed_cs.has_ecc_ops() {
        log2_num_instances += 1;
    }
    let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);
    let rt_main = rt_main_from_tower_replay(tower_replay, num_var_with_rotation)
        .ok_or_else(|| eyre!("{name} missing tower main point for rotation replay"))?;

    let (rotation_power_challenges, _) =
        sample_challenge_pows_with_tidx(ts, num_rotations, b"combine subset evals");
    let rotation_challenges = chain!(
        challenges.iter().copied(),
        rotation_power_challenges.iter().copied()
    )
    .collect_vec();
    let (origin_point, expected_evaluation, origin_tidxs) = replay_main_sumcheck(
        ts,
        RecursionField::ZERO,
        &rotation_proof.proof,
        num_var_with_rotation,
        2,
    )?;
    for eval in &rotation_proof.evals {
        ts.observe_ext(*eval);
    }

    let rotation_sumcheck_expression = first_layer
        .rotation_sumcheck_expression
        .as_ref()
        .ok_or_else(|| eyre!("{name} missing rotation sumcheck expression"))?;
    let bh = gkr_iop::gkr::booleanhypercube::BooleanHypercube::new(
        first_layer.rotation_cyclic_group_log2,
    );
    let selector_eval = gkr_iop::utils::rotation_selector_eval(
        &bh,
        &rt_main,
        &origin_point,
        first_layer.rotation_cyclic_subgroup_size,
        first_layer.rotation_cyclic_group_log2,
    );
    let mut left_evals = Vec::with_capacity(num_rotations);
    let mut right_evals = Vec::with_capacity(num_rotations);
    let mut target_evals = Vec::with_capacity(num_rotations);
    let got_claim = eval_by_expr(
        &rotation_proof
            .evals
            .chunks_exact(3)
            .flat_map(|evals| {
                let [left_eval, right_eval, target_eval] = evals else {
                    unreachable!()
                };
                left_evals.push(*left_eval);
                right_evals.push(*right_eval);
                target_evals.push(*target_eval);
                [
                    (RecursionField::ONE
                        - origin_point[first_layer.rotation_cyclic_group_log2 - 1])
                        * *left_eval
                        + origin_point[first_layer.rotation_cyclic_group_log2 - 1] * *right_eval,
                    *target_eval,
                ]
            })
            .chain(std::iter::once(selector_eval))
            .collect_vec(),
        &[],
        &rotation_challenges,
        rotation_sumcheck_expression,
    );
    if got_claim != expected_evaluation {
        bail!("{name} rotation verify failed: {expected_evaluation} != {got_claim}");
    }
    let (left_point, right_point) = bh.get_rotation_points(&origin_point);

    Ok((
        Some(RotationReplayClaims {
            left_point,
            right_point,
            origin_point,
            origin_tidxs,
            left_evals,
            right_evals,
            target_evals,
        }),
        ecc_replay,
    ))
}

fn sample_vec_with_tidxs<TS>(
    ts: &mut TS,
    label: &[u8],
    len: usize,
) -> (Vec<RecursionField>, Vec<usize>)
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    transcript_observe_label(ts, label);
    let mut values = Vec::with_capacity(len);
    let mut tidxs = Vec::with_capacity(len);
    for _ in 0..len {
        tidxs.push(ts.len());
        values.push(FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(
            ts,
        ));
    }
    (values, tidxs)
}

struct MainReplayLayer<'a> {
    air_idx: usize,
    fork_id: usize,
    layer: &'a gkr_iop::gkr::layer::Layer<RecursionField>,
    eval_and_dedup_points: Vec<(Vec<RecursionField>, Option<Vec<RecursionField>>)>,
    selector_point_sources: Vec<MainSelectorPointSourceKind>,
    selector_ctxs: Vec<gkr_iop::selector::SelectorContext>,
    eval_start: usize,
    eval_len: usize,
    alpha_start: usize,
    num_var_with_rotation: usize,
    pi: Vec<RecursionField>,
    rotation_cyclic_group_log2: usize,
    rotation_origin_selector_idx: Option<usize>,
    rotation_origin_tidxs: Vec<usize>,
    ecc_sample_tidx: Option<usize>,
    ecc_rt_tidxs: Vec<usize>,
    ecc_xy_selector_idx: Option<usize>,
    ecc_x3y3_selector_idx: Option<usize>,
}

fn replay_batched_main_preflight<TS>(
    child_vk: &RecursionVk,
    proof: &RecursionProof,
    ts: &mut TS,
    preflight: &mut Preflight,
) -> Result<()>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    let mut layers = Vec::new();
    let mut total_exprs = 0usize;
    let mut total_evals = 0usize;
    let mut max_num_variables = 0usize;
    let mut max_degree = 0usize;
    let tower_record_by_chip = preflight
        .gkr
        .chips
        .iter()
        .map(|record| (record.chip_idx, record))
        .collect::<std::collections::BTreeMap<_, _>>();

    for (chip_idx, chip_proof) in &proof.chip_proofs {
        let name = child_vk
            .circuit_index_to_name
            .get(chip_idx)
            .ok_or_else(|| eyre!("missing circuit name for chip index {chip_idx}"))?;
        if proof.public_values.shard_id > 0 {
            let Some(circuit_vk) = child_vk.circuit_vks.get(name) else {
                continue;
            };
            if circuit_vk.get_cs().with_omc_init_only() {
                continue;
            }
        }

        let circuit_vk = child_vk
            .circuit_vks
            .get(name)
            .ok_or_else(|| eyre!("missing circuit vk for {name}"))?;
        let composed_cs = circuit_vk.get_cs();
        let gkr_circuit = composed_cs
            .gkr_circuit
            .as_ref()
            .ok_or_else(|| eyre!("{name} missing gkr circuit in vk"))?;
        let layer = gkr_circuit
            .layers
            .first()
            .ok_or_else(|| eyre!("{name} empty gkr circuit layers"))?;
        let num_instances: usize = chip_proof.num_instances.iter().sum();
        let mut log2_num_instances = ceil_log2(next_pow2_instance_padding(num_instances));
        if composed_cs.has_ecc_ops() {
            log2_num_instances += 1;
        }
        let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);
        let pi = composed_cs
            .zkvm_v1_css
            .instance
            .iter()
            .map(|instance| {
                RecursionField::from(
                    proof
                        .public_values
                        .query_by_index::<RecursionField>(instance.0),
                )
            })
            .collect_vec();

        let tower_record = tower_record_by_chip
            .get(chip_idx)
            .copied()
            .ok_or_else(|| eyre!("{name} missing tower replay for main replay"))?;
        let rt_main = rt_main_from_tower_replay(&tower_record.tower_replay, num_var_with_rotation);
        if chip_proof.ecc_proof.is_some() && rt_main.is_none() {
            bail!("{name} missing tower main point for ecc bridge main replay");
        }
        let has_rt_main = rt_main.is_some();
        let rt_main = rt_main.unwrap_or_else(|| vec![RecursionField::ZERO; num_var_with_rotation]);
        let selector_ctxs = first_layer_selector_contexts(
            composed_cs,
            gkr_circuit,
            chip_proof.num_instances,
            num_var_with_rotation,
        )?;
        let mut rotation_origin_selector_idx = None;
        let mut rotation_origin_tidxs = Vec::new();
        let mut ecc_sample_tidx = None;
        let mut ecc_rt_tidxs = Vec::new();
        let mut ecc_xy_selector_idx = None;
        let mut ecc_x3y3_selector_idx = None;
        let mut selector_point_sources =
            vec![MainSelectorPointSourceKind::TowerMain; layer.out_sel_and_eval_exprs.len()];
        let mut out_evals =
            vec![PointAndEval::new(rt_main, RecursionField::ZERO); gkr_circuit.n_evaluations];
        if chip_proof.main_out_evals.len() > gkr_circuit.n_evaluations {
            bail!(
                "{name} main output eval length {} exceeds gkr output length {}",
                chip_proof.main_out_evals.len(),
                gkr_circuit.n_evaluations
            );
        }
        for (out_eval, eval) in out_evals.iter_mut().zip(chip_proof.main_out_evals.iter()) {
            out_eval.eval = *eval;
        }

        if !layer.rotation_exprs.1.is_empty() {
            let rotation_claims = tower_record
                .rotation_replay
                .as_ref()
                .ok_or_else(|| eyre!("{name} missing rotation replay claims"))?;
            let Some([left_group_idx, right_group_idx, point_group_idx]) =
                layer.rotation_selector_group_indices()
            else {
                bail!("rotation claims expected but selectors are missing");
            };
            rotation_origin_selector_idx = Some(point_group_idx);
            rotation_origin_tidxs = rotation_claims.origin_tidxs.clone();
            selector_point_sources[left_group_idx] = MainSelectorPointSourceKind::RotationLeft;
            selector_point_sources[right_group_idx] = MainSelectorPointSourceKind::RotationRight;
            selector_point_sources[point_group_idx] = MainSelectorPointSourceKind::RotationOrigin;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[left_group_idx].1,
                &rotation_claims.left_evals,
                &rotation_claims.left_point,
            )?;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[right_group_idx].1,
                &rotation_claims.right_evals,
                &rotation_claims.right_point,
            )?;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[point_group_idx].1,
                &rotation_claims.target_evals,
                &rotation_claims.origin_point,
            )?;
        }

        if let Some(ecc_proof) = chip_proof.ecc_proof.as_ref() {
            let Some(
                [
                    x_group_idx,
                    y_group_idx,
                    slope_group_idx,
                    x3_group_idx,
                    y3_group_idx,
                ],
            ) = layer.ecc_bridge_group_indices()
            else {
                bail!("ecc bridge claims expected but selectors are missing");
            };
            selector_point_sources[x_group_idx] = MainSelectorPointSourceKind::EccXY;
            selector_point_sources[y_group_idx] = MainSelectorPointSourceKind::EccXY;
            selector_point_sources[slope_group_idx] = MainSelectorPointSourceKind::EccSlope;
            selector_point_sources[x3_group_idx] = MainSelectorPointSourceKind::EccX3Y3;
            selector_point_sources[y3_group_idx] = MainSelectorPointSourceKind::EccX3Y3;
            ecc_xy_selector_idx = Some(x_group_idx);
            ecc_x3y3_selector_idx = Some(x3_group_idx);
            ecc_rt_tidxs = tower_record
                .ecc_replay
                .as_ref()
                .ok_or_else(|| eyre!("{name} missing ecc replay claims"))?
                .rt_tidxs
                .clone();

            let (sample_r_values, sample_r_tidxs) =
                sample_vec_with_tidxs(ts, b"ecc_gkr_bridge_r", 1);
            let sample_r = sample_r_values[0];
            ecc_sample_tidx = Some(sample_r_tidxs[0]);
            let claims = derive_ecc_bridge_claims(ecc_proof, sample_r, num_var_with_rotation)?;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[x_group_idx].1,
                &claims.x_evals,
                &claims.xy_point,
            )?;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[y_group_idx].1,
                &claims.y_evals,
                &claims.xy_point,
            )?;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[slope_group_idx].1,
                &claims.s_evals,
                &claims.s_point,
            )?;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[x3_group_idx].1,
                &claims.x3_evals,
                &claims.x3y3_point,
            )?;
            assign_group_evals(
                &mut out_evals,
                &layer.out_sel_and_eval_exprs[y3_group_idx].1,
                &claims.y3_evals,
                &claims.x3y3_point,
            )?;
        }
        out_evals.resize(gkr_circuit.n_evaluations, PointAndEval::default());
        let eval_and_dedup_points = layer
            .out_sel_and_eval_exprs
            .iter()
            .map(|(_, out_eval_exprs)| {
                let evals = out_eval_exprs
                    .iter()
                    .map(|out_eval| {
                        out_eval
                            .evaluate(&out_evals, &pcs_challenges_from_preflight(preflight))
                            .eval
                    })
                    .collect_vec();
                let point = out_eval_exprs.first().and_then(|out_eval| {
                    if !has_rt_main {
                        return None;
                    }
                    Some(
                        out_eval
                            .evaluate(&out_evals, &pcs_challenges_from_preflight(preflight))
                            .point,
                    )
                });
                (evals, point)
            })
            .collect_vec();

        let eval_len = layer.n_witin + layer.n_fixed + layer.n_structural_witin;
        max_num_variables = max_num_variables.max(num_var_with_rotation);
        max_degree = max_degree.max(layer.max_expr_degree + 1);
        layers.push(MainReplayLayer {
            air_idx: *chip_idx,
            fork_id: tower_record.fork_idx,
            layer,
            eval_and_dedup_points,
            selector_point_sources,
            selector_ctxs,
            eval_start: total_evals,
            eval_len,
            alpha_start: total_exprs,
            num_var_with_rotation,
            pi,
            rotation_cyclic_group_log2: layer.rotation_cyclic_group_log2,
            rotation_origin_selector_idx,
            rotation_origin_tidxs,
            ecc_sample_tidx,
            ecc_rt_tidxs,
            ecc_xy_selector_idx,
            ecc_x3y3_selector_idx,
        });
        total_evals += eval_len;
        total_exprs += layer.exprs.len();
    }

    let main_proof = &proof.main_constraint_proof;
    if layers.is_empty() {
        if !main_proof.proof.proof.proofs.is_empty()
            || !main_proof.proof.evals.is_empty()
            || main_proof.claimed_sum != RecursionField::ZERO
        {
            bail!("empty main constraints with non-empty proof");
        }
        preflight
            .main
            .global_sumchecks
            .push(crate::system::MainGlobalSumcheckRecord {
                proof_idx: 0,
                expected: RecursionField::ZERO,
                rounds: Vec::new(),
            });
        preflight
            .main
            .final_claims
            .push(MainFinalClaimRecord::default());
        return Ok(());
    }
    if main_proof.proof.evals.len() != total_evals {
        bail!(
            "main constraint eval length mismatch: {} != {}",
            main_proof.proof.evals.len(),
            total_evals
        );
    }

    let alpha_pows = sample_challenge_pows(ts, total_exprs, b"combine subset evals");
    let (global_in_point, expected_evaluation, challenge_tidxs) = replay_main_sumcheck(
        ts,
        main_proof.claimed_sum,
        &main_proof.proof.proof,
        max_num_variables,
        max_degree,
    )?;

    let eval_tidx_start = ts.len();
    for eval in &main_proof.proof.evals {
        ts.observe_ext(*eval);
    }

    let pcs_challenges = [
        preflight.vm_pvs.lookup_challenge_alpha,
        preflight.vm_pvs.lookup_challenge_beta,
    ];
    let mut eval_records =
        build_main_eval_records(&layers, &main_proof.proof.evals, eval_tidx_start);
    let tower_point_eqs = build_main_tower_point_eq_records(&layers, &global_in_point);
    let selector_evals =
        build_main_selector_eval_records(&layers, &main_proof.proof.evals, &global_in_point)?;
    let (acc, frontload_terms, final_claims) = build_final_claim_records(
        &layers,
        &main_proof.proof.evals,
        &pcs_challenges,
        &alpha_pows,
        &global_in_point,
        expected_evaluation,
    )?;
    if acc != expected_evaluation {
        bail!("main constraint claim mismatch: {expected_evaluation} != {acc}");
    }
    preflight
        .pcs
        .opening_claims
        .extend(layers.iter().map(|layer| {
            let in_point = global_in_point[..layer.num_var_with_rotation].to_vec();
            let layer_evals =
                &main_proof.proof.evals[layer.eval_start..layer.eval_start + layer.eval_len];
            PcsOpeningClaimRecord {
                input_opening_point: in_point,
                wits_in_evals: layer_evals[..layer.layer.n_witin].to_vec(),
                fixed_in_evals: layer_evals
                    [layer.layer.n_witin..layer.layer.n_witin + layer.layer.n_fixed]
                    .to_vec(),
            }
        }));
    let mut global_point_lookup_counts = vec![0usize; global_in_point.len()];
    for (opening_idx, layer) in layers.iter().enumerate() {
        for (coord_idx, value) in global_in_point[..layer.num_var_with_rotation]
            .iter()
            .copied()
            .enumerate()
        {
            global_point_lookup_counts[coord_idx] += 1;
            preflight.pcs.opening_points.push(PcsOpeningPointRecord {
                proof_idx: 0,
                opening_idx,
                coord_idx,
                global_round_idx: coord_idx,
                value,
            });
        }
    }
    for record in &tower_point_eqs {
        global_point_lookup_counts[record.round_idx] += 1;
    }
    for record in &frontload_terms {
        if record.has_global_factor {
            global_point_lookup_counts[record.global_round_idx] += 1;
        }
    }
    for (_, round_idx) in selector_formula_global_point_lookups(&selector_evals) {
        global_point_lookup_counts[round_idx] += 1;
    }
    let mut eval_lookup_counts = vec![0usize; main_proof.proof.evals.len()];
    for (opening_idx, layer) in layers.iter().enumerate() {
        for eval_idx in 0..layer.layer.n_witin {
            let global_eval_idx = layer.eval_start + eval_idx;
            eval_lookup_counts[global_eval_idx] += 1;
            preflight.pcs.opening_evals.push(PcsOpeningEvalRecord {
                proof_idx: 0,
                opening_idx,
                commit_kind: PcsOpeningCommitKind::Witin,
                eval_idx,
                main_idx: opening_idx,
                main_eval_idx: eval_idx,
                value: main_proof.proof.evals[global_eval_idx],
                raw_value: main_proof.proof.evals[global_eval_idx],
            });
        }
        for eval_idx in 0..layer.layer.n_fixed {
            let main_eval_idx = layer.layer.n_witin + eval_idx;
            let global_eval_idx = layer.eval_start + main_eval_idx;
            eval_lookup_counts[global_eval_idx] += 1;
            preflight.pcs.opening_evals.push(PcsOpeningEvalRecord {
                proof_idx: 0,
                opening_idx,
                commit_kind: PcsOpeningCommitKind::Fixed,
                eval_idx,
                main_idx: opening_idx,
                main_eval_idx,
                value: main_proof.proof.evals[global_eval_idx],
                raw_value: main_proof.proof.evals[global_eval_idx],
            });
        }
    }
    for record in &frontload_terms {
        if record.has_eval_factor {
            let global_eval_idx = layers[record.idx].eval_start + record.eval_idx;
            eval_lookup_counts[global_eval_idx] += 1;
        }
    }
    for record in &selector_evals {
        if !record.has_eval {
            continue;
        }
        let global_eval_idx = layers[record.idx].eval_start + record.eval_idx;
        eval_lookup_counts[global_eval_idx] += 1;
    }
    for record in &mut eval_records {
        record.lookup_count = eval_lookup_counts[layers[record.idx].eval_start + record.eval_idx];
    }
    preflight
        .main
        .global_sumchecks
        .push(build_global_sumcheck_record(
            0,
            main_proof.claimed_sum,
            &main_proof.proof.proof,
            &global_in_point,
            &challenge_tidxs,
            expected_evaluation,
            &global_point_lookup_counts,
        )?);
    preflight.main.evals.extend(eval_records);
    preflight.main.selector_evals.extend(selector_evals);
    preflight.main.tower_point_eqs.extend(tower_point_eqs);
    preflight.main.frontload_terms.extend(frontload_terms);
    preflight.main.final_claims.extend(final_claims);
    Ok(())
}

fn pcs_challenges_from_preflight(preflight: &Preflight) -> [RecursionField; 2] {
    [
        preflight.vm_pvs.lookup_challenge_alpha,
        preflight.vm_pvs.lookup_challenge_beta,
    ]
}

fn rt_main_from_tower_replay(
    replay: &TowerReplayResult,
    num_var_with_rotation: usize,
) -> Option<Vec<RecursionField>> {
    if num_var_with_rotation == 0 {
        return Some(Vec::new());
    }
    let final_layer = replay.layers.last()?;
    let mut rt_tower = final_layer.challenges.clone();
    rt_tower.push(final_layer.mu);
    if rt_tower.len() < num_var_with_rotation {
        return None;
    }
    Some(rt_tower[rt_tower.len() - num_var_with_rotation..].to_vec())
}

struct EccBridgeClaims {
    xy_point: Vec<RecursionField>,
    s_point: Vec<RecursionField>,
    x3y3_point: Vec<RecursionField>,
    x_evals: Vec<RecursionField>,
    y_evals: Vec<RecursionField>,
    s_evals: Vec<RecursionField>,
    x3_evals: Vec<RecursionField>,
    y3_evals: Vec<RecursionField>,
}

fn derive_ecc_bridge_claims(
    ecc_proof: &ceno_zkvm::structs::EccQuarkProof<RecursionField>,
    sample_r: RecursionField,
    num_var_with_rotation: usize,
) -> Result<EccBridgeClaims> {
    let degree = ceno_zkvm::scheme::constants::SEPTIC_EXTENSION_DEGREE;
    if ecc_proof.evals.len() < 3 {
        bail!("ecc proof evals shorter than selector prefix");
    }
    let evals = &ecc_proof.evals[3..];
    if evals.len() != degree * 7 {
        bail!(
            "invalid ecc proof eval length: expected {}, got {}",
            degree * 7,
            evals.len()
        );
    }

    let s1 = &evals[0..degree];
    let x0 = &evals[degree..2 * degree];
    let y0 = &evals[2 * degree..3 * degree];
    let x1 = &evals[3 * degree..4 * degree];
    let y1 = &evals[4 * degree..5 * degree];
    let x3 = &evals[5 * degree..6 * degree];
    let y3 = &evals[6 * degree..7 * degree];

    let one_minus_r = RecursionField::ONE - sample_r;
    let x_evals = x0
        .iter()
        .zip_eq(x1.iter())
        .map(|(a, b)| *a * one_minus_r + *b * sample_r)
        .collect_vec();
    let y_evals = y0
        .iter()
        .zip_eq(y1.iter())
        .map(|(a, b)| *a * one_minus_r + *b * sample_r)
        .collect_vec();
    let s_evals = s1.iter().map(|v| *v * sample_r).collect_vec();
    let x3_evals = x3.to_vec();
    let y3_evals = y3.to_vec();

    let mut xy_point = vec![sample_r];
    xy_point.extend(ecc_proof.rt.iter().copied());
    if xy_point.len() != num_var_with_rotation {
        bail!(
            "invalid ecc xy point length: expected {}, got {}",
            num_var_with_rotation,
            xy_point.len()
        );
    }

    let mut s_point = ecc_proof.rt.clone();
    s_point.push(sample_r);
    if s_point.len() != num_var_with_rotation {
        bail!(
            "invalid ecc slope point length: expected {}, got {}",
            num_var_with_rotation,
            s_point.len()
        );
    }

    let mut x3y3_point = ecc_proof.rt.clone();
    x3y3_point.push(RecursionField::ONE);
    if x3y3_point.len() != num_var_with_rotation {
        bail!(
            "invalid ecc x3/y3 point length: expected {}, got {}",
            num_var_with_rotation,
            x3y3_point.len()
        );
    }

    Ok(EccBridgeClaims {
        xy_point,
        s_point,
        x3y3_point,
        x_evals,
        y_evals,
        s_evals,
        x3_evals,
        y3_evals,
    })
}

fn assign_group_evals(
    out_evals: &mut [PointAndEval<RecursionField>],
    eval_exprs: &[gkr_iop::evaluation::EvalExpression<RecursionField>],
    evals: &[RecursionField],
    point: &[RecursionField],
) -> Result<()> {
    if eval_exprs.len() != evals.len() {
        bail!(
            "ecc bridge group eval length mismatch: {} != {}",
            eval_exprs.len(),
            evals.len()
        );
    }
    for (eval_expr, eval) in eval_exprs.iter().zip_eq(evals.iter()) {
        let gkr_iop::evaluation::EvalExpression::Single(index) = eval_expr else {
            bail!("ecc bridge group must use EvalExpression::Single");
        };
        let Some(out_eval) = out_evals.get_mut(*index) else {
            bail!("ecc bridge output eval index {index} out of range");
        };
        *out_eval = PointAndEval::new(point.to_vec(), *eval);
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct GkrOutputStageMask(u8);

impl GkrOutputStageMask {
    const TOWER: Self = Self(1 << 0);
    const ECC: Self = Self(1 << 1);
    const ROTATION: Self = Self(1 << 2);
    const ZERO: Self = Self(1 << 3);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

fn first_layer_output_group_stage_masks(
    composed_cs: &ceno_zkvm::structs::ComposedConstrainSystem<RecursionField>,
    circuit: &gkr_iop::gkr::GKRCircuit<RecursionField>,
) -> Result<Vec<GkrOutputStageMask>> {
    let first_layer = circuit
        .layers
        .first()
        .ok_or_else(|| eyre!("empty gkr circuit layer"))?;
    let mut group_masks = vec![GkrOutputStageMask::ZERO; first_layer.out_sel_and_eval_exprs.len()];

    if let Some(rotation_groups) = first_layer.rotation_selector_group_indices() {
        for group_idx in rotation_groups {
            let Some(mask) = group_masks.get_mut(group_idx) else {
                bail!("rotation selector group index {group_idx} out of range");
            };
            *mask = GkrOutputStageMask::ROTATION;
        }
    }
    if let Some(ecc_groups) = first_layer.ecc_bridge_group_indices() {
        for group_idx in ecc_groups {
            let Some(mask) = group_masks.get_mut(group_idx) else {
                bail!("ecc selector group index {group_idx} out of range");
            };
            *mask = GkrOutputStageMask::ECC;
        }
    }

    let tower_outputs = tower_output_count(composed_cs);
    let mut seen_tower_outputs = 0usize;
    for (group_mask, (_, outputs)) in group_masks
        .iter_mut()
        .zip(first_layer.out_sel_and_eval_exprs.iter())
    {
        if seen_tower_outputs >= tower_outputs {
            break;
        }
        *group_mask = group_mask.union(GkrOutputStageMask::TOWER);
        seen_tower_outputs += outputs.len();
    }
    if seen_tower_outputs < tower_outputs {
        bail!(
            "failed to cover all tower outputs: layer={}, seen_tower_outputs={}, tower_outputs={}",
            first_layer.name,
            seen_tower_outputs,
            tower_outputs
        );
    }

    Ok(group_masks)
}

fn first_layer_selector_contexts(
    composed_cs: &ceno_zkvm::structs::ComposedConstrainSystem<RecursionField>,
    circuit: &gkr_iop::gkr::GKRCircuit<RecursionField>,
    num_instances: [usize; 2],
    num_vars: usize,
) -> Result<Vec<gkr_iop::selector::SelectorContext>> {
    let cs = &composed_cs.zkvm_v1_css;
    let total_num_instances = num_instances.iter().sum();
    let first_layer = circuit
        .layers
        .first()
        .ok_or_else(|| eyre!("empty gkr circuit layer"))?;
    let group_stage_masks = first_layer_output_group_stage_masks(composed_cs, circuit)?;
    let distinct_rw_selectors =
        cs.r_selector.is_some() && cs.w_selector.is_some() && cs.r_selector != cs.w_selector;

    Ok(first_layer
        .out_sel_and_eval_exprs
        .iter()
        .zip_eq(group_stage_masks.iter())
        .map(|((selector, _), stage_mask)| {
            if stage_mask.contains(GkrOutputStageMask::TOWER)
                && distinct_rw_selectors
                && matches!(selector, gkr_iop::selector::SelectorType::Prefix(_))
            {
                if cs.r_selector.as_ref() == Some(selector) {
                    return gkr_iop::selector::SelectorContext::new(0, num_instances[0], num_vars);
                }
                if cs.w_selector.as_ref() == Some(selector) {
                    return gkr_iop::selector::SelectorContext::new(
                        num_instances[0],
                        num_instances[1],
                        num_vars,
                    );
                }
            }

            gkr_iop::selector::SelectorContext::new(0, total_num_instances, num_vars)
        })
        .collect_vec())
}

fn tower_output_count(
    composed_cs: &ceno_zkvm::structs::ComposedConstrainSystem<RecursionField>,
) -> usize {
    let cs = &composed_cs.zkvm_v1_css;
    let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
    let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
    let num_lk_num = cs.lk_table_expressions.len();
    let num_lk_den = if !cs.lk_table_expressions.is_empty() {
        cs.lk_table_expressions.len()
    } else {
        cs.lk_expressions.len()
    };
    num_reads + num_writes + num_lk_num + num_lk_den
}

fn build_global_sumcheck_record(
    proof_idx: usize,
    claimed_sum: RecursionField,
    proof: &sumcheck::structs::IOPProof<RecursionField>,
    global_in_point: &[RecursionField],
    challenge_tidxs: &[usize],
    expected_evaluation: RecursionField,
    point_lookup_counts: &[usize],
) -> Result<crate::system::MainGlobalSumcheckRecord> {
    if proof.proofs.len() != global_in_point.len() {
        bail!(
            "main global sumcheck proof/point length mismatch: {} != {}",
            proof.proofs.len(),
            global_in_point.len()
        );
    }
    if proof.proofs.len() != challenge_tidxs.len() {
        bail!(
            "main global sumcheck proof/challenge-tidx length mismatch: {} != {}",
            proof.proofs.len(),
            challenge_tidxs.len()
        );
    }
    let mut claim = claimed_sum;
    let mut rounds = Vec::with_capacity(proof.proofs.len());
    for (round_idx, ((prover_msg, challenge), challenge_tidx)) in proof
        .proofs
        .iter()
        .zip_eq(global_in_point.iter().copied())
        .zip_eq(challenge_tidxs.iter().copied())
        .enumerate()
    {
        if prover_msg.evaluations.len() > 4 {
            bail!(
                "main global sumcheck round {round_idx} has degree-width {}, max supported 4",
                prover_msg.evaluations.len()
            );
        }
        if prover_msg.evaluations.is_empty() {
            bail!("main global sumcheck round {round_idx} has no evaluations");
        }
        let mut evaluations = [RecursionField::ZERO; 4];
        for (dst, src) in evaluations
            .iter_mut()
            .zip(prover_msg.evaluations.iter().copied())
        {
            *dst = src;
        }
        if prover_msg.evaluations.len() < 4 {
            evaluations[3] = extrapolate_uni_poly(
                claim - evaluations[0],
                &prover_msg.evaluations,
                RecursionField::from_u64(4),
            );
        }
        let claim_out = extrapolate_uni_poly(claim - evaluations[0], &evaluations, challenge);
        rounds.push(crate::system::MainGlobalSumcheckRoundRecord {
            evaluations,
            challenge,
            challenge_tidx,
            claim_in: claim,
            claim_out,
            point_lookup_count: point_lookup_counts.get(round_idx).copied().unwrap_or(0),
        });
        claim = claim_out;
    }
    if claim != expected_evaluation {
        bail!("main global sumcheck fold mismatch: {expected_evaluation} != {claim}");
    }
    Ok(crate::system::MainGlobalSumcheckRecord {
        proof_idx,
        expected: expected_evaluation,
        rounds,
    })
}

fn build_main_eval_records(
    layers: &[MainReplayLayer<'_>],
    main_evals: &[RecursionField],
    eval_tidx_start: usize,
) -> Vec<MainEvalRecord> {
    let mut records = Vec::new();
    for (idx, layer) in layers.iter().enumerate() {
        for local_eval_idx in 0..layer.eval_len {
            let global_eval_idx = layer.eval_start + local_eval_idx;
            records.push(MainEvalRecord {
                proof_idx: 0,
                idx,
                eval_idx: local_eval_idx,
                tidx: eval_tidx_start + global_eval_idx * D_EF,
                value: main_evals[global_eval_idx],
                lookup_count: 0,
            });
        }
    }
    records
}

fn build_main_selector_point_records(
    selector_evals: &[MainSelectorEvalRecord],
    tower_idx_by_air: &std::collections::BTreeMap<(usize, usize), usize>,
) -> Vec<MainSelectorPointRecord> {
    let lookup_counts = selector_formula_point_lookup_counts(selector_evals);
    let mut records = Vec::new();
    for record in selector_evals {
        if !record.has_eval {
            continue;
        }
        for (round_idx, value) in record.out_point.iter().copied().enumerate() {
            let lookup_count = lookup_counts
                .get(&(
                    record.proof_idx,
                    record.idx,
                    record.air_idx,
                    record.selector_idx,
                    round_idx,
                ))
                .copied()
                .unwrap_or(0);
            records.push(MainSelectorPointRecord {
                proof_idx: record.proof_idx,
                idx: record.idx,
                tower_idx: tower_idx_by_air
                    .get(&(record.proof_idx, record.air_idx))
                    .copied()
                    .unwrap_or(record.tower_idx),
                air_idx: record.air_idx,
                selector_idx: record.selector_idx,
                round_idx,
                value,
                source_kind: record.point_source,
                lookup_count,
                fork_id: record.fork_id,
                has_transcript: false,
                transcript_tidx: 0,
                has_ecc_rt: false,
                has_source: false,
                source_selector_idx: 0,
                source_source_kind: MainSelectorPointSourceKind::TowerMain,
                source_round_idx: 0,
                source_value: RecursionField::ZERO,
                derive_kind: MainSelectorPointDeriveKind::Identity,
            });
        }
    }
    let values_by_key = records
        .iter()
        .map(|record| {
            (
                (
                    record.proof_idx,
                    record.idx,
                    record.air_idx,
                    record.selector_idx,
                    record.round_idx,
                ),
                record.value,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let evals_by_key = selector_evals
        .iter()
        .map(|record| {
            (
                (
                    record.proof_idx,
                    record.idx,
                    record.air_idx,
                    record.selector_idx,
                ),
                record,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut source_lookups = Vec::new();
    for point in &mut records {
        let Some(eval) = evals_by_key.get(&(
            point.proof_idx,
            point.idx,
            point.air_idx,
            point.selector_idx,
        )) else {
            continue;
        };
        match point.source_kind {
            MainSelectorPointSourceKind::TowerMain => {}
            MainSelectorPointSourceKind::RotationOrigin => {
                if let Some(tidx) = eval.rotation_origin_tidxs.get(point.round_idx).copied() {
                    point.has_transcript = true;
                    point.transcript_tidx = tidx;
                }
            }
            MainSelectorPointSourceKind::RotationLeft
            | MainSelectorPointSourceKind::RotationRight => {
                let Some(origin_selector_idx) = eval.rotation_origin_selector_idx else {
                    continue;
                };
                let g = eval.rotation_cyclic_group_log2;
                let (derive_kind, source_round_idx) =
                    rotation_point_source(point.source_kind, g, point.round_idx);
                point.derive_kind = derive_kind;
                if matches!(
                    derive_kind,
                    MainSelectorPointDeriveKind::Identity | MainSelectorPointDeriveKind::OneMinus
                ) {
                    point.has_source = true;
                    point.source_selector_idx = origin_selector_idx;
                    point.source_source_kind = MainSelectorPointSourceKind::RotationOrigin;
                    point.source_round_idx = source_round_idx;
                    if let Some(value) = values_by_key.get(&(
                        point.proof_idx,
                        point.idx,
                        point.air_idx,
                        origin_selector_idx,
                        source_round_idx,
                    )) {
                        point.source_value = *value;
                        source_lookups.push((
                            point.proof_idx,
                            point.idx,
                            point.air_idx,
                            origin_selector_idx,
                            source_round_idx,
                        ));
                    }
                }
            }
            MainSelectorPointSourceKind::EccXY => {
                if point.round_idx == 0 {
                    if Some(point.selector_idx) == eval.ecc_xy_selector_idx {
                        if let Some(tidx) = eval.ecc_sample_tidx {
                            point.has_transcript = true;
                            point.transcript_tidx = tidx;
                        }
                    } else if let Some(source_selector_idx) = eval.ecc_xy_selector_idx {
                        point.has_source = true;
                        point.source_selector_idx = source_selector_idx;
                        point.source_source_kind = MainSelectorPointSourceKind::EccXY;
                        point.source_round_idx = 0;
                        if let Some(value) = values_by_key.get(&(
                            point.proof_idx,
                            point.idx,
                            point.air_idx,
                            source_selector_idx,
                            point.source_round_idx,
                        )) {
                            point.source_value = *value;
                            source_lookups.push((
                                point.proof_idx,
                                point.idx,
                                point.air_idx,
                                source_selector_idx,
                                point.source_round_idx,
                            ));
                        }
                    } else if let Some(tidx) = eval.ecc_sample_tidx {
                        point.has_transcript = true;
                        point.transcript_tidx = tidx;
                    }
                } else if let Some(source_selector_idx) = eval.ecc_x3y3_selector_idx {
                    point.has_source = true;
                    point.source_selector_idx = source_selector_idx;
                    point.source_source_kind = MainSelectorPointSourceKind::EccX3Y3;
                    point.source_round_idx = point.round_idx - 1;
                    if let Some(value) = values_by_key.get(&(
                        point.proof_idx,
                        point.idx,
                        point.air_idx,
                        source_selector_idx,
                        point.source_round_idx,
                    )) {
                        point.source_value = *value;
                        source_lookups.push((
                            point.proof_idx,
                            point.idx,
                            point.air_idx,
                            source_selector_idx,
                            point.source_round_idx,
                        ));
                    }
                }
            }
            MainSelectorPointSourceKind::EccSlope => {
                if point.round_idx + 1 == eval.out_point.len() {
                    if let Some(source_selector_idx) = eval.ecc_xy_selector_idx {
                        point.has_source = true;
                        point.source_selector_idx = source_selector_idx;
                        point.source_source_kind = MainSelectorPointSourceKind::EccXY;
                        point.source_round_idx = 0;
                    }
                } else if let Some(source_selector_idx) = eval.ecc_x3y3_selector_idx {
                    point.has_source = true;
                    point.source_selector_idx = source_selector_idx;
                    point.source_source_kind = MainSelectorPointSourceKind::EccX3Y3;
                    point.source_round_idx = point.round_idx;
                }
                if point.has_source {
                    if let Some(value) = values_by_key.get(&(
                        point.proof_idx,
                        point.idx,
                        point.air_idx,
                        point.source_selector_idx,
                        point.source_round_idx,
                    )) {
                        point.source_value = *value;
                        source_lookups.push((
                            point.proof_idx,
                            point.idx,
                            point.air_idx,
                            point.source_selector_idx,
                            point.source_round_idx,
                        ));
                    }
                }
            }
            MainSelectorPointSourceKind::EccX3Y3 => {
                if point.round_idx + 1 == eval.out_point.len() {
                    point.derive_kind = MainSelectorPointDeriveKind::One;
                } else if Some(point.selector_idx) == eval.ecc_x3y3_selector_idx {
                    let Some(tidx) = eval.ecc_rt_tidxs.get(point.round_idx).copied() else {
                        continue;
                    };
                    point.has_ecc_rt = true;
                    point.transcript_tidx = tidx;
                } else if let Some(source_selector_idx) = eval.ecc_x3y3_selector_idx {
                    point.has_source = true;
                    point.source_selector_idx = source_selector_idx;
                    point.source_source_kind = MainSelectorPointSourceKind::EccX3Y3;
                    point.source_round_idx = point.round_idx;
                    if let Some(value) = values_by_key.get(&(
                        point.proof_idx,
                        point.idx,
                        point.air_idx,
                        source_selector_idx,
                        point.source_round_idx,
                    )) {
                        point.source_value = *value;
                        source_lookups.push((
                            point.proof_idx,
                            point.idx,
                            point.air_idx,
                            source_selector_idx,
                            point.source_round_idx,
                        ));
                    }
                }
            }
        }
    }
    let mut record_idx_by_key = records
        .iter()
        .enumerate()
        .map(|(idx, record)| {
            (
                (
                    record.proof_idx,
                    record.idx,
                    record.air_idx,
                    record.selector_idx,
                    record.round_idx,
                ),
                idx,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for key in source_lookups {
        if let Some(idx) = record_idx_by_key.remove(&key) {
            records[idx].lookup_count += 1;
            record_idx_by_key.insert(key, idx);
        }
    }
    records.retain(|record| record.lookup_count != 0);
    records
}

fn build_main_ecc_rt_records(
    proofs: &[RecursionProof],
    preflights: &[Preflight],
    tower_idx_by_air: &std::collections::BTreeMap<(usize, usize), usize>,
    selector_point_records: &[MainSelectorPointRecord],
) -> Vec<MainEccRtRecord> {
    let lookup_counts = selector_point_records
        .iter()
        .filter(|record| record.has_ecc_rt)
        .fold(
            std::collections::BTreeMap::<(usize, usize, usize), usize>::new(),
            |mut counts, record| {
                *counts
                    .entry((record.proof_idx, record.tower_idx, record.round_idx))
                    .or_default() += 1;
                counts
            },
        );
    let mut records = Vec::new();
    for (proof_idx, preflight) in preflights.iter().enumerate() {
        let Some(proof) = proofs.get(proof_idx) else {
            continue;
        };
        for chip in &preflight.gkr.chips {
            let Some(ecc_replay) = chip.ecc_replay.as_ref() else {
                continue;
            };
            let Some(ecc_proof) = proof
                .chip_proofs
                .get(&chip.chip_idx)
                .and_then(|chip_proof| chip_proof.ecc_proof.as_ref())
            else {
                continue;
            };
            let Some(idx) = tower_idx_by_air.get(&(proof_idx, chip.chip_idx)).copied() else {
                continue;
            };
            let Some(fork) = preflight.fork_transcripts.get(chip.fork_idx) else {
                continue;
            };
            let fork_values = fork.log.values();
            let num_vars = ecc_replay.rt_tidxs.len();
            if num_vars == 0 {
                continue;
            }
            let out_rt = ecc_replay
                .out_rt_tidxs
                .iter()
                .map(|tidx| {
                    fork_values
                        .get(*tidx..*tidx + D_EF)
                        .and_then(RecursionField::from_basis_coefficients_slice)
                        .unwrap_or(RecursionField::ZERO)
                })
                .collect_vec();
            let rt = ecc_replay
                .rt_tidxs
                .iter()
                .map(|tidx| {
                    fork_values
                        .get(*tidx..*tidx + D_EF)
                        .and_then(RecursionField::from_basis_coefficients_slice)
                        .unwrap_or(RecursionField::ZERO)
                })
                .collect_vec();
            let alpha = fork_values
                .get(ecc_replay.alpha_tidx..ecc_replay.alpha_tidx + D_EF)
                .and_then(RecursionField::from_basis_coefficients_slice)
                .unwrap_or(RecursionField::ZERO);
            let mut alpha_pows = [RecursionField::ZERO; 49];
            let mut pow = RecursionField::ONE;
            for dst in &mut alpha_pows {
                *dst = pow;
                pow *= alpha;
            }
            if ecc_proof.evals.len() < 52 {
                continue;
            }
            let evals = &ecc_proof.evals[3..];
            let to_septic = |start: usize| -> [RecursionField; 7] {
                core::array::from_fn(|i| evals[start + i])
            };
            let s0 = to_septic(0);
            let x0 = to_septic(7);
            let y0 = to_septic(14);
            let x1 = to_septic(21);
            let y1 = to_septic(28);
            let x3 = to_septic(35);
            let y3 = to_septic(42);
            let sum_x = core::array::from_fn(|i| RecursionField::from(ecc_proof.sum.x.0[i]));
            let sum_y = core::array::from_fn(|i| RecursionField::from(ecc_proof.sum.y.0[i]));
            let (add_eval, bypass_eval, export_eval) = native_ecc_equation_evals(
                &s0,
                &x0,
                &y0,
                &x1,
                &y1,
                &x3,
                &y3,
                &sum_x,
                &sum_y,
                &alpha_pows,
            );

            let mut layer_ns = (0..num_vars)
                .scan(ecc_proof.num_instances, |n_instance, _| {
                    let current = *n_instance;
                    *n_instance = (*n_instance).div_ceil(2);
                    Some(current)
                })
                .collect_vec();
            layer_ns.reverse();
            let mut claim = RecursionField::ZERO;
            let mut eq_acc = RecursionField::ONE;
            let mut last_acc = RecursionField::ONE;
            let mut export_out_acc = RecursionField::ONE;
            let mut export_rt_acc = RecursionField::ONE;
            let mut quark_acc = RecursionField::ZERO;
            for (round_idx, tidx) in ecc_replay.rt_tidxs.iter().copied().enumerate() {
                let prover_msg = ecc_proof.zerocheck_proof.proofs.get(round_idx);
                let mut round_evals = [RecursionField::ZERO; 3];
                if let Some(prover_msg) = prover_msg {
                    for (dst, src) in round_evals
                        .iter_mut()
                        .zip(prover_msg.evaluations.iter().copied())
                    {
                        *dst = src;
                    }
                }
                let claim_in = claim;
                let claim_out =
                    extrapolate_uni_poly(claim - round_evals[0], &round_evals, rt[round_idx]);
                claim = claim_out;

                let eq_in = eq_acc;
                eq_acc *= eq_binary_factor(out_rt[round_idx], rt[round_idx]);
                let last_in = last_acc;
                last_acc *= out_rt[round_idx] * rt[round_idx];
                let export_out_in = export_out_acc;
                export_out_acc *= if round_idx == 0 {
                    RecursionField::ONE - out_rt[round_idx]
                } else {
                    out_rt[round_idx]
                };
                let export_rt_in = export_rt_acc;
                export_rt_acc *= if round_idx == 0 {
                    RecursionField::ONE - rt[round_idx]
                } else {
                    rt[round_idx]
                };

                let layer_n = layer_ns[round_idx];
                let prefix_count = layer_n / 2;
                let quark_factor = if prefix_count == 0 {
                    RecursionField::ZERO
                } else if round_idx == 0 {
                    RecursionField::ONE
                } else {
                    native_eq_lte(prefix_count - 1, &out_rt[..round_idx], &rt[..round_idx])
                };
                let lte_witness = build_lte_witness(prefix_count, round_idx, &out_rt, &rt);
                let quark_in = quark_acc;
                quark_acc = (RecursionField::ONE - out_rt[round_idx])
                    * (RecursionField::ONE - rt[round_idx])
                    * quark_factor
                    + out_rt[round_idx] * rt[round_idx] * quark_acc;

                let value = fork_values
                    .get(tidx..tidx + D_EF)
                    .and_then(RecursionField::from_basis_coefficients_slice)
                    .unwrap_or(RecursionField::ZERO);
                records.push(MainEccRtRecord {
                    proof_idx,
                    idx,
                    fork_id: chip.fork_idx,
                    round_idx,
                    num_rounds: ecc_replay.rt_tidxs.len(),
                    is_first: round_idx == 0,
                    is_last: round_idx + 1 == ecc_replay.rt_tidxs.len(),
                    tidx,
                    out_tidx: ecc_replay.out_rt_tidxs.get(round_idx).copied().unwrap_or(0),
                    alpha_tidx: ecc_replay.alpha_tidx,
                    value,
                    out_value: out_rt[round_idx],
                    alpha,
                    alpha_pows,
                    ev1: round_evals[0],
                    ev2: round_evals[1],
                    ev3: round_evals[2],
                    claim_in,
                    claim_out,
                    sel_add: ecc_proof.evals[0],
                    sel_bypass: ecc_proof.evals[1],
                    sel_export: ecc_proof.evals[2],
                    s0,
                    x0,
                    y0,
                    x1,
                    y1,
                    x3,
                    y3,
                    sum_x,
                    sum_y,
                    eq_in,
                    eq_out: eq_acc,
                    last_in,
                    last_out: last_acc,
                    export_out_in,
                    export_out_out: export_out_acc,
                    export_rt_in,
                    export_rt_out: export_rt_acc,
                    quark_in,
                    quark_factor,
                    quark_out: quark_acc,
                    add_eval,
                    bypass_eval,
                    export_eval,
                    lte_out_point: lte_witness.out_point,
                    lte_rt_point: lte_witness.rt_point,
                    lte_prefix_acc: lte_witness.prefix_acc,
                    lte_less_acc: lte_witness.less_acc,
                    lte_bits: lte_witness.bits,
                    lte_active: lte_witness.active,
                    quark_prefix_count: prefix_count,
                    quark_layer_n: layer_n,
                    quark_parity: layer_n % 2 == 1,
                    lookup_count: lookup_counts
                        .get(&(proof_idx, idx, round_idx))
                        .copied()
                        .unwrap_or(0),
                });
            }
        }
    }
    records
}

struct EccLteWitness {
    out_point: [RecursionField; 32],
    rt_point: [RecursionField; 32],
    prefix_acc: [RecursionField; 33],
    less_acc: [RecursionField; 33],
    bits: [bool; 32],
    active: [bool; 32],
}

fn build_lte_witness(
    prefix_count: usize,
    round_idx: usize,
    out_rt: &[RecursionField],
    rt: &[RecursionField],
) -> EccLteWitness {
    let max_idx = prefix_count.saturating_sub(1);
    let out_point = core::array::from_fn(|i| out_rt.get(i).copied().unwrap_or_default());
    let rt_point = core::array::from_fn(|i| rt.get(i).copied().unwrap_or_default());
    let bits = core::array::from_fn(|i| i < round_idx && ((max_idx >> i) & 1) == 1);
    let active = core::array::from_fn(|i| i < round_idx);
    let mut prefix_acc = [RecursionField::ZERO; 33];
    let mut less_acc = [RecursionField::ZERO; 33];
    prefix_acc[32] = RecursionField::ONE;
    for i in (0..32).rev() {
        if active[i] {
            let same_one = out_point[i] * rt_point[i];
            let same_zero =
                (RecursionField::ONE - out_point[i]) * (RecursionField::ONE - rt_point[i]);
            let same_any = same_one + same_zero;
            let equal_choice = if bits[i] { same_one } else { same_zero };
            prefix_acc[i] = prefix_acc[i + 1] * equal_choice;
            less_acc[i] = less_acc[i + 1] * same_any
                + if bits[i] {
                    prefix_acc[i + 1] * same_zero
                } else {
                    RecursionField::ZERO
                };
        } else {
            prefix_acc[i] = prefix_acc[i + 1];
            less_acc[i] = less_acc[i + 1];
        }
    }
    EccLteWitness {
        out_point,
        rt_point,
        prefix_acc,
        less_acc,
        bits,
        active,
    }
}

fn eq_binary_factor(a: RecursionField, b: RecursionField) -> RecursionField {
    a * b + (RecursionField::ONE - a) * (RecursionField::ONE - b)
}

fn native_eq_lte(max_idx: usize, a: &[RecursionField], b: &[RecursionField]) -> RecursionField {
    let mut running_product = Vec::with_capacity(b.len() + 1);
    running_product.push(RecursionField::ONE);
    for i in 0..b.len() {
        running_product.push(running_product[i] * eq_binary_factor(a[i], b[i]));
    }
    let mut running_product2 = vec![RecursionField::ZERO; b.len() + 1];
    running_product2[b.len()] = RecursionField::ONE;
    for i in (0..b.len()).rev() {
        let bit = RecursionField::from_usize((max_idx >> i) & 1);
        running_product2[i] = running_product2[i + 1]
            * (a[i] * b[i] * bit
                + (RecursionField::ONE - a[i])
                    * (RecursionField::ONE - b[i])
                    * (RecursionField::ONE - bit));
    }
    let mut ans = running_product[b.len()];
    for i in 0..b.len() {
        if ((max_idx >> i) & 1) == 0 {
            ans -= running_product[i] * running_product2[i + 1] * a[i] * b[i];
        }
    }
    ans
}

#[allow(clippy::too_many_arguments)]
fn native_ecc_equation_evals(
    s0: &[RecursionField; 7],
    x0: &[RecursionField; 7],
    y0: &[RecursionField; 7],
    x1: &[RecursionField; 7],
    y1: &[RecursionField; 7],
    x3: &[RecursionField; 7],
    y3: &[RecursionField; 7],
    sum_x: &[RecursionField; 7],
    sum_y: &[RecursionField; 7],
    alpha_pows: &[RecursionField; 49],
) -> (RecursionField, RecursionField, RecursionField) {
    let mut add_eval = RecursionField::ZERO;
    let mut bypass_eval = RecursionField::ZERO;
    let mut export_eval = RecursionField::ZERO;
    let s0_x0_x1 = native_septic_mul(s0, &core::array::from_fn(|i| x0[i] - x1[i]));
    let s0_squared = native_septic_mul(s0, s0);
    let s0_x0_x3 = native_septic_mul(s0, &core::array::from_fn(|i| x0[i] - x3[i]));
    for i in 0..7 {
        let v1 = s0_x0_x1[i] - (y0[i] - y1[i]);
        let v2 = s0_squared[i] - x0[i] - x1[i] - x3[i];
        let v3 = s0_x0_x3[i] - (y0[i] + y3[i]);
        let v4 = x3[i] - x0[i];
        let v5 = y3[i] - y0[i];
        add_eval += v1 * alpha_pows[i] + v2 * alpha_pows[7 + i] + v3 * alpha_pows[14 + i];
        bypass_eval += v4 * alpha_pows[21 + i] + v5 * alpha_pows[28 + i];
        export_eval +=
            (x3[i] - sum_x[i]) * alpha_pows[35 + i] + (y3[i] - sum_y[i]) * alpha_pows[42 + i];
    }
    (add_eval, bypass_eval, export_eval)
}

fn native_septic_mul(a: &[RecursionField; 7], b: &[RecursionField; 7]) -> [RecursionField; 7] {
    let mut out = [RecursionField::ZERO; 7];
    let two = RecursionField::from_usize(2);
    let five = RecursionField::from_usize(5);
    for i in 0..7 {
        for j in 0..7 {
            let term = a[i] * b[j];
            let mut index = i + j;
            if index < 7 {
                out[index] += term;
            } else {
                index -= 7;
                out[index] += five * term;
                out[index + 1] += two * term;
            }
        }
    }
    out
}

fn rotation_point_source(
    source_kind: MainSelectorPointSourceKind,
    rotation_cyclic_group_log2: usize,
    round_idx: usize,
) -> (MainSelectorPointDeriveKind, usize) {
    match (source_kind, rotation_cyclic_group_log2, round_idx) {
        (MainSelectorPointSourceKind::RotationLeft, _, 0) => (MainSelectorPointDeriveKind::Zero, 0),
        (MainSelectorPointSourceKind::RotationLeft, g, round) if round < g => {
            (MainSelectorPointDeriveKind::Identity, round - 1)
        }
        (MainSelectorPointSourceKind::RotationLeft, _, round) => {
            (MainSelectorPointDeriveKind::Identity, round)
        }
        (MainSelectorPointSourceKind::RotationRight, _, 0) => (MainSelectorPointDeriveKind::One, 0),
        (MainSelectorPointSourceKind::RotationRight, 5, 2)
        | (MainSelectorPointSourceKind::RotationRight, 6, 1) => {
            (MainSelectorPointDeriveKind::OneMinus, round_idx - 1)
        }
        (MainSelectorPointSourceKind::RotationRight, g, round) if round < g => {
            (MainSelectorPointDeriveKind::Identity, round - 1)
        }
        (MainSelectorPointSourceKind::RotationRight, _, round) => {
            (MainSelectorPointDeriveKind::Identity, round)
        }
        _ => (MainSelectorPointDeriveKind::Identity, round_idx),
    }
}

fn build_main_tower_point_eq_records(
    layers: &[MainReplayLayer<'_>],
    global_in_point: &[RecursionField],
) -> Vec<MainTowerPointEqRecord> {
    let mut records = Vec::new();
    for (idx, layer) in layers.iter().enumerate() {
        for round_idx in 0..layer.num_var_with_rotation {
            records.push(MainTowerPointEqRecord {
                proof_idx: 0,
                idx,
                round_idx,
                global_value: global_in_point[round_idx],
                tower_value: RecursionField::ZERO,
                eq_in: RecursionField::ZERO,
                eq_out: RecursionField::ZERO,
            });
        }
    }
    records
}

fn build_main_selector_eval_records(
    layers: &[MainReplayLayer<'_>],
    main_evals: &[RecursionField],
    global_in_point: &[RecursionField],
) -> Result<Vec<MainSelectorEvalRecord>> {
    let mut records = Vec::new();
    for (idx, layer) in layers.iter().enumerate() {
        let structural_witin_offset = layer.layer.n_witin + layer.layer.n_fixed;
        let in_point = global_in_point[..layer.num_var_with_rotation].to_vec();
        if in_point.len() > MAX_SELECTOR_POINT_VARS {
            bail!(
                "{} selector point width {} exceeds AIR cap {}",
                layer.layer.name,
                in_point.len(),
                MAX_SELECTOR_POINT_VARS
            );
        }
        for (selector_idx, (((sel_type, _), (_, out_point)), selector_ctx)) in layer
            .layer
            .out_sel_and_eval_exprs
            .iter()
            .zip(layer.eval_and_dedup_points.iter())
            .zip(layer.selector_ctxs.iter())
            .enumerate()
        {
            if matches!(sel_type, gkr_iop::selector::SelectorType::None) {
                bail!(
                    "{} selector group {selector_idx} uses SelectorType::None; migrate this selector before proving recursion-v2 main",
                    layer.layer.name
                );
            }
            let (kind, ordered_sparse_num_vars, sparse_indices, wit_id) = selector_shape(sel_type)?;
            if sparse_indices.len() > MAX_SELECTOR_SPARSE_INDICES {
                bail!(
                    "{} selector group {selector_idx} sparse index count {} exceeds AIR cap {}",
                    layer.layer.name,
                    sparse_indices.len(),
                    MAX_SELECTOR_SPARSE_INDICES
                );
            }
            let eval_idx = wit_id as usize + structural_witin_offset;
            let Some(out_point) = out_point.as_ref() else {
                records.push(MainSelectorEvalRecord {
                    proof_idx: 0,
                    idx,
                    tower_idx: 0,
                    air_idx: layer.air_idx,
                    selector_idx,
                    has_eval: false,
                    eval_idx,
                    kind,
                    ctx_offset: selector_ctx.offset,
                    ctx_num_instances: selector_ctx.num_instances,
                    ctx_num_vars: selector_ctx.num_vars,
                    ordered_sparse_num_vars,
                    sparse_indices,
                    in_point: Vec::new(),
                    out_point: Vec::new(),
                    point_source: layer.selector_point_sources[selector_idx],
                    fork_id: layer.fork_id,
                    rotation_cyclic_group_log2: layer.rotation_cyclic_group_log2,
                    rotation_origin_selector_idx: layer.rotation_origin_selector_idx,
                    rotation_origin_tidxs: layer.rotation_origin_tidxs.clone(),
                    ecc_sample_tidx: layer.ecc_sample_tidx,
                    ecc_rt_tidxs: layer.ecc_rt_tidxs.clone(),
                    ecc_xy_selector_idx: layer.ecc_xy_selector_idx,
                    ecc_x3y3_selector_idx: layer.ecc_x3y3_selector_idx,
                    value: RecursionField::ZERO,
                });
                continue;
            };
            if out_point.len() > MAX_SELECTOR_POINT_VARS {
                bail!(
                    "{} selector output point width {} exceeds AIR cap {}",
                    layer.layer.name,
                    out_point.len(),
                    MAX_SELECTOR_POINT_VARS
                );
            }
            let Some((expected_eval, evaluated_wit_id)) =
                sel_type.evaluate(out_point, &in_point, selector_ctx)
            else {
                records.push(MainSelectorEvalRecord {
                    proof_idx: 0,
                    idx,
                    tower_idx: 0,
                    air_idx: layer.air_idx,
                    selector_idx,
                    has_eval: false,
                    eval_idx,
                    kind,
                    ctx_offset: selector_ctx.offset,
                    ctx_num_instances: selector_ctx.num_instances,
                    ctx_num_vars: selector_ctx.num_vars,
                    ordered_sparse_num_vars,
                    sparse_indices,
                    in_point: Vec::new(),
                    out_point: Vec::new(),
                    point_source: layer.selector_point_sources[selector_idx],
                    fork_id: layer.fork_id,
                    rotation_cyclic_group_log2: layer.rotation_cyclic_group_log2,
                    rotation_origin_selector_idx: layer.rotation_origin_selector_idx,
                    rotation_origin_tidxs: layer.rotation_origin_tidxs.clone(),
                    ecc_sample_tidx: layer.ecc_sample_tidx,
                    ecc_rt_tidxs: layer.ecc_rt_tidxs.clone(),
                    ecc_xy_selector_idx: layer.ecc_xy_selector_idx,
                    ecc_x3y3_selector_idx: layer.ecc_x3y3_selector_idx,
                    value: RecursionField::ZERO,
                });
                continue;
            };
            if evaluated_wit_id != wit_id {
                bail!(
                    "{} selector group {selector_idx} witness id mismatch: shape {wit_id} evaluate {evaluated_wit_id}",
                    layer.layer.name
                );
            }
            let Some(_actual_eval) = main_evals.get(layer.eval_start + eval_idx).copied() else {
                bail!("main selector structural witin index {eval_idx} out of range");
            };
            records.push(MainSelectorEvalRecord {
                proof_idx: 0,
                idx,
                tower_idx: 0,
                air_idx: layer.air_idx,
                selector_idx,
                has_eval: true,
                eval_idx,
                kind,
                ctx_offset: selector_ctx.offset,
                ctx_num_instances: selector_ctx.num_instances,
                ctx_num_vars: selector_ctx.num_vars,
                ordered_sparse_num_vars,
                sparse_indices,
                in_point: in_point.clone(),
                out_point: out_point.clone(),
                point_source: layer.selector_point_sources[selector_idx],
                fork_id: layer.fork_id,
                rotation_cyclic_group_log2: layer.rotation_cyclic_group_log2,
                rotation_origin_selector_idx: layer.rotation_origin_selector_idx,
                rotation_origin_tidxs: layer.rotation_origin_tidxs.clone(),
                ecc_sample_tidx: layer.ecc_sample_tidx,
                ecc_rt_tidxs: layer.ecc_rt_tidxs.clone(),
                ecc_xy_selector_idx: layer.ecc_xy_selector_idx,
                ecc_x3y3_selector_idx: layer.ecc_x3y3_selector_idx,
                value: expected_eval,
            });
        }
    }
    Ok(records)
}

fn selector_shape(
    sel_type: &gkr_iop::selector::SelectorType<RecursionField>,
) -> Result<(
    MainSelectorKind,
    usize,
    Vec<usize>,
    multilinear_extensions::WitnessId,
)> {
    use gkr_iop::selector::SelectorType;
    let (kind, ordered_sparse_num_vars, sparse_indices, expr) = match sel_type {
        SelectorType::None => bail!("SelectorType::None is not supported in recursion-v2 main"),
        SelectorType::Whole(expr) => (MainSelectorKind::Whole, 0, Vec::new(), expr),
        SelectorType::Prefix(expr) => (MainSelectorKind::Prefix, 0, Vec::new(), expr),
        SelectorType::OrderedSparse {
            num_vars,
            indices,
            expression,
        } => (
            MainSelectorKind::OrderedSparse,
            *num_vars,
            indices.clone(),
            expression,
        ),
        SelectorType::QuarkBinaryTreeLessThan(expr) => (
            MainSelectorKind::QuarkBinaryTreeLessThan,
            0,
            Vec::new(),
            expr,
        ),
    };
    let Expression::StructuralWitIn(wit_id, _) = expr else {
        bail!("selector expression must be StructuralWitIn");
    };
    Ok((kind, ordered_sparse_num_vars, sparse_indices, *wit_id))
}

fn build_final_claim_records(
    layers: &[MainReplayLayer<'_>],
    main_evals: &[RecursionField],
    pcs_challenges: &[RecursionField; 2],
    alpha_pows: &[RecursionField],
    global_in_point: &[RecursionField],
    expected_evaluation: RecursionField,
) -> Result<(
    RecursionField,
    Vec<MainFrontloadTermRecord>,
    Vec<MainFinalClaimRecord>,
)> {
    let mut acc = RecursionField::ZERO;
    let mut frontload_records = Vec::new();
    let mut records = Vec::with_capacity(layers.len());
    for (idx, layer) in layers.iter().enumerate() {
        let layer_evals = &main_evals[layer.eval_start..layer.eval_start + layer.eval_len];
        validate_direct_structural_evals(layer, layer_evals, global_in_point)?;
        let main_sumcheck_challenges = chain!(
            pcs_challenges.iter().copied(),
            alpha_pows[layer.alpha_start..layer.alpha_start + layer.layer.exprs.len()]
                .iter()
                .copied()
        )
        .collect_vec();
        let terms = layer
            .layer
            .main_sumcheck_expression_monomial_terms
            .as_ref()
            .ok_or_else(|| eyre!("missing main sumcheck expression monomial terms"))?;
        let contribution = build_frontload_term_records_for_layer(
            idx,
            layer,
            layer_evals,
            &layer.pi,
            &main_sumcheck_challenges,
            global_in_point,
            terms,
            &mut frontload_records,
        )?;
        let monomial_contribution = eval_batched_main_frontload_terms_oracle(
            layer_evals,
            &layer.pi,
            &main_sumcheck_challenges,
            global_in_point,
            layer.num_var_with_rotation,
            terms,
        );
        if contribution != monomial_contribution {
            bail!(
                "layer monomial contribution mismatch at chip {idx}: {monomial_contribution} != {contribution}"
            );
        }
        let acc_in = acc;
        acc += contribution;
        records.push(MainFinalClaimRecord {
            proof_idx: 0,
            idx,
            contribution,
            acc_in,
            acc_out: acc,
            expected: expected_evaluation,
        });
    }
    Ok((acc, frontload_records, records))
}

fn validate_direct_structural_evals(
    layer: &MainReplayLayer<'_>,
    layer_evals: &[RecursionField],
    global_in_point: &[RecursionField],
) -> Result<()> {
    let structural_witin_offset = layer.layer.n_witin + layer.layer.n_fixed;
    let in_point = global_in_point[..layer.num_var_with_rotation].to_vec();
    for (((sel_type, _), (_, out_point)), selector_ctx) in layer
        .layer
        .out_sel_and_eval_exprs
        .iter()
        .zip(layer.eval_and_dedup_points.iter())
        .zip(layer.selector_ctxs.iter())
    {
        let Some(out_point) = out_point.as_ref() else {
            continue;
        };
        if let Some((_expected_eval, wit_id)) =
            sel_type.evaluate(out_point, &in_point, selector_ctx)
        {
            let wit_id = wit_id as usize + structural_witin_offset;
            let Some(_actual_eval) = layer_evals.get(wit_id).copied() else {
                bail!("main selector structural witin index {wit_id} out of range");
            };
        }
    }
    for StructuralWitIn { id, witin_type } in &layer.layer.structural_witins {
        let wit_id = *id as usize + structural_witin_offset;
        let Some(actual_eval) = layer_evals.get(wit_id).copied() else {
            bail!("main structural witin index {wit_id} out of range");
        };
        let expected_eval = match witin_type {
            EqualDistanceSequence {
                offset,
                multi_factor,
                descending,
                ..
            } => gkr_iop::utils::eval_wellform_address_vec(
                *offset as u64,
                *multi_factor as u64,
                &in_point,
                *descending,
            ),
            EqualDistanceDynamicSequence {
                offset_instance_id,
                multi_factor,
                descending,
                ..
            } => {
                let offset = layer.pi[*offset_instance_id as usize].to_canonical_u64();
                gkr_iop::utils::eval_wellform_address_vec(
                    offset,
                    *multi_factor as u64,
                    &in_point,
                    *descending,
                )
            }
            StackedIncrementalSequence { .. } => {
                gkr_iop::utils::eval_stacked_wellform_address_vec(&in_point)
            }
            StackedConstantSequence { .. } => gkr_iop::utils::eval_stacked_constant_vec(&in_point),
            InnerRepeatingIncrementalSequence { k, .. } => {
                gkr_iop::utils::eval_inner_repeated_incremental_vec(*k as u64, &in_point)
            }
            OuterRepeatingIncrementalSequence { k, .. } => {
                gkr_iop::utils::eval_outer_repeated_incremental_vec(*k as u64, &in_point)
            }
            Empty => continue,
        };
        if actual_eval != expected_eval {
            bail!(
                "{} structural witin mismatch: {expected_eval} != {actual_eval}",
                layer.layer.name
            );
        }
    }
    Ok(())
}

fn build_frontload_term_records_for_layer(
    idx: usize,
    layer: &MainReplayLayer<'_>,
    layer_evals: &[RecursionField],
    pi: &[RecursionField],
    challenges: &[RecursionField],
    global_in_point: &[RecursionField],
    terms: &[multilinear_extensions::monomial::Term<
        Expression<RecursionField>,
        Expression<RecursionField>,
    >],
    records: &mut Vec<MainFrontloadTermRecord>,
) -> Result<RecursionField> {
    let tail_start = layer.num_var_with_rotation;
    let tail_point = &global_in_point[tail_start..];
    let mut row_idx = 0usize;
    let mut node_idx = 0usize;
    let mut layer_acc = RecursionField::ZERO;

    for (term_idx, term) in terms.iter().enumerate() {
        let mut term_value = emit_scalar_expr_row(
            idx,
            term_idx,
            &term.scalar,
            pi,
            challenges,
            records,
            &mut row_idx,
            &mut node_idx,
        )?;

        for expr in &term.product {
            let Expression::WitIn(wit_id) = expr else {
                bail!("main monomial product must be converted to WitIn");
            };
            let eval_idx = *wit_id as usize;
            let raw_eval = *layer_evals
                .get(eval_idx)
                .ok_or_else(|| eyre!("main monomial wit index {eval_idx} out of range"))?;
            let weighted_eval = emit_monomial_wit_factor_rows(
                idx,
                term_idx,
                eval_idx,
                raw_eval,
                tail_start,
                tail_point,
                records,
                &mut row_idx,
                &mut node_idx,
            );
            let next = term_value * weighted_eval;
            records.push(MainFrontloadTermRecord {
                proof_idx: 0,
                idx,
                row_idx,
                node_idx,
                is_mul: true,
                constraint_idx: term_idx,
                arg0: term_value,
                arg1: weighted_eval,
                value: next,
                ..MainFrontloadTermRecord::default()
            });
            row_idx += 1;
            node_idx += 1;
            term_value = next;
        }

        let next_acc = layer_acc + term_value;
        records.push(MainFrontloadTermRecord {
            proof_idx: 0,
            idx,
            row_idx,
            node_idx,
            is_fold: true,
            constraint_idx: term_idx,
            alpha: RecursionField::ONE,
            arg0: term_value,
            value: next_acc,
            chip_acc_in: layer_acc,
            chip_acc_out: next_acc,
            is_last_chip_step: term_idx + 1 == terms.len(),
            ..MainFrontloadTermRecord::default()
        });
        row_idx += 1;
        node_idx += 1;
        layer_acc = next_acc;
    }

    if terms.is_empty() {
        records.push(MainFrontloadTermRecord {
            proof_idx: 0,
            idx,
            row_idx,
            node_idx,
            is_fold: true,
            alpha: RecursionField::ONE,
            arg0: RecursionField::ZERO,
            value: RecursionField::ZERO,
            chip_acc_in: RecursionField::ZERO,
            chip_acc_out: RecursionField::ZERO,
            is_last_chip_step: true,
            ..MainFrontloadTermRecord::default()
        });
    }

    Ok(layer_acc)
}

fn emit_scalar_expr_row(
    idx: usize,
    term_idx: usize,
    expr: &Expression<RecursionField>,
    pi: &[RecursionField],
    challenges: &[RecursionField],
    records: &mut Vec<MainFrontloadTermRecord>,
    row_idx: &mut usize,
    node_idx: &mut usize,
) -> Result<RecursionField> {
    let this_node = *node_idx;
    *node_idx += 1;
    let mut record = MainFrontloadTermRecord {
        proof_idx: 0,
        idx,
        row_idx: *row_idx,
        node_idx: this_node,
        constraint_idx: term_idx,
        ..MainFrontloadTermRecord::default()
    };

    let value = match expr {
        Expression::WitIn(_) | Expression::StructuralWitIn(_, _) | Expression::Fixed(_) => {
            bail!("main monomial scalar must not contain witness-backed expressions")
        }
        Expression::Instance(instance) | Expression::InstanceScalar(instance) => {
            let value = *pi
                .get(instance.0 as usize)
                .ok_or_else(|| eyre!("main scalar instance index {} out of range", instance.0))?;
            record.is_instance = true;
            record.instance_idx = instance.0 as usize;
            record.arg0 = value;
            value
        }
        Expression::Constant(value) => {
            let value = either_to_ext(*value);
            record.is_const = true;
            record.arg0 = value;
            value
        }
        Expression::Challenge(ch_id, pow, scalar, offset) => {
            let challenge_idx = *ch_id as usize;
            let challenge = *challenges
                .get(challenge_idx)
                .ok_or_else(|| eyre!("main scalar challenge index {challenge_idx} out of range"))?;
            let value = challenge.exp_u64(*pow as u64) * *scalar + *offset;
            record.is_challenge = true;
            record.challenge_idx = challenge_idx;
            record.arg0 = value;
            value
        }
        Expression::Sum(left, right) => {
            let left = emit_scalar_expr_row(
                idx, term_idx, left, pi, challenges, records, row_idx, node_idx,
            )?;
            let right = emit_scalar_expr_row(
                idx, term_idx, right, pi, challenges, records, row_idx, node_idx,
            )?;
            record.is_add = true;
            record.arg0 = left;
            record.arg1 = right;
            left + right
        }
        Expression::Product(left, right) => {
            let left = emit_scalar_expr_row(
                idx, term_idx, left, pi, challenges, records, row_idx, node_idx,
            )?;
            let right = emit_scalar_expr_row(
                idx, term_idx, right, pi, challenges, records, row_idx, node_idx,
            )?;
            record.is_mul = true;
            record.arg0 = left;
            record.arg1 = right;
            left * right
        }
        Expression::ScaledSum(x, a, b) => {
            let x =
                emit_scalar_expr_row(idx, term_idx, x, pi, challenges, records, row_idx, node_idx)?;
            let a =
                emit_scalar_expr_row(idx, term_idx, a, pi, challenges, records, row_idx, node_idx)?;
            let b =
                emit_scalar_expr_row(idx, term_idx, b, pi, challenges, records, row_idx, node_idx)?;
            let mul_node = *node_idx;
            *node_idx += 1;
            records.push(MainFrontloadTermRecord {
                proof_idx: 0,
                idx,
                row_idx: *row_idx,
                node_idx: mul_node,
                is_mul: true,
                constraint_idx: term_idx,
                arg0: a,
                arg1: x,
                value: a * x,
                ..MainFrontloadTermRecord::default()
            });
            *row_idx += 1;
            record.is_add = true;
            record.arg0 = a * x;
            record.arg1 = b;
            a * x + b
        }
    };

    record.value = value;
    record.chip_acc_out = record.chip_acc_in;
    records.push(record);
    *row_idx += 1;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
fn emit_monomial_wit_factor_rows(
    idx: usize,
    term_idx: usize,
    eval_idx: usize,
    mut acc: RecursionField,
    tail_start: usize,
    tail_point: &[RecursionField],
    records: &mut Vec<MainFrontloadTermRecord>,
    row_idx: &mut usize,
    node_idx: &mut usize,
) -> RecursionField {
    records.push(MainFrontloadTermRecord {
        proof_idx: 0,
        idx,
        row_idx: *row_idx,
        node_idx: *node_idx,
        eval_idx,
        has_eval_factor: true,
        is_wit: true,
        constraint_idx: term_idx,
        arg0: acc,
        value: acc,
        ..MainFrontloadTermRecord::default()
    });
    *row_idx += 1;
    *node_idx += 1;

    for (tail_offset, tail_value) in tail_point.iter().copied().enumerate() {
        let next = acc * tail_value;
        records.push(MainFrontloadTermRecord {
            proof_idx: 0,
            idx,
            row_idx: *row_idx,
            node_idx: *node_idx,
            global_round_idx: tail_start + tail_offset,
            has_global_factor: true,
            is_tail: true,
            constraint_idx: term_idx,
            arg0: tail_value,
            arg1: acc,
            value: next,
            chip_acc_out: next,
            ..MainFrontloadTermRecord::default()
        });
        *row_idx += 1;
        *node_idx += 1;
        acc = next;
    }
    acc
}

fn eval_batched_main_frontload_terms_oracle(
    layer_evals: &[RecursionField],
    pi: &[RecursionField],
    challenges: &[RecursionField],
    global_in_point: &[RecursionField],
    num_var_with_rotation: usize,
    terms: &[multilinear_extensions::monomial::Term<
        Expression<RecursionField>,
        Expression<RecursionField>,
    >],
) -> RecursionField {
    let tail_point = &global_in_point[num_var_with_rotation..];
    let mut acc = RecursionField::ZERO;
    for term in terms {
        let mut value = either_to_ext(eval_by_expr_with_instance(
            &[],
            &[],
            &[],
            pi,
            challenges,
            &term.scalar,
        ));
        for expr in &term.product {
            let Expression::WitIn(wit_id) = expr else {
                panic!("main monomial product must be converted to WitIn")
            };
            value *= layer_evals[*wit_id as usize];
            for tail in tail_point {
                value *= *tail;
            }
        }
        acc += value;
    }
    acc
}

fn either_to_ext(
    value: Either<<RecursionField as ff_ext::ExtensionField>::BaseField, RecursionField>,
) -> RecursionField {
    match value {
        Either::Left(base) => RecursionField::from(base),
        Either::Right(ext) => ext,
    }
}

fn sample_challenge_pows<TS>(ts: &mut TS, size: usize, label: &[u8]) -> Vec<RecursionField>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    transcript_observe_label(ts, label);
    let alpha = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
    iter::successors(Some(RecursionField::ONE), move |prev| Some(*prev * alpha))
        .take(size)
        .collect()
}

fn sample_challenge_pows_with_tidx<TS>(
    ts: &mut TS,
    size: usize,
    label: &[u8],
) -> (Vec<RecursionField>, usize)
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    transcript_observe_label(ts, label);
    let tidx = ts.len();
    let alpha = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
    let pows = iter::successors(Some(RecursionField::ONE), move |prev| Some(*prev * alpha))
        .take(size)
        .collect();
    (pows, tidx)
}

fn replay_main_sumcheck<TS>(
    ts: &mut TS,
    claimed_sum: RecursionField,
    proof: &sumcheck::structs::IOPProof<RecursionField>,
    max_num_variables: usize,
    max_degree: usize,
) -> Result<(Vec<RecursionField>, RecursionField, Vec<usize>)>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    if max_num_variables == 0 {
        return Ok((vec![], claimed_sum, vec![]));
    }

    transcript_observe_label(ts, &max_num_variables.to_le_bytes());
    transcript_observe_label(ts, &max_degree.to_le_bytes());
    let mut challenges = Vec::with_capacity(max_num_variables);
    let mut challenge_tidxs = Vec::with_capacity(max_num_variables);
    let mut expected = claimed_sum;
    for round in 0..max_num_variables {
        let prover_msg = proof
            .proofs
            .get(round)
            .ok_or_else(|| eyre!("main sumcheck proof is incomplete"))?;
        if prover_msg.evaluations.len() != max_degree {
            bail!(
                "main sumcheck round {round} eval count {} != {max_degree}",
                prover_msg.evaluations.len()
            );
        }
        for eval in &prover_msg.evaluations {
            ts.observe_ext(*eval);
        }
        transcript_observe_label(ts, b"Internal round");
        let challenge_tidx = ts.len();
        let challenge = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        let eval_0 = expected - prover_msg.evaluations[0];
        expected = extrapolate_uni_poly(eval_0, &prover_msg.evaluations, challenge);
        challenges.push(challenge);
        challenge_tidxs.push(challenge_tidx);
    }
    Ok((challenges, expected, challenge_tidxs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecc_x3y3_selector_eval_record(selector_idx: usize) -> MainSelectorEvalRecord {
        MainSelectorEvalRecord {
            proof_idx: 0,
            idx: 0,
            air_idx: 7,
            selector_idx,
            has_eval: true,
            kind: MainSelectorKind::Whole,
            ctx_num_vars: 3,
            out_point: vec![
                RecursionField::from_usize(11),
                RecursionField::from_usize(13),
                RecursionField::ONE,
            ],
            point_source: MainSelectorPointSourceKind::EccX3Y3,
            ecc_rt_tidxs: vec![100, 104],
            ecc_x3y3_selector_idx: Some(10),
            ..Default::default()
        }
    }

    #[test]
    fn ecc_x3y3_rt_coordinates_are_bound_to_ecc_sumcheck_challenges_once() {
        let records = build_main_selector_point_records(
            &[
                ecc_x3y3_selector_eval_record(10),
                ecc_x3y3_selector_eval_record(11),
            ],
            &std::collections::BTreeMap::new(),
        );

        let find = |selector_idx, round_idx| {
            records
                .iter()
                .find(|record| record.selector_idx == selector_idx && record.round_idx == round_idx)
                .expect("selector point record exists")
        };

        let canonical_r0 = find(10, 0);
        assert!(!canonical_r0.has_transcript);
        assert!(canonical_r0.has_ecc_rt);
        assert_eq!(canonical_r0.transcript_tidx, 100);
        assert!(!canonical_r0.has_source);

        let canonical_r1 = find(10, 1);
        assert!(!canonical_r1.has_transcript);
        assert!(canonical_r1.has_ecc_rt);
        assert_eq!(canonical_r1.transcript_tidx, 104);
        assert!(!canonical_r1.has_source);

        let sibling_r0 = find(11, 0);
        assert!(!sibling_r0.has_transcript);
        assert!(sibling_r0.has_source);
        assert_eq!(sibling_r0.source_selector_idx, 10);
        assert_eq!(
            sibling_r0.source_source_kind,
            MainSelectorPointSourceKind::EccX3Y3
        );
        assert_eq!(sibling_r0.source_round_idx, 0);

        let sibling_r1 = find(11, 1);
        assert!(!sibling_r1.has_transcript);
        assert!(sibling_r1.has_source);
        assert_eq!(sibling_r1.source_selector_idx, 10);
        assert_eq!(
            sibling_r1.source_source_kind,
            MainSelectorPointSourceKind::EccX3Y3
        );
        assert_eq!(sibling_r1.source_round_idx, 1);

        assert_eq!(find(10, 2).derive_kind, MainSelectorPointDeriveKind::One);
        assert_eq!(find(11, 2).derive_kind, MainSelectorPointDeriveKind::One);
    }
}
