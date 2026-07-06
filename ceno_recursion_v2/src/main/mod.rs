mod air;
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
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use sumcheck::util::extrapolate_uni_poly;
use witness::next_pow2_instance_padding;

use self::{
    air::MainAir,
    selector::{
        MAX_SELECTOR_POINT_VARS, MAX_SELECTOR_SPARSE_INDICES, MainSelectorEvalAir,
        MainSelectorEvalTraceGenerator, MainSelectorFormulaAir, MainSelectorFormulaTraceGenerator,
    },
    trace::{MainRecord, MainTraceGenerator},
    transcript_bind::{MainTranscriptBindAir, MainTranscriptBindTraceGenerator},
};
use crate::{
    bus::{
        AirPresenceBus, ForkedTranscriptBus, MainBus, MainEvalBus, MainExpressionClaimBus,
        MainGlobalPointBus, MainSelectorResultBus, MainSelectorShapeBus,
        MainSelectorSparseIndexShapeBus, TranscriptBus,
    },
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, MainEvalRecord,
        MainFinalClaimRecord, MainFrontloadTermRecord, MainSelectorEvalRecord, MainSelectorKind,
        MainTowerPointEqRecord, Preflight, RecursionField, RecursionProof, RecursionVk,
        RotationReplayClaims, TraceGenModule,
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
    main_selector_result_bus: MainSelectorResultBus,
    main_selector_shape_bus: MainSelectorShapeBus,
    main_selector_sparse_index_shape_bus: MainSelectorSparseIndexShapeBus,
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
        let main_selector_result_bus = bus_inventory.main_selector_result_bus;
        let main_selector_shape_bus = bus_inventory.main_selector_shape_bus;
        let main_selector_sparse_index_shape_bus =
            bus_inventory.main_selector_sparse_index_shape_bus;
        Self {
            main_bus,
            expression_claim_bus,
            transcript_bus,
            forked_transcript_bus,
            air_presence_bus,
            main_global_point_bus,
            main_eval_bus,
            main_selector_result_bus,
            main_selector_shape_bus,
            main_selector_sparse_index_shape_bus,
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
        for input in tower_input_records
            .iter()
            .filter(|record| record.n_logup != 0)
        {
            let tidx = main_tidx_from_tower_input(input);
            main_records.push(MainRecord {
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
            if preflight.main.global_sumchecks.len() > 1
                && std::env::var_os("CENO_REC_V2_DEBUG_MAIN").is_some()
            {
                eprintln!(
                    "rec-v2-debug module=main source=collect proof_idx={proof_idx} key=global_sumcheck_records value={}",
                    preflight.main.global_sumchecks.len()
                );
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
        for record in &selector_eval_records {
            if !record.has_eval {
                continue;
            }
            for round_idx in 0..record.ctx_num_vars.min(selector::MAX_SELECTOR_POINT_VARS) {
                *global_lookup_counts
                    .entry((record.proof_idx, round_idx))
                    .or_default() += 1;
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
        for record in &mut eval_records {
            record.lookup_count = eval_lookup_counts
                .get(&(record.proof_idx, record.idx, record.eval_idx))
                .copied()
                .unwrap_or(0);
        }
        for global in &mut global_sumcheck_records {
            for (round_idx, round) in global.rounds.iter_mut().enumerate() {
                round.point_lookup_count = global_lookup_counts
                    .get(&(global.proof_idx, round_idx))
                    .copied()
                    .unwrap_or(0);
            }
        }
        if std::env::var_os("CENO_REC_V2_DEBUG_MAIN").is_some() {
            for global in &global_sumcheck_records {
                let final_expected = final_claim_records
                    .iter()
                    .find(|record| record.proof_idx == global.proof_idx)
                    .map(|record| record.expected);
                eprintln!(
                    "rec-v2-debug module=main source=collect proof_idx={} key=global_expected value={:?} final_expected={:?} global_rows={}",
                    global.proof_idx,
                    global.expected,
                    final_expected,
                    global.total_rows()
                );
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
            let values = preflight.transcript.values();
            let samples = preflight.transcript.samples();
            for tidx in preflight.main.transcript_start..preflight.main.transcript_end {
                if eval_tidxs.contains(&tidx) || global_challenge_tidxs.contains(&tidx) {
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
    pub(crate) tower_point_eq_records: Vec<MainTowerPointEqRecord>,
    pub(crate) frontload_term_records: Vec<MainFrontloadTermRecord>,
    pub(crate) final_claim_records: Vec<MainFinalClaimRecord>,
    pub(crate) transcript_records: Vec<crate::system::MainTranscriptRecord>,
}

impl AirModule for MainModule {
    fn num_airs(&self) -> usize {
        4
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
            Arc::new(MainSelectorFormulaAir {
                global_point_bus: self.main_global_point_bus,
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
        transcript_records.sort_by_key(|record| (record.proof_idx, record.tidx));
        let ctx = MainTraceCtx {
            main_records: &main_records,
            selector_eval_records: &selector_eval_records,
            transcript_records: &transcript_records,
        };
        let chips = [
            MainModuleChip::Main,
            MainModuleChip::TranscriptBind,
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
    transcript_records: &'a [crate::system::MainTranscriptRecord],
}

enum MainModuleChip {
    Main,
    TranscriptBind,
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
) -> Result<Option<RotationReplayClaims>>
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

    if composed_cs.has_ecc_ops() {
        let ecc_proof = chip_proof
            .ecc_proof
            .as_ref()
            .ok_or_else(|| eyre!("{name} missing ecc proof"))?;
        let num_vars = ceil_log2(next_pow2_instance_padding(ecc_proof.num_instances));
        sample_vec(ts, b"ecc", num_vars);
        let _alpha_pows = sample_challenge_pows(
            ts,
            7 * ceno_zkvm::scheme::constants::SEPTIC_EXTENSION_DEGREE,
            b"ecc_alpha",
        );
        let _ = replay_main_sumcheck(
            ts,
            RecursionField::ZERO,
            &ecc_proof.zerocheck_proof,
            num_vars,
            3,
        )?;
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
        return Ok(None);
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

    let rotation_challenges = chain!(
        challenges.iter().copied(),
        sample_challenge_pows(ts, num_rotations, b"combine subset evals")
    )
    .collect_vec();
    let (origin_point, expected_evaluation, _) = replay_main_sumcheck(
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

    Ok(Some(RotationReplayClaims {
        left_point,
        right_point,
        origin_point,
        left_evals,
        right_evals,
        target_evals,
    }))
}

fn sample_vec<TS>(ts: &mut TS, label: &[u8], len: usize) -> Vec<RecursionField>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    transcript_observe_label(ts, label);
    (0..len)
        .map(|_| FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts))
        .collect()
}

struct MainReplayLayer<'a> {
    air_idx: usize,
    layer: &'a gkr_iop::gkr::layer::Layer<RecursionField>,
    eval_and_dedup_points: Vec<(Vec<RecursionField>, Option<Vec<RecursionField>>)>,
    selector_ctxs: Vec<gkr_iop::selector::SelectorContext>,
    eval_start: usize,
    eval_len: usize,
    alpha_start: usize,
    num_var_with_rotation: usize,
    pi: Vec<RecursionField>,
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

            let sample_r = sample_vec(ts, b"ecc_gkr_bridge_r", 1)[0];
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
            layer,
            eval_and_dedup_points,
            selector_ctxs,
            eval_start: total_evals,
            eval_len,
            alpha_start: total_exprs,
            num_var_with_rotation,
            pi,
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
    let mut global_point_lookup_counts = vec![0usize; global_in_point.len()];
    for record in &tower_point_eqs {
        global_point_lookup_counts[record.round_idx] += 1;
    }
    for record in &frontload_terms {
        if record.has_global_factor {
            global_point_lookup_counts[record.global_round_idx] += 1;
        }
    }
    for record in &selector_evals {
        if !record.has_eval {
            continue;
        }
        for round_idx in 0..record.ctx_num_vars.min(MAX_SELECTOR_POINT_VARS) {
            global_point_lookup_counts[round_idx] += 1;
        }
    }
    let mut eval_lookup_counts = vec![0usize; main_proof.proof.evals.len()];
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
            let Some(actual_eval) = main_evals.get(layer.eval_start + eval_idx).copied() else {
                bail!("main selector structural witin index {eval_idx} out of range");
            };
            if actual_eval != expected_eval {
                if std::env::var_os("CENO_REC_V2_DEBUG_MAIN").is_some() {
                    eprintln!(
                        "rec-v2-debug module=main source=selector-preflight proof_idx=0 idx={idx} air_idx={} selector_idx={selector_idx} wit_id={eval_idx} expected={expected_eval} got={actual_eval}",
                        layer.air_idx
                    );
                }
            }
            records.push(MainSelectorEvalRecord {
                proof_idx: 0,
                idx,
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
        if let Some((expected_eval, wit_id)) = sel_type.evaluate(out_point, &in_point, selector_ctx)
        {
            let wit_id = wit_id as usize + structural_witin_offset;
            let Some(actual_eval) = layer_evals.get(wit_id).copied() else {
                bail!("main selector structural witin index {wit_id} out of range");
            };
            if actual_eval != expected_eval {
                if std::env::var_os("CENO_REC_V2_DEBUG_MAIN").is_some() {
                    eprintln!(
                        "rec-v2-debug module=main source=selector-structural-check layer={} wit_id={wit_id} expected={expected_eval} got={actual_eval}",
                        layer.layer.name
                    );
                }
            }
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
            if std::env::var_os("CENO_REC_V2_DEBUG_MAIN").is_some() {
                eprintln!(
                    "rec-v2-debug module=main source=structural-check wit_id={wit_id} expected={expected_eval} got={actual_eval}"
                );
            }
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
