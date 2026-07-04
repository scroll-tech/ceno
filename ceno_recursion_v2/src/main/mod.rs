mod air;
pub(crate) mod eval_absorb;
pub(crate) mod final_claim;
pub(crate) mod frontload;
pub(crate) mod global_sumcheck;
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
    util::ceil_log2,
    utils::eval_by_expr_with_instance,
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
    trace::{MainRecord, MainTraceGenerator},
    transcript_bind::{MainTranscriptBindAir, MainTranscriptBindTraceGenerator},
};
use crate::{
    bus::{ForkedTranscriptBus, MainBus, MainExpressionClaimBus, TranscriptBus},
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, MainEvalRecord,
        MainFinalClaimRecord, MainFrontloadTermRecord, MainTowerPointEqRecord, Preflight,
        RecursionField, RecursionProof, RecursionVk, TraceGenModule,
    },
    tower::{
        TowerInputRecord, build_tower_input_records, build_tower_main_point_records,
        tower_transcript_len,
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
}

impl MainModule {
    pub fn new(b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        let _ = b;
        let main_bus = bus_inventory.main_bus;
        let expression_claim_bus = bus_inventory.main_expression_claim_bus;
        let transcript_bus = bus_inventory.transcript_bus;
        let forked_transcript_bus = bus_inventory.forked_transcript_bus;
        Self {
            main_bus,
            expression_claim_bus,
            transcript_bus,
            forked_transcript_bus,
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
    pub(crate) tower_point_eq_records: Vec<MainTowerPointEqRecord>,
    pub(crate) frontload_term_records: Vec<MainFrontloadTermRecord>,
    pub(crate) final_claim_records: Vec<MainFinalClaimRecord>,
    pub(crate) transcript_records: Vec<crate::system::MainTranscriptRecord>,
}

impl AirModule for MainModule {
    fn num_airs(&self) -> usize {
        2
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
            tower_point_eq_records: _,
            frontload_term_records: _,
            final_claim_records: _,
            ref mut transcript_records,
        } = records;
        main_records.sort_by_key(|record| (record.proof_idx, record.idx));
        transcript_records.sort_by_key(|record| (record.proof_idx, record.tidx));
        let ctx = MainTraceCtx {
            main_records: &main_records,
            transcript_records: &transcript_records,
        };
        let chips = [MainModuleChip::Main, MainModuleChip::TranscriptBind];
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
    transcript_records: &'a [crate::system::MainTranscriptRecord],
}

enum MainModuleChip {
    Main,
    TranscriptBind,
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
    challenges: [RecursionField; 2],
) -> Result<()>
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
        return Ok(());
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

    let _rotation_challenges = chain!(
        challenges.iter().copied(),
        sample_challenge_pows(ts, num_rotations, b"combine subset evals")
    )
    .collect_vec();
    let _ = replay_main_sumcheck(
        ts,
        RecursionField::ZERO,
        &rotation_proof.proof,
        num_var_with_rotation,
        2,
    )?;
    for eval in &rotation_proof.evals {
        ts.observe_ext(*eval);
    }
    Ok(())
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
    layer: &'a gkr_iop::gkr::layer::Layer<RecursionField>,
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

        if chip_proof.ecc_proof.is_some() {
            bail!(
                "recursion-v2 batch main constraints do not yet constrain ecc_gkr_bridge_r claims"
            );
        }

        let eval_len = layer.n_witin + layer.n_fixed + layer.n_structural_witin;
        max_num_variables = max_num_variables.max(num_var_with_rotation);
        max_degree = max_degree.max(layer.max_expr_degree + 1);
        layers.push(MainReplayLayer {
            layer,
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
    let mut eval_lookup_counts = vec![0usize; main_proof.proof.evals.len()];
    for record in &frontload_terms {
        if record.has_eval_factor {
            let global_eval_idx = layers[record.idx].eval_start + record.eval_idx;
            eval_lookup_counts[global_eval_idx] += 1;
        }
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
    preflight.main.tower_point_eqs.extend(tower_point_eqs);
    preflight.main.frontload_terms.extend(frontload_terms);
    preflight.main.final_claims.extend(final_claims);
    Ok(())
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
        let contribution = build_frontload_term_records_for_layer(
            idx,
            layer,
            layer_evals,
            &layer.pi,
            &main_sumcheck_challenges,
            global_in_point,
            &mut frontload_records,
        )?;
        if let Some(terms) = layer.layer.main_sumcheck_expression_monomial_terms.as_ref() {
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
                    "layer expr contribution mismatch at chip {idx}: {monomial_contribution} != {contribution}"
                );
            }
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
    let in_point = &global_in_point[..layer.num_var_with_rotation];
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
                in_point,
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
                    in_point,
                    *descending,
                )
            }
            StackedIncrementalSequence { .. } => {
                gkr_iop::utils::eval_stacked_wellform_address_vec(in_point)
            }
            StackedConstantSequence { .. } => gkr_iop::utils::eval_stacked_constant_vec(in_point),
            InnerRepeatingIncrementalSequence { k, .. } => {
                gkr_iop::utils::eval_inner_repeated_incremental_vec(*k as u64, in_point)
            }
            OuterRepeatingIncrementalSequence { k, .. } => {
                gkr_iop::utils::eval_outer_repeated_incremental_vec(*k as u64, in_point)
            }
            Empty => continue,
        };
        if actual_eval != expected_eval {
            bail!(
                "main structural witin mismatch wit_id={wit_id} expected={expected_eval} got={actual_eval}"
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
    records: &mut Vec<MainFrontloadTermRecord>,
) -> Result<RecursionField> {
    let tail_start = layer.num_var_with_rotation;
    let tail_point = &global_in_point[tail_start..];
    let expr = layer
        .layer
        .main_sumcheck_expression
        .as_ref()
        .ok_or_else(|| eyre!("missing main sumcheck expression"))?;
    let mut row_idx = 0usize;
    let mut node_idx = 0usize;
    let folded_value = emit_main_expr_row(
        idx,
        expr,
        layer_evals,
        pi,
        challenges,
        tail_start,
        tail_point,
        records,
        &mut row_idx,
        &mut node_idx,
    )?;

    records.push(MainFrontloadTermRecord {
        proof_idx: 0,
        idx,
        row_idx,
        node_idx,
        eval_idx: 0,
        has_eval_factor: false,
        instance_idx: 0,
        challenge_idx: 0,
        global_round_idx: 0,
        has_global_factor: false,
        is_wit: false,
        is_const: false,
        is_instance: false,
        is_challenge: false,
        is_add: false,
        is_sub: false,
        is_neg: false,
        is_mul: false,
        is_fold: true,
        is_tail: false,
        constraint_idx: 0,
        alpha: RecursionField::ONE,
        arg0: folded_value,
        arg1: RecursionField::ZERO,
        value: folded_value,
        chip_acc_in: RecursionField::ZERO,
        chip_acc_out: folded_value,
        is_last_chip_step: true,
    });

    Ok(folded_value)
}

#[allow(clippy::too_many_arguments)]
fn emit_main_expr_row(
    idx: usize,
    expr: &Expression<RecursionField>,
    layer_evals: &[RecursionField],
    pi: &[RecursionField],
    challenges: &[RecursionField],
    tail_start: usize,
    tail_point: &[RecursionField],
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
        eval_idx: 0,
        has_eval_factor: false,
        instance_idx: 0,
        challenge_idx: 0,
        global_round_idx: 0,
        has_global_factor: false,
        is_wit: false,
        is_const: false,
        is_instance: false,
        is_challenge: false,
        is_add: false,
        is_sub: false,
        is_neg: false,
        is_mul: false,
        is_fold: false,
        is_tail: false,
        constraint_idx: 0,
        alpha: RecursionField::ZERO,
        arg0: RecursionField::ZERO,
        arg1: RecursionField::ZERO,
        value: RecursionField::ZERO,
        chip_acc_in: RecursionField::ZERO,
        chip_acc_out: RecursionField::ZERO,
        is_last_chip_step: false,
    };

    let value = match expr {
        Expression::WitIn(wit_id) => {
            let eval_idx = *wit_id as usize;
            let value = *layer_evals
                .get(eval_idx)
                .ok_or_else(|| eyre!("main expr wit index {eval_idx} out of range"))?;
            record.is_wit = true;
            record.has_eval_factor = true;
            record.eval_idx = eval_idx;
            record.arg0 = value;
            value
        }
        Expression::StructuralWitIn(wit_id, _) => {
            let eval_idx = *wit_id as usize;
            let value = *layer_evals
                .get(eval_idx)
                .ok_or_else(|| eyre!("main expr structural wit index {eval_idx} out of range"))?;
            record.is_wit = true;
            record.has_eval_factor = true;
            record.eval_idx = eval_idx;
            record.arg0 = value;
            value
        }
        Expression::Fixed(fixed) => {
            let eval_idx = fixed.0;
            let value = *layer_evals
                .get(eval_idx)
                .ok_or_else(|| eyre!("main expr fixed index {eval_idx} out of range"))?;
            record.is_wit = true;
            record.has_eval_factor = true;
            record.eval_idx = eval_idx;
            record.arg0 = value;
            value
        }
        Expression::Instance(instance) | Expression::InstanceScalar(instance) => {
            let value = *pi
                .get(instance.0)
                .ok_or_else(|| eyre!("main expr instance index {} out of range", instance.0))?;
            record.is_instance = true;
            record.instance_idx = instance.0;
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
                .ok_or_else(|| eyre!("main expr challenge index {challenge_idx} out of range"))?;
            let value = challenge.exp_u64(*pow as u64) * *scalar + *offset;
            record.is_challenge = true;
            record.challenge_idx = challenge_idx;
            record.arg0 = value;
            value
        }
        Expression::Sum(left, right) => {
            let left = emit_main_expr_row(
                idx,
                left,
                layer_evals,
                pi,
                challenges,
                tail_start,
                tail_point,
                records,
                row_idx,
                node_idx,
            )?;
            let right = emit_main_expr_row(
                idx,
                right,
                layer_evals,
                pi,
                challenges,
                tail_start,
                tail_point,
                records,
                row_idx,
                node_idx,
            )?;
            record.is_add = true;
            record.arg0 = left;
            record.arg1 = right;
            left + right
        }
        Expression::Product(left, right) => {
            let left = emit_main_expr_row(
                idx,
                left,
                layer_evals,
                pi,
                challenges,
                tail_start,
                tail_point,
                records,
                row_idx,
                node_idx,
            )?;
            let right = emit_main_expr_row(
                idx,
                right,
                layer_evals,
                pi,
                challenges,
                tail_start,
                tail_point,
                records,
                row_idx,
                node_idx,
            )?;
            record.is_mul = true;
            record.arg0 = left;
            record.arg1 = right;
            left * right
        }
        Expression::ScaledSum(x, a, b) => {
            let x = emit_main_expr_row(
                idx,
                x,
                layer_evals,
                pi,
                challenges,
                tail_start,
                tail_point,
                records,
                row_idx,
                node_idx,
            )?;
            let a = emit_main_expr_row(
                idx,
                a,
                layer_evals,
                pi,
                challenges,
                tail_start,
                tail_point,
                records,
                row_idx,
                node_idx,
            )?;
            let b = emit_main_expr_row(
                idx,
                b,
                layer_evals,
                pi,
                challenges,
                tail_start,
                tail_point,
                records,
                row_idx,
                node_idx,
            )?;
            let mul_node = *node_idx;
            *node_idx += 1;
            records.push(MainFrontloadTermRecord {
                proof_idx: 0,
                idx,
                row_idx: *row_idx,
                node_idx: mul_node,
                is_mul: true,
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

    let should_emit_wit_tail = record.is_wit;
    record.value = value;
    record.chip_acc_out = record.chip_acc_in;
    records.push(record);
    *row_idx += 1;
    if should_emit_wit_tail {
        Ok(emit_main_expr_wit_tail_rows(
            idx, value, tail_start, tail_point, records, row_idx, node_idx,
        ))
    } else {
        Ok(value)
    }
}

fn emit_main_expr_wit_tail_rows(
    idx: usize,
    mut acc: RecursionField,
    tail_start: usize,
    tail_point: &[RecursionField],
    records: &mut Vec<MainFrontloadTermRecord>,
    row_idx: &mut usize,
    node_idx: &mut usize,
) -> RecursionField {
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
