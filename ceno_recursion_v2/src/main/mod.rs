mod air;
mod eval_absorb;
mod final_claim;
mod frontload;
mod global_sumcheck;
mod tower_point;
mod trace;
mod transcript_bind;

use std::{iter, sync::Arc};

use eyre::{Result, bail, eyre};
use itertools::{Either, Itertools, chain};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, monomial::Term, util::ceil_log2, utils::eval_by_expr_with_instance,
    virtual_poly::VPAuxInfo,
};
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, D_EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use sumcheck::{structs::IOPVerifierState, util::extrapolate_uni_poly};
use transcript::{BasicTranscript, Transcript};
use witness::next_pow2_instance_padding;

use self::{
    air::MainAir,
    eval_absorb::{MainEvalAbsorbAir, MainEvalAbsorbTraceGenerator},
    final_claim::{MainFinalClaimAir, MainFinalClaimTraceGenerator},
    frontload::{MainFrontloadTermAir, MainFrontloadTermTraceGenerator},
    global_sumcheck::{MainGlobalSumcheckAir, MainGlobalSumcheckTraceGenerator},
    tower_point::{MainTowerPointEqAir, MainTowerPointEqTraceGenerator},
    trace::{MainRecord, MainTraceGenerator},
    transcript_bind::{MainTranscriptBindAir, MainTranscriptBindTraceGenerator},
};
use crate::{
    bus::{
        ForkedTranscriptBus, MainBus, MainContributionBus, MainEvalBus, MainExpressionClaimBus,
        MainGlobalClaimBus, MainGlobalPointBus, TowerMainPointBus, TranscriptBus,
    },
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, MainEvalRecord,
        MainFinalClaimRecord, MainFrontloadTermRecord, MainTowerPointEqRecord, Preflight,
        RecursionField, RecursionPcs, RecursionProof, RecursionVk, TraceGenModule, child_vk_digest,
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
    global_claim_bus: MainGlobalClaimBus,
    global_point_bus: MainGlobalPointBus,
    eval_bus: MainEvalBus,
    contribution_bus: MainContributionBus,
    tower_point_bus: TowerMainPointBus,
    transcript_bus: TranscriptBus,
    forked_transcript_bus: ForkedTranscriptBus,
}

impl MainModule {
    pub fn new(b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        let _ = b;
        let main_bus = bus_inventory.main_bus;
        let expression_claim_bus = bus_inventory.main_expression_claim_bus;
        let global_claim_bus = bus_inventory.main_global_claim_bus;
        let global_point_bus = bus_inventory.main_global_point_bus;
        let eval_bus = bus_inventory.main_eval_bus;
        let contribution_bus = bus_inventory.main_contribution_bus;
        let tower_point_bus = bus_inventory.tower_main_point_bus;
        let transcript_bus = bus_inventory.transcript_bus;
        let forked_transcript_bus = bus_inventory.forked_transcript_bus;
        Self {
            main_bus,
            expression_claim_bus,
            global_claim_bus,
            global_point_bus,
            eval_bus,
            contribution_bus,
            tower_point_bus,
            transcript_bus,
            forked_transcript_bus,
        }
    }

    fn collect_records(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
    ) -> Result<(
        Vec<MainRecord>,
        Vec<crate::system::MainGlobalSumcheckRecord>,
        Vec<MainEvalRecord>,
        Vec<MainTowerPointEqRecord>,
        Vec<MainFrontloadTermRecord>,
        Vec<MainFinalClaimRecord>,
        Vec<crate::system::MainTranscriptRecord>,
    )> {
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
            let values = preflight.transcript.values();
            let samples = preflight.transcript.samples();
            for tidx in preflight.main.transcript_start..preflight.main.transcript_end {
                if eval_tidxs.contains(&tidx) {
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

        Ok((
            main_records,
            global_sumcheck_records,
            eval_records,
            tower_point_eq_records,
            frontload_term_records,
            final_claim_records,
            transcript_records,
        ))
    }
}

impl AirModule for MainModule {
    fn num_airs(&self) -> usize {
        7
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let main_air = MainAir {
            main_bus: self.main_bus,
            expression_claim_bus: self.expression_claim_bus,
            send_expression_claim: !crate::system::MAIN_PREFIX_ONLY,
        };
        vec![
            Arc::new(main_air) as AirRef<_>,
            Arc::new(MainTranscriptBindAir {
                transcript_bus: self.transcript_bus,
                forked_transcript_bus: self.forked_transcript_bus,
            }) as AirRef<_>,
            Arc::new(MainGlobalSumcheckAir {
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
        let (
            mut main_records,
            mut global_sumcheck_records,
            mut eval_records,
            mut tower_point_eq_records,
            mut frontload_term_records,
            mut final_claim_records,
            mut transcript_records,
        ) = self.collect_records(child_vk, proofs, preflights).ok()?;
        main_records.sort_by_key(|record| (record.proof_idx, record.idx));
        global_sumcheck_records.sort_by_key(|record| record.proof_idx);
        eval_records.sort_by_key(|record| (record.proof_idx, record.idx, record.eval_idx));
        tower_point_eq_records
            .sort_by_key(|record| (record.proof_idx, record.idx, record.round_idx));
        frontload_term_records.sort_by_key(|record| {
            (
                record.proof_idx,
                record.idx,
                record.term_idx,
                record.step_idx,
            )
        });
        final_claim_records.sort_by_key(|record| (record.proof_idx, record.idx));
        transcript_records.sort_by_key(|record| (record.proof_idx, record.tidx));
        let ctx = MainTraceCtx {
            main_records: &main_records,
            global_sumcheck_records: &global_sumcheck_records,
            eval_records: &eval_records,
            tower_point_eq_records: &tower_point_eq_records,
            frontload_term_records: &frontload_term_records,
            final_claim_records: &final_claim_records,
            transcript_records: &transcript_records,
        };
        let chips = [
            MainModuleChip::Main,
            MainModuleChip::TranscriptBind,
            MainModuleChip::GlobalSumcheck,
            MainModuleChip::EvalAbsorb,
            MainModuleChip::TowerPointEq,
            MainModuleChip::FrontloadTerm,
            MainModuleChip::FinalClaim,
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
    global_sumcheck_records: &'a [crate::system::MainGlobalSumcheckRecord],
    eval_records: &'a [MainEvalRecord],
    tower_point_eq_records: &'a [MainTowerPointEqRecord],
    frontload_term_records: &'a [MainFrontloadTermRecord],
    final_claim_records: &'a [MainFinalClaimRecord],
    transcript_records: &'a [crate::system::MainTranscriptRecord],
}

enum MainModuleChip {
    Main,
    TranscriptBind,
    GlobalSumcheck,
    EvalAbsorb,
    TowerPointEq,
    FrontloadTerm,
    FinalClaim,
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
            MainModuleChip::GlobalSumcheck => MainGlobalSumcheckTraceGenerator
                .generate_trace(&ctx.global_sumcheck_records, required_height),
            MainModuleChip::EvalAbsorb => {
                MainEvalAbsorbTraceGenerator.generate_trace(&ctx.eval_records, required_height)
            }
            MainModuleChip::TowerPointEq => MainTowerPointEqTraceGenerator
                .generate_trace(&ctx.tower_point_eq_records, required_height),
            MainModuleChip::FrontloadTerm => MainFrontloadTermTraceGenerator
                .generate_trace(&ctx.frontload_term_records, required_height),
            MainModuleChip::FinalClaim => MainFinalClaimTraceGenerator
                .generate_trace(&ctx.final_claim_records, required_height),
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
    let alpha_span = num_layers.saturating_sub(1) * tower_transcript_len::ALPHA_LEN;
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
            transcript_observe_label(ts, b"ecc_gkr_bridge_r");
            let _ = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
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

    let _openvm_alpha_pows = sample_challenge_pows(ts, total_exprs, b"combine subset evals");
    let (_openvm_global_in_point, _openvm_expected_evaluation) = replay_main_sumcheck(
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

    let (pcs_challenges, alpha_pows, global_in_point, expected_evaluation) =
        native_main_claim_inputs(child_vk, proof, total_exprs, max_num_variables, max_degree)?;
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
    let mut claim = claimed_sum;
    let mut rounds = Vec::with_capacity(proof.proofs.len());
    for (round_idx, (prover_msg, challenge)) in proof
        .proofs
        .iter()
        .zip_eq(global_in_point.iter().copied())
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

fn native_main_claim_inputs(
    child_vk: &RecursionVk,
    proof: &RecursionProof,
    total_exprs: usize,
    max_num_variables: usize,
    max_degree: usize,
) -> Result<(
    [RecursionField; 2],
    Vec<RecursionField>,
    Vec<RecursionField>,
    RecursionField,
)> {
    let mut transcript = BasicTranscript::<RecursionField>::new(b"riscv");
    transcript.append_field_element_exts(&child_vk_digest(child_vk));

    for (_, circuit_vk) in child_vk.circuit_vks.iter() {
        for instance_value in circuit_vk.get_cs().zkvm_v1_css.instance.iter() {
            transcript.append_field_element(
                &proof
                    .public_values
                    .query_by_index::<RecursionField>(instance_value.0),
            );
        }
    }

    if let Some(fixed_commit) = child_vk.fixed_commit.as_ref() {
        RecursionPcs::write_commitment(fixed_commit, &mut transcript)
            .map_err(|err| eyre!("native fixed commitment replay failed: {err:?}"))?;
    }
    if let Some(fixed_commit) = child_vk.fixed_no_omc_init_commit.as_ref() {
        RecursionPcs::write_commitment(fixed_commit, &mut transcript)
            .map_err(|err| eyre!("native fixed no-omc commitment replay failed: {err:?}"))?;
    }
    RecursionPcs::write_commitment(&proof.witin_commit, &mut transcript)
        .map_err(|err| eyre!("native witness commitment replay failed: {err:?}"))?;

    let challenges = [
        transcript.read_challenge().elements,
        transcript.read_challenge().elements,
    ];
    let mut forked_transcripts =
        vec![BasicTranscript::<RecursionField>::new(b"fork"); proof.chip_proofs.len()];

    for (fork_idx, ((chip_idx, chip_proof), fork_transcript)) in proof
        .chip_proofs
        .iter()
        .zip_eq(forked_transcripts.iter_mut())
        .enumerate()
    {
        let Some(name) = child_vk.circuit_index_to_name.get(chip_idx) else {
            bail!("missing circuit name for chip index {chip_idx}");
        };
        let circuit_vk = child_vk
            .circuit_vks
            .get(name)
            .ok_or_else(|| eyre!("missing circuit vk for {name}"))?;
        if proof.public_values.shard_id > 0 && circuit_vk.get_cs().with_omc_init_only() {
            continue;
        }

        fork_transcript.append_field_element_ext(&challenges[0]);
        fork_transcript.append_field_element_ext(&challenges[1]);
        fork_transcript.append_field_element(&F::from_usize(fork_idx));
        fork_transcript.append_field_element(&F::from_u64(*chip_idx as u64));
        for num_instance in &chip_proof.num_instances {
            fork_transcript.append_field_element(&F::from_usize(*num_instance));
        }

        let (_, num_var_with_rotation) = native_tower_num_variables(circuit_vk, chip_proof);
        native_record_gkr_transcript(fork_transcript, circuit_vk, chip_proof)?;
        let composed_cs = circuit_vk.get_cs();
        if composed_cs.has_ecc_ops() {
            let ecc_proof = chip_proof
                .ecc_proof
                .as_ref()
                .ok_or_else(|| eyre!("{name} missing ecc proof"))?;
            native_replay_ecc_transcript(fork_transcript, ecc_proof);
        }

        let gkr_circuit = composed_cs
            .gkr_circuit
            .as_ref()
            .ok_or_else(|| eyre!("{name} missing gkr circuit in vk"))?;
        let first_layer = gkr_circuit
            .layers
            .first()
            .ok_or_else(|| eyre!("{name} empty gkr circuit layers"))?;
        if !first_layer.rotation_exprs.1.is_empty() {
            let rotation_proof = chip_proof
                .rotation_proof
                .as_ref()
                .ok_or_else(|| eyre!("{name} missing rotation proof"))?;
            native_replay_rotation_transcript(
                fork_transcript,
                rotation_proof,
                first_layer.rotation_exprs.1.len(),
                num_var_with_rotation,
            )?;
        }
    }

    for mut fork_transcript in forked_transcripts {
        let sample = fork_transcript.sample_vec(1)[0];
        transcript.append_field_element_ext(&sample);
    }

    let alpha_pows = sumcheck::util::get_challenge_pows(total_exprs, &mut transcript);
    let subclaim = IOPVerifierState::verify(
        proof.main_constraint_proof.claimed_sum,
        &proof.main_constraint_proof.proof.proof,
        &VPAuxInfo {
            max_degree,
            max_num_variables,
            phantom: std::marker::PhantomData,
        },
        &mut transcript,
    );
    let global_in_point = subclaim
        .point
        .into_iter()
        .map(|challenge| challenge.elements)
        .collect_vec();
    transcript.append_field_element_exts(&proof.main_constraint_proof.proof.evals);
    Ok((
        challenges,
        alpha_pows,
        global_in_point,
        subclaim.expected_evaluation,
    ))
}

fn native_record_gkr_transcript(
    ts: &mut BasicTranscript<RecursionField>,
    circuit_vk: &ceno_zkvm::structs::VerifyingKey<RecursionField>,
    chip_proof: &ceno_zkvm::scheme::ZKVMChipProof<RecursionField>,
) -> Result<()> {
    for eval in chip_proof
        .r_out_evals
        .iter()
        .chain(chip_proof.w_out_evals.iter())
        .chain(chip_proof.lk_out_evals.iter())
        .flatten()
    {
        ts.append_field_element_ext(eval);
    }

    let (tower_num_variables, _) = native_tower_num_variables(circuit_vk, chip_proof);
    ceno_zkvm::scheme::verifier::TowerVerify::verify(
        chip_proof
            .r_out_evals
            .iter()
            .cloned()
            .chain(chip_proof.w_out_evals.iter().cloned())
            .collect_vec(),
        chip_proof.lk_out_evals.clone(),
        &chip_proof.tower_proof,
        tower_num_variables,
        2,
        ts,
    )
    .map(|_| ())
    .map_err(|err| eyre!("native tower transcript replay failed: {err:?}"))
}

fn native_replay_ecc_transcript(
    ts: &mut BasicTranscript<RecursionField>,
    ecc_proof: &ceno_zkvm::structs::EccQuarkProof<RecursionField>,
) {
    let num_vars = ceil_log2(next_pow2_instance_padding(ecc_proof.num_instances));
    let _ = ts.sample_and_append_vec(b"ecc", num_vars);
    let _ = ts.sample_and_append_challenge_pows(
        7 * ceno_zkvm::scheme::constants::SEPTIC_EXTENSION_DEGREE,
        b"ecc_alpha",
    );
    let _ = IOPVerifierState::verify(
        RecursionField::ZERO,
        &ecc_proof.zerocheck_proof,
        &VPAuxInfo {
            max_degree: 3,
            max_num_variables: num_vars,
            phantom: std::marker::PhantomData,
        },
        ts,
    );
}

fn native_replay_rotation_transcript(
    ts: &mut BasicTranscript<RecursionField>,
    rotation_proof: &gkr_iop::gkr::layer::sumcheck_layer::SumcheckLayerProof<RecursionField>,
    num_rotations: usize,
    num_var_with_rotation: usize,
) -> Result<()> {
    if rotation_proof.evals.len() != num_rotations * 3 {
        bail!(
            "rotation eval length mismatch: {} != {}",
            rotation_proof.evals.len(),
            num_rotations * 3
        );
    }
    let _ = sumcheck::util::get_challenge_pows(num_rotations, ts);
    let _ = IOPVerifierState::verify(
        RecursionField::ZERO,
        &rotation_proof.proof,
        &VPAuxInfo {
            max_degree: 2,
            max_num_variables: num_var_with_rotation,
            phantom: std::marker::PhantomData,
        },
        ts,
    );
    ts.append_field_element_exts(&rotation_proof.evals);
    Ok(())
}

fn native_tower_num_variables(
    circuit_vk: &ceno_zkvm::structs::VerifyingKey<RecursionField>,
    chip_proof: &ceno_zkvm::scheme::ZKVMChipProof<RecursionField>,
) -> (Vec<usize>, usize) {
    let composed_cs = circuit_vk.get_cs();
    let cs = &composed_cs.zkvm_v1_css;
    let num_instances = chip_proof.num_instances.iter().sum();
    let r_counts_per_instance = cs.r_expressions.len() + cs.r_table_expressions.len();
    let w_counts_per_instance = cs.w_expressions.len() + cs.w_table_expressions.len();
    let lk_counts_per_instance = cs.lk_expressions.len() + cs.lk_table_expressions.len();
    let num_batched = r_counts_per_instance + w_counts_per_instance + lk_counts_per_instance;
    let mut log2_num_instances = ceil_log2(next_pow2_instance_padding(num_instances));
    if composed_cs.has_ecc_ops() {
        log2_num_instances += 1;
    }
    let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);
    let grouped_tower_shape = chip_proof.r_out_evals.len()
        == usize::from(r_counts_per_instance > 0)
        && chip_proof.w_out_evals.len() == usize::from(w_counts_per_instance > 0)
        && chip_proof.lk_out_evals.len() == usize::from(lk_counts_per_instance > 0);
    let tower_num_variables = if grouped_tower_shape {
        let group_num_vars =
            |op_count: usize| num_var_with_rotation + ceil_log2(op_count.next_power_of_two());
        chip_proof
            .r_out_evals
            .iter()
            .map(|_| group_num_vars(r_counts_per_instance))
            .chain(
                chip_proof
                    .w_out_evals
                    .iter()
                    .map(|_| group_num_vars(w_counts_per_instance)),
            )
            .chain(
                chip_proof
                    .lk_out_evals
                    .iter()
                    .map(|_| group_num_vars(lk_counts_per_instance)),
            )
            .collect_vec()
    } else {
        vec![num_var_with_rotation; num_batched]
    };
    (tower_num_variables, num_var_with_rotation)
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
            .ok_or_else(|| eyre!("missing main sumcheck monomial terms"))?;
        let contribution = build_frontload_term_records_for_layer(
            idx,
            layer,
            layer_evals,
            &layer.pi,
            &main_sumcheck_challenges,
            global_in_point,
            terms,
            &mut frontload_records,
        );
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

fn build_frontload_term_records_for_layer(
    idx: usize,
    layer: &MainReplayLayer<'_>,
    layer_evals: &[RecursionField],
    pi: &[RecursionField],
    challenges: &[RecursionField],
    global_in_point: &[RecursionField],
    terms: &[Term<Expression<RecursionField>, Expression<RecursionField>>],
    records: &mut Vec<MainFrontloadTermRecord>,
) -> RecursionField {
    let tail_start = layer.num_var_with_rotation;
    let tail_point = &global_in_point[tail_start..];
    let mut chip_acc = RecursionField::ZERO;

    for (term_idx, term) in terms.iter().enumerate() {
        let scalar = eval_by_expr_with_instance(&[], &[], &[], pi, challenges, &term.scalar);
        let scalar = either_to_ext(scalar);
        let product_wit_ids = term.product.iter().map(|expr| {
            let Expression::WitIn(wit_id) = expr else {
                panic!("main monomial product must be converted to WitIn")
            };
            *wit_id as usize
        });

        let mut factors = vec![(scalar, None, None)];
        for wit_id in product_wit_ids {
            factors.push((layer_evals[wit_id], Some(wit_id), None));
            for (tail_offset, value) in tail_point.iter().copied().enumerate() {
                factors.push((value, None, Some(tail_start + tail_offset)));
            }
        }

        let mut term_acc = RecursionField::ONE;
        for (step_idx, (factor, eval_idx, global_round_idx)) in factors.iter().copied().enumerate()
        {
            let term_acc_in = term_acc;
            term_acc *= factor;
            let is_last_step = step_idx + 1 == factors.len();
            let chip_acc_in = chip_acc;
            let chip_acc_out = if is_last_step {
                chip_acc + term_acc
            } else {
                chip_acc
            };
            records.push(MainFrontloadTermRecord {
                proof_idx: 0,
                idx,
                term_idx,
                step_idx,
                is_first_step: step_idx == 0,
                is_last_step,
                eval_idx: eval_idx.unwrap_or(0),
                has_eval_factor: eval_idx.is_some(),
                global_round_idx: global_round_idx.unwrap_or(0),
                has_global_factor: global_round_idx.is_some(),
                factor,
                term_acc_in,
                term_acc_out: term_acc,
                chip_acc_in,
                chip_acc_out,
            });
            if is_last_step {
                chip_acc = chip_acc_out;
            }
        }
    }

    chip_acc
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
) -> Result<(Vec<RecursionField>, RecursionField)>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    if max_num_variables == 0 {
        return Ok((vec![], claimed_sum));
    }

    transcript_observe_label(ts, &max_num_variables.to_le_bytes());
    transcript_observe_label(ts, &max_degree.to_le_bytes());
    let mut challenges = Vec::with_capacity(max_num_variables);
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
        let challenge = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        let eval_0 = expected - prover_msg.evaluations[0];
        expected = extrapolate_uni_poly(eval_0, &prover_msg.evaluations, challenge);
        challenges.push(challenge);
    }
    Ok((challenges, expected))
}
