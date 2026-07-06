//! # GKR Air Module
//!
//! The GKR protocol reduces a fractional sum claim $\sum_{y \in H_{\ell+n}}
//! \frac{\hat{p}(y)}{\hat{q}(y)} = 0$ to evaluation claims on the input layer polynomials at a
//! random point. This is done through a layer-by-layer recursive reduction, where each layer uses a
//! sumcheck protocol.
//!
//! The GKR Air Module verifies the [`TowerProof`](openvm_stark_backend::proof::TowerProof) struct and
//! consists of four AIRs:
//!
//! 1. **TowerInputAir** - Handles initial setup, coordinates other AIRs, and sends final claims to
//!    batch constraint module
//! 2. **TowerLayerAir** - Manages layer-by-layer GKR reduction (verifies
//!    [`verify_gkr`](openvm_stark_backend::verifier::fractional_sumcheck_gkr::verify_gkr))
//! 3. **TowerLayerSumcheckAir** - Executes sumcheck protocol for each layer (verifies
//!    [`verify_gkr_sumcheck`](openvm_stark_backend::verifier::fractional_sumcheck_gkr::verify_gkr_sumcheck))
//!
//! ## Architecture
//!
//! ```text
//!                                ┌─────────────────┐
//!                                │                 │───────────────────► TranscriptBus
//!                                │                 │
//!  TowerModuleBus ────────────────►│   TowerInputAir   │───────────────────► ExpBitsLenBus
//!                                │                 │
//!                                │                 │───────────────────► BatchConstraintModuleBus
//!                                └─────────────────┘
//!                                      ┆      ▲
//!                                      ┆      ┆
//!                     TowerLayerInputBus ┆      ┆ TowerLayerOutputBus
//!                                      ┆      ┆
//!                                      ▼      ┆
//!                             ┌─────────────────────────┐
//!                             │                         │──────────────► TranscriptBus
//!   ┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│       TowerLayerAir       │
//!   ┆                         │                         │──────────────► XiRandomnessBus
//!   ┆                         └─────────────────────────┘
//!   ┆                                  ┆      ▲
//!   ┆                                  ┆      ┆
//!   ┆              TowerSumcheckInputBus ┆      ┆ TowerSumcheckOutputBus
//!   ┆                                  ┆      ┆
//!   ┆                                  ▼      ┆
//!   ┆ TowerSumcheckChallengeBus ┌─────────────────────────┐
//!   ┆┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│                         │──────────────► TranscriptBus
//!   ┆                         │   TowerLayerSumcheckAir   │
//!   └┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄►│                         │──────────────► XiRandomnessBus
//!                             └─────────────────────────┘
//! ```

use std::sync::Arc;

use ::sumcheck::structs::IOPProverMessage;
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, ReadOnlyTranscript, StarkProtocolConfig, TranscriptHistory,
    p3_maybe_rayon::prelude::*, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, D_EF, EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use recursion_circuit::primitives::exp_bits_len::ExpBitsLenTraceGenerator;
use strum::EnumCount;
use tracing::error;

use crate::{
    main::selector::selector_formula_point_lookup_counts,
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, MainSelectorPointSourceKind,
        Preflight, RecursionField, RecursionProof, RecursionVk, TowerChipTranscriptRange,
        TraceGenModule,
    },
    tower::{
        alpha_pow::{TowerAlphaPowAir, TowerAlphaPowTraceGenerator},
        bus::{
            TowerActivityBus, TowerInputShapeBus, TowerLayerInputBus, TowerLayerOutputBus,
            TowerShapeBus,
        },
        input::{TowerInputAir, TowerInputTraceGenerator},
        layer::{TowerLayerAir, TowerLayerRecord, TowerLayerTraceGenerator},
        main_point::{TowerMainPointAir, TowerMainPointTraceGenerator},
        shape::{
            TowerActivityAir, TowerActivityTraceGenerator, TowerShapeAir, TowerShapeRecord,
            TowerShapeTraceGenerator,
        },
        sumcheck::{TowerLayerSumcheckAir, TowerSumcheckRecord, TowerSumcheckTraceGenerator},
    },
    tracegen::{ModuleChip, RowMajorChip},
    utils::transcript_observe_label,
};
use ceno_zkvm::{scheme::ZKVMChipProof, structs::VerifyingKey};
use eyre::Result;
use witness::next_pow2_instance_padding;

// Internal bus definitions
mod bus;
pub use bus::{
    TowerAlphaPowBus, TowerAlphaPowMessage, TowerSumcheckChallengeBus,
    TowerSumcheckChallengeMessage, TowerSumcheckInputBus, TowerSumcheckInputMessage,
    TowerSumcheckOutputBus, TowerSumcheckOutputMessage,
};

/// Transcript field-element lengths per tower operation.
///
/// These match the native verifier (gkr-backend `BasicTranscript`) which absorbs
/// labels before each sample via `sample_and_append_challenge` /
/// `sample_and_append_vec`.  The recursion transcript must reproduce the exact
/// same sponge sequence.
pub mod tower_transcript_len {
    use crate::utils::label_to_field_words;
    use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;

    // Label field-element counts: ceil(byte_len / 4).
    // b"combine subset evals" = 20 bytes -> 5 field elements
    pub const LABEL_COMBINE: usize = 5;
    // b"product_sum" = 11 bytes -> 3 field elements
    pub const LABEL_PRODUCT_SUM: usize = 3;
    // b"Internal round" = 14 bytes -> 4 field elements
    pub const LABEL_INTERNAL_ROUND: usize = 4;
    // b"merge" = 5 bytes -> 2 field elements
    pub const LABEL_MERGE: usize = 2;
    // usize::to_le_bytes() = 8 bytes → 2 field elements (64-bit platform)
    const LABEL_USIZE: usize = 2;

    pub const LABEL_COMBINE_FIELDS: [u32; LABEL_COMBINE] =
        label_to_field_words(b"combine subset evals");
    pub const LABEL_PRODUCT_SUM_FIELDS: [u32; LABEL_PRODUCT_SUM] =
        label_to_field_words(b"product_sum");
    pub const LABEL_INTERNAL_ROUND_FIELDS: [u32; LABEL_INTERNAL_ROUND] =
        label_to_field_words(b"Internal round");
    pub const LABEL_MERGE_FIELDS: [u32; LABEL_MERGE] = label_to_field_words(b"merge");

    /// label "combine subset evals" (5) + sample alpha (D_EF)
    pub const ALPHA_LEN: usize = LABEL_COMBINE + D_EF;
    /// label "product_sum" (3) + sample initial_rt (D_EF)
    pub const BETA_LEN: usize = LABEL_PRODUCT_SUM + D_EF;
    /// Alpha + beta: total elements before the GKR layer loop.
    pub const ALPHA_BETA_LEN: usize = ALPHA_LEN + BETA_LEN;
    /// Sumcheck init: label max_num_variables (2) + label max_degree (2)
    pub const SUMCHECK_INIT_LEN: usize = LABEL_USIZE + LABEL_USIZE;
    /// Per sumcheck round: 3 observe (3*D_EF) + label "Internal round" (4) + sample (D_EF)
    pub const ROUND_LEN: usize = 3 * D_EF + LABEL_INTERNAL_ROUND + D_EF;
    /// Merge: label "merge" (2) + sample mu (D_EF)
    pub const MERGE_LEN: usize = LABEL_MERGE + D_EF;

    /// Legacy maximum post-sumcheck tidx span.
    ///
    /// Interleaved towers compact this at runtime based on active read/write/logup
    /// slots for the current layer.
    pub const POST_SUMCHECK_LEN: usize = 4 * D_EF + MERGE_LEN;

    /// Gap between consecutive sumcheck blocks across GKR layers:
    /// post-sumcheck of previous layer + pre-sumcheck of next layer.
    pub const LAYER_GAP_LEN: usize = POST_SUMCHECK_LEN + ALPHA_LEN + SUMCHECK_INIT_LEN;

    /// Tidx span of layer `layer_idx` (includes sumcheck, claim slots, and transcript ops).
    /// Layer 0 (root): SUMCHECK_INIT_LEN + 1*ROUND_LEN + POST_SUMCHECK_LEN.
    /// Layer j>0: ALPHA_LEN + SUMCHECK_INIT_LEN + (j+1)*ROUND_LEN + POST_SUMCHECK_LEN.
    pub const fn layer_span(layer_idx: usize) -> usize {
        if layer_idx == 0 {
            SUMCHECK_INIT_LEN + ROUND_LEN + POST_SUMCHECK_LEN
        } else {
            ALPHA_LEN + SUMCHECK_INIT_LEN + (layer_idx + 1) * ROUND_LEN + POST_SUMCHECK_LEN
        }
    }

    /// Cumulative tidx span for layers 0..layer_idx (exclusive).
    pub const fn layers_cumulative(layer_idx: usize) -> usize {
        let mut total = 0;
        let mut i = 0;
        while i < layer_idx {
            total += layer_span(i);
            i += 1;
        }
        total
    }

    /// Offset from the start of layer `layer_idx` to `tidx_after_sumcheck`
    /// (where claims start).
    /// Layer 0: SUMCHECK_INIT_LEN + 1*ROUND_LEN.
    /// Layer j>0: ALPHA_LEN + SUMCHECK_INIT_LEN + (j+1)*ROUND_LEN.
    pub const fn claim_offset_in_layer(layer_idx: usize) -> usize {
        if layer_idx == 0 {
            SUMCHECK_INIT_LEN + ROUND_LEN
        } else {
            ALPHA_LEN + SUMCHECK_INIT_LEN + (layer_idx + 1) * ROUND_LEN
        }
    }

    /// Offset from the start of layer `layer_idx` to the first sumcheck round.
    pub const fn sumcheck_start_offset_in_layer(layer_idx: usize) -> usize {
        if layer_idx == 0 {
            SUMCHECK_INIT_LEN
        } else {
            ALPHA_LEN + SUMCHECK_INIT_LEN
        }
    }

    pub const fn compact_claim_len(
        read_active: bool,
        write_active: bool,
        logup_active: bool,
    ) -> usize {
        (if read_active { 2 * D_EF } else { 0 })
            + (if write_active { 2 * D_EF } else { 0 })
            + (if logup_active { 4 * D_EF } else { 0 })
    }

    pub const fn compact_post_sumcheck_len(
        read_active: bool,
        write_active: bool,
        logup_active: bool,
    ) -> usize {
        compact_claim_len(read_active, write_active, logup_active) + MERGE_LEN
    }

    pub fn compact_layer_span(
        layer_idx: usize,
        read_active: bool,
        write_active: bool,
        logup_active: bool,
    ) -> usize {
        let pre_sumcheck = if layer_idx == 0 {
            SUMCHECK_INIT_LEN
        } else {
            ALPHA_LEN + SUMCHECK_INIT_LEN
        };
        pre_sumcheck
            + (layer_idx + 1) * ROUND_LEN
            + compact_post_sumcheck_len(read_active, write_active, logup_active)
    }
}

// Sub-modules for different AIRs
pub mod alpha_pow;
pub mod input;
pub mod layer;
pub mod main_point;
pub mod shape;
pub mod sumcheck;
pub(crate) use shape::{TOWER_ACTIVITY_LOGUP, TOWER_ACTIVITY_READ, TOWER_ACTIVITY_WRITE};
#[allow(clippy::module_inception)]
mod tower;
pub(crate) use input::TowerInputRecord;
pub(crate) use tower::{TowerReplayResult, replay_tower_proof_precomputed};
pub struct TowerModule {
    // Global bus inventory
    bus_inventory: BusInventory,
    // Module buses
    shape_bus: TowerShapeBus,
    input_shape_bus: TowerInputShapeBus,
    activity_bus: TowerActivityBus,
    layer_input_bus: TowerLayerInputBus,
    layer_output_bus: TowerLayerOutputBus,
    alpha_pow_bus: TowerAlphaPowBus,
    sumcheck_input_bus: TowerSumcheckInputBus,
    sumcheck_output_bus: TowerSumcheckOutputBus,
    sumcheck_challenge_bus: TowerSumcheckChallengeBus,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TowerTowerEvalRecord {
    pub(crate) read_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) write_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) logup_layers: Vec<Vec<[EF; 4]>>,
}

pub(crate) struct TowerBlobCpu {
    shape_records: Vec<TowerShapeRecord>,
    pub(crate) input_records: Vec<TowerInputRecord>,
    /// Per-proof q0 claims matching input_records (one per proof).
    proof_q0_claims: Vec<EF>,
    layer_records: Vec<TowerLayerRecord>,
    tower_records: Vec<TowerTowerEvalRecord>,
    sumcheck_records: Vec<TowerSumcheckRecord>,
    mus_records: Vec<Vec<EF>>,
    main_point_records: Vec<crate::system::TowerMainPointRecord>,
    /// Per-chip q0 claims matching layer_records.
    q0_claims: Vec<EF>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TowerTranscriptSchedule {
    pub(crate) alpha_logup: EF,
    pub(crate) beta: EF,
    pub(crate) lambdas: Vec<EF>,
    pub(crate) final_alpha: EF,
    pub(crate) mus: Vec<EF>,
    pub(crate) ris: Vec<EF>,
}

impl TowerModule {
    pub fn new(_vk: &RecursionVk, b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        TowerModule {
            bus_inventory,
            shape_bus: TowerShapeBus::new(b.new_bus_idx()),
            input_shape_bus: TowerInputShapeBus::new(b.new_bus_idx()),
            activity_bus: TowerActivityBus::new(b.new_bus_idx()),
            layer_input_bus: TowerLayerInputBus::new(b.new_bus_idx()),
            layer_output_bus: TowerLayerOutputBus::new(b.new_bus_idx()),
            alpha_pow_bus: TowerAlphaPowBus::new(b.new_bus_idx()),
            sumcheck_input_bus: TowerSumcheckInputBus::new(b.new_bus_idx()),
            sumcheck_output_bus: TowerSumcheckOutputBus::new(b.new_bus_idx()),
            sumcheck_challenge_bus: TowerSumcheckChallengeBus::new(b.new_bus_idx()),
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
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
        for (&chip_idx, chip_proof) in &proof.chip_proofs {
            let tidx = ts.len();
            let tower_replay =
                record_and_replay_tower_preflight(ts, child_vk, chip_idx, chip_proof);

            preflight.gkr.chips.push(TowerChipTranscriptRange {
                chip_idx,
                tidx,
                fork_idx: 0, // unused in forked flow
                tower_replay,
                rotation_replay: None,
            });
        }
    }
}

pub(crate) fn convert_logup_claim(
    chip_proof: &ZKVMChipProof<RecursionField>,
    layer_idx: usize,
) -> [EF; 4] {
    chip_proof
        .tower_proof
        .logup_specs_eval
        .iter()
        .find_map(|spec_layers| spec_layers.get(layer_idx))
        .map(|evals| {
            let mut claim = [EF::ZERO; 4];
            for (dst, src) in claim.iter_mut().zip(evals.iter()) {
                *dst = *src;
            }
            claim
        })
        .unwrap_or([EF::ZERO; 4])
}

fn convert_sumcheck_evals(msg: &IOPProverMessage<RecursionField>) -> [EF; 3] {
    let mut evals = [EF::ZERO; 3];
    for (dst, src) in evals.iter_mut().zip(msg.evaluations.iter()) {
        *dst = *src;
    }
    evals
}

pub(crate) fn interpolate_pair(values: [EF; 2], mu: EF) -> EF {
    let delta = values[1] - values[0];
    values[0] + delta * mu
}

pub(crate) fn tower_pre_alpha_tidx(
    chip_proof: &ZKVMChipProof<RecursionField>,
    tower_start_tidx: usize,
) -> usize {
    let out_eval_count = chip_proof
        .r_out_evals
        .iter()
        .chain(chip_proof.w_out_evals.iter())
        .chain(chip_proof.lk_out_evals.iter())
        .map(Vec::len)
        .sum::<usize>();
    tower_start_tidx + out_eval_count * D_EF
}

fn accumulate_prod_claims(rows: &[[EF; 2]], lambda: EF, lambda_prime: EF, mu: EF) -> (EF, EF) {
    let _ = (lambda, lambda_prime);
    let Some(pair) = rows.first() else {
        return (EF::ZERO, EF::ZERO);
    };
    (interpolate_pair(*pair, mu), pair[0] * pair[1])
}

fn accumulate_logup_claims(rows: &[[EF; 4]], lambda: EF, lambda_prime: EF, mu: EF) -> (EF, EF) {
    let Some(quad) = rows.first() else {
        return (EF::ZERO, EF::ZERO);
    };
    let p_xi = interpolate_pair([quad[0], quad[1]], mu);
    let q_xi = interpolate_pair([quad[2], quad[3]], mu);
    let p_cross = quad[0] * quad[3] + quad[1] * quad[2];
    let q_cross = quad[2] * quad[3];
    (p_xi + lambda * q_xi, p_cross + lambda_prime * q_cross)
}

pub(crate) fn circuit_vk_for_idx(
    vk: &RecursionVk,
    chip_idx: usize,
) -> Option<&VerifyingKey<RecursionField>> {
    vk.circuit_index_to_name
        .get(&chip_idx)
        .and_then(|name| vk.circuit_vks.get(name))
}

/// Record all tower transcript events for one chip proof, then replay tower proof.
/// Keeping this in the tower module avoids preflight callsites duplicating
/// transcript/replay wiring logic.
pub(crate) fn record_and_replay_tower_preflight<TS>(
    ts: &mut TS,
    child_vk: &RecursionVk,
    chip_idx: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
) -> TowerReplayResult
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    let schedule = record_gkr_transcript(ts, chip_idx, chip_proof);
    match circuit_vk_for_idx(child_vk, chip_idx) {
        Some(circuit_vk) => match replay_tower_proof_precomputed(chip_proof, circuit_vk, &schedule)
        {
            Ok(replay) => replay,
            Err(err) => {
                error!(
                    ?err,
                    chip_idx, "failed to replay tower proof during preflight"
                );
                TowerReplayResult::default()
            }
        },
        None => TowerReplayResult::default(),
    }
}

fn grouped_op_vars(raw_count: usize) -> usize {
    if raw_count == 0 {
        0
    } else {
        raw_count.next_power_of_two().ilog2() as usize
    }
}

fn build_tower_shape_record(
    proof_idx: usize,
    idx: usize,
    air_idx: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
    circuit_vk: &VerifyingKey<RecursionField>,
) -> TowerShapeRecord {
    let cs = &circuit_vk.cs;
    let num_instances: usize = chip_proof.num_instances.iter().copied().sum();
    let next_pow2_instance = next_pow2_instance_padding(num_instances);
    let mut log2_num_instances = next_pow2_instance.ilog2() as usize;
    if cs.has_ecc_ops() {
        log2_num_instances += 1;
    }
    let num_vars = log2_num_instances + cs.rotation_vars().unwrap_or(0);
    let raw_read_count = cs.num_reads();
    let raw_write_count = cs.num_writes();
    let raw_logup_count = cs.num_lks();
    let read_op_vars = grouped_op_vars(raw_read_count);
    let write_op_vars = grouped_op_vars(raw_write_count);
    let logup_op_vars = grouped_op_vars(raw_logup_count);
    let has_read = raw_read_count > 0;
    let has_write = raw_write_count > 0;
    let has_logup = raw_logup_count > 0;
    let read_tower_vars = if has_read { num_vars + read_op_vars } else { 0 };
    let write_tower_vars = if has_write {
        num_vars + write_op_vars
    } else {
        0
    };
    let logup_tower_vars = if has_logup {
        num_vars + logup_op_vars
    } else {
        0
    };
    let max_tower_vars = read_tower_vars.max(write_tower_vars).max(logup_tower_vars);

    TowerShapeRecord {
        proof_idx,
        idx,
        air_idx,
        num_vars,
        read_op_vars,
        write_op_vars,
        logup_op_vars,
        has_read,
        has_write,
        has_logup,
        read_tower_vars,
        write_tower_vars,
        logup_tower_vars,
        max_tower_vars,
        max_layer_count: max_tower_vars.saturating_sub(1),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_chip_records(
    proof_idx: usize,
    idx: usize,
    air_idx: usize,
    fork_id: usize,
    is_first_air_idx: bool,
    chip_proof: &ZKVMChipProof<RecursionField>,
    circuit_vk: &VerifyingKey<RecursionField>,
    replay: &TowerReplayResult,
    schedule: &TowerTranscriptSchedule,
    tidx: usize,
    fork_final_sample_tidx: usize,
) -> Result<(
    TowerShapeRecord,
    TowerInputRecord,
    TowerLayerRecord,
    TowerTowerEvalRecord,
    TowerSumcheckRecord,
    Vec<EF>,
    Vec<crate::system::TowerMainPointRecord>,
    EF,
)> {
    let shape_record = build_tower_shape_record(proof_idx, idx, air_idx, chip_proof, circuit_vk);
    let layer_count = shape_record.max_layer_count;

    let read_count = usize::from(shape_record.has_read);
    let write_count = usize::from(shape_record.has_write);
    let logup_count = usize::from(shape_record.has_logup);

    let mut read_layers = vec![Vec::with_capacity(read_count); layer_count];
    let mut write_layers = vec![Vec::with_capacity(write_count); layer_count];
    let mut logup_layers = vec![Vec::with_capacity(logup_count); layer_count];

    for (spec_idx, rounds) in chip_proof.tower_proof.prod_specs_eval.iter().enumerate() {
        for layer_idx in 0..layer_count {
            let mut pair = [EF::ZERO; 2];
            if let Some(values) = rounds.get(layer_idx) {
                for (dst, src) in pair.iter_mut().zip(values.iter().take(2)) {
                    *dst = *src;
                }
            }
            if spec_idx < read_count && layer_idx + 1 < shape_record.read_tower_vars {
                read_layers[layer_idx].push(pair);
            } else if layer_idx + 1 < shape_record.write_tower_vars {
                write_layers[layer_idx].push(pair);
            }
        }
    }

    for rounds in &chip_proof.tower_proof.logup_specs_eval {
        #[allow(clippy::needless_range_loop)]
        for layer_idx in 0..layer_count {
            let mut quad = [EF::ZERO; 4];
            if let Some(values) = rounds.get(layer_idx) {
                for (dst, src) in quad.iter_mut().zip(values.iter().take(4)) {
                    *dst = *src;
                }
            }
            if layer_idx + 1 < shape_record.logup_tower_vars {
                logup_layers[layer_idx].push(quad);
            }
        }
    }

    let tower_record = TowerTowerEvalRecord {
        read_layers,
        write_layers,
        logup_layers,
    };

    let mut layer_record = TowerLayerRecord {
        proof_idx,
        idx,
        fork_id,
        is_first_air_idx,
        // TowerLayerAir starts after alpha/beta labels+sampling.
        tidx: tidx + tower_transcript_len::ALPHA_BETA_LEN,
        layer_claims: Vec::with_capacity(layer_count),
        lambdas: vec![EF::ZERO; layer_count],
        final_alpha: schedule.final_alpha,
        eq_at_r_primes: vec![EF::ZERO; layer_count],
        read_counts: vec![1; layer_count],
        write_counts: vec![1; layer_count],
        logup_counts: vec![1; layer_count],
        read_claims: vec![EF::ZERO; layer_count],
        read_prime_claims: vec![EF::ZERO; layer_count],
        write_claims: vec![EF::ZERO; layer_count],
        write_prime_claims: vec![EF::ZERO; layer_count],
        logup_claims: vec![EF::ZERO; layer_count],
        logup_prime_claims: vec![EF::ZERO; layer_count],
        sumcheck_claims: vec![EF::ZERO; layer_count],
        sumcheck_claim_outs: vec![EF::ZERO; layer_count],
    };

    for layer_idx in 0..layer_count {
        let read_len = tower_record
            .read_layers
            .get(layer_idx)
            .map(|rows| rows.len())
            .unwrap_or(0);
        let write_len = tower_record
            .write_layers
            .get(layer_idx)
            .map(|rows| rows.len())
            .unwrap_or(0);
        let logup_len = tower_record
            .logup_layers
            .get(layer_idx)
            .map(|rows| rows.len())
            .unwrap_or(0);
        eyre::ensure!(
            read_len <= 1 && write_len <= 1 && logup_len <= 1,
            "grouped tower layer {layer_idx} has too many specs: read={read_len}, write={write_len}, logup={logup_len}"
        );
        layer_record.read_counts[layer_idx] = read_len;
        layer_record.write_counts[layer_idx] = write_len;
        layer_record.logup_counts[layer_idx] = logup_len;
    }

    for layer_idx in 0..layer_count {
        layer_record
            .layer_claims
            .push(convert_logup_claim(chip_proof, layer_idx));
    }

    let mut sumcheck_record = TowerSumcheckRecord {
        proof_idx,
        idx,
        fork_id,
        is_first_air_idx,
        // Base tidx of tower layer 0. Each sumcheck row derives its own
        // per-layer offset from this base.
        tidx: tidx + tower_transcript_len::ALPHA_BETA_LEN,
        beta: schedule.beta,
        evals: Vec::new(),
        ris: Vec::new(),
        claims: vec![EF::ZERO; layer_count],
        read_counts: layer_record.read_counts.clone(),
        write_counts: layer_record.write_counts.clone(),
        logup_counts: layer_record.logup_counts.clone(),
    };

    // Native verifier processes every tower round through IOPVerifierState,
    // including root layer 0. Layer k has k+1 sumcheck rounds.
    let num_sumcheck_layers = layer_count;
    let total_sumcheck_rounds = num_sumcheck_layers * (num_sumcheck_layers + 1) / 2;

    for (k, round_msgs) in chip_proof.tower_proof.proofs.iter().enumerate() {
        if k >= num_sumcheck_layers {
            break;
        }
        for msg in round_msgs {
            sumcheck_record.evals.push(convert_sumcheck_evals(msg));
        }
    }
    let mut mus_record = vec![EF::ZERO; layer_count];

    let q0_claim = chip_proof
        .lk_out_evals
        .first()
        .and_then(|evals| evals.get(2))
        .copied()
        .unwrap_or(EF::ZERO);

    // Truncate ris to match the sumcheck trace's expected total_rounds.
    sumcheck_record.ris = schedule.ris[..total_sumcheck_rounds.min(schedule.ris.len())].to_vec();
    if !replay.layers.is_empty() && total_sumcheck_rounds > 0 {
        eyre::ensure!(
            sumcheck_record.ris.len() == sumcheck_record.evals.len(),
            "tower replay produced mismatched round counts: replay challenges={}, sumcheck eval rounds={}",
            sumcheck_record.ris.len(),
            sumcheck_record.evals.len()
        );
    }
    for (layer_idx, data) in replay.layers.iter().enumerate() {
        if layer_idx < layer_record.eq_at_r_primes.len() {
            layer_record.eq_at_r_primes[layer_idx] = data.eq_at_r;
            layer_record.lambdas[layer_idx] =
                schedule.lambdas.get(layer_idx).copied().unwrap_or(EF::ZERO);
            mus_record[layer_idx] = schedule.mus.get(layer_idx).copied().unwrap_or(EF::ZERO);
        }
        if layer_idx < layer_count {
            if layer_idx < sumcheck_record.claims.len() {
                sumcheck_record.claims[layer_idx] = data.claim_in;
            }
            if layer_idx < layer_record.sumcheck_claims.len() {
                layer_record.sumcheck_claims[layer_idx] = data.claim_in;
            }
            if layer_idx < layer_record.sumcheck_claim_outs.len() {
                layer_record.sumcheck_claim_outs[layer_idx] = data.claim_out;
            }
        }
    }

    for layer_idx in 0..layer_count {
        let lambda = layer_record
            .lambdas
            .get(layer_idx)
            .copied()
            .unwrap_or(EF::ZERO);
        let lambda_prime = layer_record.lambda_prime_at(layer_idx);
        let mu = mus_record.get(layer_idx).copied().unwrap_or(EF::ZERO);

        if let Some(rows) = tower_record.read_layers.get(layer_idx) {
            let (claim, prime) = accumulate_prod_claims(rows, lambda, lambda_prime, mu);
            layer_record.read_claims[layer_idx] = claim;
            layer_record.read_prime_claims[layer_idx] = prime;
        }
        if let Some(rows) = tower_record.write_layers.get(layer_idx) {
            let (claim, prime) = accumulate_prod_claims(rows, lambda, lambda_prime, mu);
            layer_record.write_claims[layer_idx] = claim;
            layer_record.write_prime_claims[layer_idx] = prime;
        }
        if let Some(rows) = tower_record.logup_layers.get(layer_idx) {
            let (claim, prime) = accumulate_logup_claims(rows, lambda, lambda_prime, mu);
            layer_record.logup_claims[layer_idx] = claim;
            layer_record.logup_prime_claims[layer_idx] = prime;
        }
    }

    // Compute eq_at_r_primes from ris and mus so that TowerLayerAir's eq values
    // match the sumcheck trace's eq_out on the sumcheck_output_bus.
    // Sumcheck internal layer k (0-indexed) → TowerLayerAir layer k.
    let num_sumcheck_layers = layer_count;
    for k in 0..num_sumcheck_layers {
        let eq = TowerSumcheckRecord::compute_eq_for_layer(
            k,
            schedule.beta,
            &mus_record,
            &sumcheck_record.ris,
        );
        if k < layer_record.eq_at_r_primes.len() {
            layer_record.eq_at_r_primes[k] = eq;
        }
    }

    let layer_output_claim = if layer_count == 0 {
        EF::ZERO
    } else {
        let layer_idx = layer_count - 1;
        let alpha = layer_record.lambda_at(layer_idx);
        let mut pow = EF::ONE;
        let read_weight = if shape_record.has_read {
            let weight = pow;
            pow *= alpha;
            if layer_record.read_active_at(layer_idx) {
                weight
            } else {
                EF::ZERO
            }
        } else {
            EF::ZERO
        };
        let write_weight = if shape_record.has_write {
            let weight = pow;
            pow *= alpha;
            if layer_record.write_active_at(layer_idx) {
                weight
            } else {
                EF::ZERO
            }
        } else {
            EF::ZERO
        };
        let (logup_p_weight, logup_q_weight) = if shape_record.has_logup {
            let p_weight = pow;
            let q_weight = pow * alpha;
            if layer_record.logup_active_at(layer_idx) {
                (p_weight, q_weight)
            } else {
                (EF::ZERO, EF::ZERO)
            }
        } else {
            (EF::ZERO, EF::ZERO)
        };
        let mu = mus_record.get(layer_idx).copied().unwrap_or(EF::ZERO);
        let logup_quad = tower_record
            .logup_layers
            .get(layer_idx)
            .and_then(|rows| rows.first())
            .copied()
            .unwrap_or([EF::ZERO; 4]);
        read_weight * layer_record.read_claims[layer_idx]
            + write_weight * layer_record.write_claims[layer_idx]
            + logup_p_weight * interpolate_pair([logup_quad[0], logup_quad[1]], mu)
            + logup_q_weight * interpolate_pair([logup_quad[2], logup_quad[3]], mu)
    };
    let layer_output_lambda = if layer_count == 0 {
        EF::ZERO
    } else {
        schedule.lambdas.last().copied().unwrap_or(EF::ZERO)
    };
    let layer_output_mu = if layer_count == 0 {
        EF::ZERO
    } else {
        schedule.mus.last().copied().unwrap_or(EF::ZERO)
    };
    let main_point_records = if layer_count == 0 || shape_record.num_vars == 0 {
        Vec::new()
    } else {
        let final_layer = layer_count - 1;
        let start = TowerSumcheckRecord::layer_start_index(final_layer);
        let end = start + TowerSumcheckRecord::layer_rounds(final_layer);
        eyre::ensure!(
            sumcheck_record.ris.len() >= end,
            "tower point source length {} is shorter than final layer end {}",
            sumcheck_record.ris.len(),
            end
        );
        let mut rt_tower = sumcheck_record.ris[start..end].to_vec();
        rt_tower.push(layer_output_mu);
        eyre::ensure!(
            rt_tower.len() >= shape_record.num_vars,
            "tower point length {} is shorter than main point length {}",
            rt_tower.len(),
            shape_record.num_vars
        );
        rt_tower[rt_tower.len() - shape_record.num_vars..]
            .iter()
            .copied()
            .enumerate()
            .map(|(round_idx, value)| crate::system::TowerMainPointRecord {
                proof_idx,
                idx,
                round_idx,
                value,
                lookup_count: 1,
            })
            .collect()
    };
    let mut read_out_evals = [EF::ZERO; 2];
    if let Some(values) = chip_proof.r_out_evals.first() {
        for (dst, src) in read_out_evals.iter_mut().zip(values.iter().take(2)) {
            *dst = *src;
        }
    }
    let mut write_out_evals = [EF::ZERO; 2];
    if let Some(values) = chip_proof.w_out_evals.first() {
        for (dst, src) in write_out_evals.iter_mut().zip(values.iter().take(2)) {
            *dst = *src;
        }
    }
    let mut logup_out_evals = [EF::ZERO; 4];
    if let Some(values) = chip_proof.lk_out_evals.first() {
        for (dst, src) in logup_out_evals.iter_mut().zip(values.iter().take(4)) {
            *dst = *src;
        }
    }
    let input_record = TowerInputRecord {
        proof_idx,
        idx,
        fork_id,
        tidx,
        fork_final_sample_tidx,
        n_logup: layer_count,
        alpha_logup: schedule.alpha_logup,
        beta: schedule.beta,
        read_out_evals,
        write_out_evals,
        logup_out_evals,
        has_read_out: !chip_proof.r_out_evals.is_empty(),
        has_write_out: !chip_proof.w_out_evals.is_empty(),
        has_logup_out: !chip_proof.lk_out_evals.is_empty(),
        has_read: shape_record.has_read,
        has_write: shape_record.has_write,
        has_logup: shape_record.has_logup,
        read_tower_vars: shape_record.read_tower_vars,
        write_tower_vars: shape_record.write_tower_vars,
        logup_tower_vars: shape_record.logup_tower_vars,
        max_layer_count: shape_record.max_layer_count,
        input_layer_claim: layer_output_claim,
        layer_output_lambda,
        layer_output_mu,
    };

    if std::env::var_os("CENO_TOWER_DEBUG").is_some() {
        for layer_idx in 0..layer_count {
            let alpha = layer_record.lambda_at(layer_idx);
            let mut pow = EF::ONE;
            let read_weight = if shape_record.has_read {
                let weight = pow;
                pow *= alpha;
                if layer_record.read_active_at(layer_idx) {
                    weight
                } else {
                    EF::ZERO
                }
            } else {
                EF::ZERO
            };
            let write_weight = if shape_record.has_write {
                let weight = pow;
                pow *= alpha;
                if layer_record.write_active_at(layer_idx) {
                    weight
                } else {
                    EF::ZERO
                }
            } else {
                EF::ZERO
            };
            let (logup_p_weight, logup_q_weight) = if shape_record.has_logup {
                let p_weight = pow;
                let q_weight = pow * alpha;
                if layer_record.logup_active_at(layer_idx) {
                    (p_weight, q_weight)
                } else {
                    (EF::ZERO, EF::ZERO)
                }
            } else {
                (EF::ZERO, EF::ZERO)
            };
            let read_prime = layer_record.read_prime_claims[layer_idx];
            let write_prime = layer_record.write_prime_claims[layer_idx];
            let logup_quad = tower_record
                .logup_layers
                .get(layer_idx)
                .and_then(|rows| rows.first())
                .copied()
                .unwrap_or([EF::ZERO; 4]);
            let logup_p_cross = logup_quad[0] * logup_quad[3] + logup_quad[1] * logup_quad[2];
            let logup_q_cross = logup_quad[2] * logup_quad[3];
            let expected = layer_record.eq_at_r_primes[layer_idx]
                * (read_weight * read_prime
                    + write_weight * write_prime
                    + logup_p_weight * logup_p_cross
                    + logup_q_weight * logup_q_cross);
            let replay_claim_out = replay
                .layers
                .get(layer_idx)
                .map(|layer| layer.claim_out)
                .unwrap_or(EF::ZERO);
            let replay_eq = replay
                .layers
                .get(layer_idx)
                .map(|layer| layer.eq_at_r)
                .unwrap_or(EF::ZERO);
            if expected != replay_claim_out {
                panic!(
                    "tower debug mismatch proof_idx={proof_idx} idx={idx} layer={layer_idx} expected={expected:?} replay_claim_out={replay_claim_out:?} alpha={alpha:?} eq={:?} replay_eq={replay_eq:?} weights=({read_weight:?},{write_weight:?},{logup_p_weight:?},{logup_q_weight:?}) primes=({read_prime:?},{write_prime:?},{logup_p_cross:?},{logup_q_cross:?}) active=({},{},{}) shape=({},{},{})",
                    layer_record.eq_at_r_primes[layer_idx],
                    layer_record.read_active_at(layer_idx),
                    layer_record.write_active_at(layer_idx),
                    layer_record.logup_active_at(layer_idx),
                    shape_record.has_read,
                    shape_record.has_write,
                    shape_record.has_logup,
                );
            }
        }
    }

    Ok((
        shape_record,
        input_record,
        layer_record,
        tower_record,
        sumcheck_record,
        mus_record,
        main_point_records,
        q0_claim,
    ))
}

fn build_chip_input_record(
    proof_idx: usize,
    idx: usize,
    fork_id: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
    circuit_vk: &VerifyingKey<RecursionField>,
    schedule: &TowerTranscriptSchedule,
    tidx: usize,
    fork_final_sample_tidx: usize,
) -> Result<TowerInputRecord> {
    let shape_record = build_tower_shape_record(proof_idx, idx, idx, chip_proof, circuit_vk);
    let layer_count = shape_record.max_layer_count;

    let read_count = usize::from(shape_record.has_read);
    let write_count = usize::from(shape_record.has_write);
    let logup_count = usize::from(shape_record.has_logup);
    let mut read_layers = vec![Vec::with_capacity(read_count); layer_count];
    let mut write_layers = vec![Vec::with_capacity(write_count); layer_count];
    let mut logup_layers = vec![Vec::with_capacity(logup_count); layer_count];

    for (spec_idx, rounds) in chip_proof.tower_proof.prod_specs_eval.iter().enumerate() {
        for layer_idx in 0..layer_count {
            let mut pair = [EF::ZERO; 2];
            if let Some(values) = rounds.get(layer_idx) {
                for (dst, src) in pair.iter_mut().zip(values.iter().take(2)) {
                    *dst = *src;
                }
            }
            if spec_idx < read_count && layer_idx + 1 < shape_record.read_tower_vars {
                read_layers[layer_idx].push(pair);
            } else if layer_idx + 1 < shape_record.write_tower_vars {
                write_layers[layer_idx].push(pair);
            }
        }
    }

    for rounds in &chip_proof.tower_proof.logup_specs_eval {
        for layer_idx in 0..layer_count {
            let mut quad = [EF::ZERO; 4];
            if let Some(values) = rounds.get(layer_idx) {
                for (dst, src) in quad.iter_mut().zip(values.iter().take(4)) {
                    *dst = *src;
                }
            }
            if layer_idx + 1 < shape_record.logup_tower_vars {
                logup_layers[layer_idx].push(quad);
            }
        }
    }

    for layer_idx in 0..layer_count {
        let read_len = read_layers.get(layer_idx).map(Vec::len).unwrap_or(0);
        let write_len = write_layers.get(layer_idx).map(Vec::len).unwrap_or(0);
        let logup_len = logup_layers.get(layer_idx).map(Vec::len).unwrap_or(0);
        eyre::ensure!(
            read_len <= 1 && write_len <= 1 && logup_len <= 1,
            "grouped tower layer {layer_idx} has too many specs: read={read_len}, write={write_len}, logup={logup_len}"
        );
    }

    let layer_output_claim = if layer_count == 0 {
        EF::ZERO
    } else {
        let layer_idx = layer_count - 1;
        let alpha = schedule.lambdas.get(layer_idx).copied().unwrap_or(EF::ZERO);
        let mut pow = EF::ONE;
        let read_weight = if shape_record.has_read {
            let weight = pow;
            pow *= alpha;
            if read_layers
                .get(layer_idx)
                .is_some_and(|rows| !rows.is_empty())
            {
                weight
            } else {
                EF::ZERO
            }
        } else {
            EF::ZERO
        };
        let write_weight = if shape_record.has_write {
            let weight = pow;
            pow *= alpha;
            if write_layers
                .get(layer_idx)
                .is_some_and(|rows| !rows.is_empty())
            {
                weight
            } else {
                EF::ZERO
            }
        } else {
            EF::ZERO
        };
        let (logup_p_weight, logup_q_weight) = if shape_record.has_logup {
            let p_weight = pow;
            let q_weight = pow * alpha;
            if logup_layers
                .get(layer_idx)
                .is_some_and(|rows| !rows.is_empty())
            {
                (p_weight, q_weight)
            } else {
                (EF::ZERO, EF::ZERO)
            }
        } else {
            (EF::ZERO, EF::ZERO)
        };
        let mu = schedule.mus.get(layer_idx).copied().unwrap_or(EF::ZERO);
        let read_claim = read_layers
            .get(layer_idx)
            .map(|rows| accumulate_prod_claims(rows, EF::ZERO, EF::ZERO, mu).0)
            .unwrap_or(EF::ZERO);
        let write_claim = write_layers
            .get(layer_idx)
            .map(|rows| accumulate_prod_claims(rows, EF::ZERO, EF::ZERO, mu).0)
            .unwrap_or(EF::ZERO);
        let logup_quad = logup_layers
            .get(layer_idx)
            .and_then(|rows| rows.first())
            .copied()
            .unwrap_or([EF::ZERO; 4]);
        read_weight * read_claim
            + write_weight * write_claim
            + logup_p_weight * interpolate_pair([logup_quad[0], logup_quad[1]], mu)
            + logup_q_weight * interpolate_pair([logup_quad[2], logup_quad[3]], mu)
    };

    let layer_output_lambda = if layer_count == 0 {
        EF::ZERO
    } else {
        schedule.lambdas.last().copied().unwrap_or(EF::ZERO)
    };
    let layer_output_mu = if layer_count == 0 {
        EF::ZERO
    } else {
        schedule.mus.last().copied().unwrap_or(EF::ZERO)
    };
    let mut read_out_evals = [EF::ZERO; 2];
    if let Some(values) = chip_proof.r_out_evals.first() {
        for (dst, src) in read_out_evals.iter_mut().zip(values.iter().take(2)) {
            *dst = *src;
        }
    }
    let mut write_out_evals = [EF::ZERO; 2];
    if let Some(values) = chip_proof.w_out_evals.first() {
        for (dst, src) in write_out_evals.iter_mut().zip(values.iter().take(2)) {
            *dst = *src;
        }
    }
    let mut logup_out_evals = [EF::ZERO; 4];
    if let Some(values) = chip_proof.lk_out_evals.first() {
        for (dst, src) in logup_out_evals.iter_mut().zip(values.iter().take(4)) {
            *dst = *src;
        }
    }

    Ok(TowerInputRecord {
        proof_idx,
        idx,
        fork_id,
        tidx,
        fork_final_sample_tidx,
        n_logup: layer_count,
        alpha_logup: schedule.alpha_logup,
        beta: schedule.beta,
        read_out_evals,
        write_out_evals,
        logup_out_evals,
        has_read_out: !chip_proof.r_out_evals.is_empty(),
        has_write_out: !chip_proof.w_out_evals.is_empty(),
        has_logup_out: !chip_proof.lk_out_evals.is_empty(),
        has_read: shape_record.has_read,
        has_write: shape_record.has_write,
        has_logup: shape_record.has_logup,
        read_tower_vars: shape_record.read_tower_vars,
        write_tower_vars: shape_record.write_tower_vars,
        logup_tower_vars: shape_record.logup_tower_vars,
        max_layer_count: shape_record.max_layer_count,
        input_layer_claim: layer_output_claim,
        layer_output_lambda,
        layer_output_mu,
    })
}

impl AirModule for TowerModule {
    fn num_airs(&self) -> usize {
        TowerModuleChipDiscriminants::COUNT
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let tower_shape_air = TowerShapeAir {
            air_shape_bus: self.bus_inventory.air_shape_bus,
            range_bus: self.bus_inventory.range_checker_bus,
            shape_bus: self.shape_bus,
            input_shape_bus: self.input_shape_bus,
        };
        let tower_activity_air = TowerActivityAir {
            range_bus: self.bus_inventory.range_checker_bus,
            shape_bus: self.shape_bus,
            activity_bus: self.activity_bus,
        };
        let gkr_input_air = TowerInputAir {
            tower_module_bus: self.bus_inventory.tower_module_bus,
            main_bus: self.bus_inventory.main_bus,
            forked_transcript_bus: self.bus_inventory.forked_transcript_bus,
            fork_final_sample_bus: self.bus_inventory.fork_final_sample_bus,
            input_shape_bus: self.input_shape_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
            sumcheck_challenge_bus: self.sumcheck_challenge_bus,
            send_main: true,
        };

        let gkr_layer_air = TowerLayerAir {
            forked_transcript_bus: self.bus_inventory.forked_transcript_bus,
            activity_bus: self.activity_bus,
            alpha_pow_bus: self.alpha_pow_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
            sumcheck_input_bus: self.sumcheck_input_bus,
            sumcheck_output_bus: self.sumcheck_output_bus,
            sumcheck_challenge_bus: self.sumcheck_challenge_bus,
        };

        let gkr_sumcheck_air = TowerLayerSumcheckAir::new(
            self.bus_inventory.forked_transcript_bus,
            self.bus_inventory.xi_randomness_bus,
            self.sumcheck_input_bus,
            self.sumcheck_output_bus,
            self.sumcheck_challenge_bus,
        );
        let tower_alpha_pow_air = TowerAlphaPowAir {
            alpha_pow_bus: self.alpha_pow_bus,
        };
        let tower_main_point_air = TowerMainPointAir {
            tower_point_bus: self.bus_inventory.tower_main_point_bus,
        };

        vec![
            Arc::new(tower_shape_air) as AirRef<_>,
            Arc::new(tower_activity_air) as AirRef<_>,
            Arc::new(gkr_input_air) as AirRef<_>,
            Arc::new(tower_alpha_pow_air) as AirRef<_>,
            Arc::new(gkr_layer_air) as AirRef<_>,
            Arc::new(gkr_sumcheck_air) as AirRef<_>,
            Arc::new(tower_main_point_air) as AirRef<_>,
        ]
    }
}

impl TowerModule {
    #[tracing::instrument(skip_all)]
    fn generate_blob(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        exp_bits_len_gen: &ExpBitsLenTraceGenerator,
    ) -> Result<TowerBlobCpu> {
        let _ = (self, preflights, exp_bits_len_gen);
        build_gkr_blob(child_vk, proofs, preflights)
    }
}

pub(crate) fn build_gkr_blob(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    preflights: &[Preflight],
) -> Result<TowerBlobCpu> {
    let mut shape_records = Vec::new();
    let mut input_records = Vec::new();
    let mut proof_q0_claims = Vec::new();
    let mut layer_records = Vec::new();
    let mut tower_records = Vec::new();
    let mut sumcheck_records = Vec::new();
    let mut mus_records = Vec::new();
    let mut main_point_records = Vec::new();
    let mut q0_claims = Vec::new();

    eyre::ensure!(
        proofs.len() == preflights.len(),
        "proof/preflight length mismatch"
    );

    for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights).enumerate() {
        let mut has_chip = false;

        let sorted_idx_by_chip: std::collections::BTreeMap<usize, usize> = preflight
            .proof_shape
            .sorted_trace_vdata
            .iter()
            .enumerate()
            .map(|(sorted_idx, (chip_idx, _))| (*chip_idx, sorted_idx))
            .collect();
        let mut sorted_pf_entries: Vec<_> = preflight.gkr.chips.iter().collect();
        sorted_pf_entries.sort_by_key(|entry| {
            (
                sorted_idx_by_chip
                    .get(&entry.chip_idx)
                    .copied()
                    .unwrap_or(usize::MAX),
                entry.chip_idx,
            )
        });
        let tower_idx_by_chip = sorted_pf_entries
            .iter()
            .enumerate()
            .map(|(tower_idx, entry)| (entry.chip_idx, tower_idx))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut selector_eval_records = preflight.main.selector_evals.clone();
        for record in &mut selector_eval_records {
            record.proof_idx = proof_idx;
        }
        let selector_point_lookup_counts =
            selector_formula_point_lookup_counts(&selector_eval_records);
        let mut selector_tower_point_counts =
            std::collections::BTreeMap::<(usize, usize), usize>::new();
        for record in &selector_eval_records {
            if record.point_source != MainSelectorPointSourceKind::TowerMain {
                continue;
            }
            let Some(tower_idx) = tower_idx_by_chip.get(&record.air_idx).copied() else {
                continue;
            };
            for round_idx in 0..record.out_point.len() {
                let count = selector_point_lookup_counts
                    .get(&(
                        record.proof_idx,
                        record.idx,
                        record.air_idx,
                        record.selector_idx,
                        round_idx,
                    ))
                    .copied()
                    .unwrap_or(0);
                if count != 0 {
                    *selector_tower_point_counts
                        .entry((tower_idx, round_idx))
                        .or_default() += 1;
                }
            }
        }
        for (entry_idx, pf_entry) in sorted_pf_entries.into_iter().enumerate() {
            let chip_idx = pf_entry.chip_idx;
            let chip_proof = proof
                .chip_proofs
                .get(&chip_idx)
                .ok_or_else(|| eyre::eyre!("missing chip proof for chip {chip_idx}"))?;
            has_chip = true;
            // Access the fork log directly using fork_idx and fork-local tidx.
            let mut ts = {
                let fork_log = preflight.fork_log(pf_entry.fork_idx);
                ReadOnlyTranscript::new(fork_log, pf_entry.tidx)
            };
            let transcript_schedule = record_gkr_transcript(&mut ts, chip_idx, chip_proof);

            let circuit_vk = circuit_vk_for_idx(child_vk, chip_idx)
                .ok_or_else(|| eyre::eyre!("missing circuit verifying key for index {chip_idx}"))?;

            let replay = &pf_entry.tower_replay;
            let schedule = &transcript_schedule;

            // Use sequential index for NestedForLoop compatibility (idx must increment
            // by 0 or 1 within each proof_idx group).
            let idx = entry_idx;
            let tower_air_tidx = tower_pre_alpha_tidx(chip_proof, pf_entry.tidx);
            let fork_final_sample_tidx = preflight
                .fork_log(pf_entry.fork_idx)
                .len()
                .saturating_sub(D_EF);
            let (
                shape_record,
                chip_input_record,
                layer_record,
                tower_record,
                sumcheck_record,
                mus_record,
                mut chip_main_point_records,
                q0_claim,
            ) = build_chip_records(
                proof_idx,
                idx,
                entry_idx,
                pf_entry.fork_idx,
                entry_idx == 0,
                chip_proof,
                circuit_vk,
                replay,
                schedule,
                tower_air_tidx,
                fork_final_sample_tidx,
            )?;
            for record in &mut chip_main_point_records {
                record.lookup_count += selector_tower_point_counts
                    .get(&(idx, record.round_idx))
                    .copied()
                    .unwrap_or(0);
            }
            if std::env::var_os("CENO_REC_V2_DEBUG_TOWER").is_some() {
                let out_eval_span = tower_air_tidx.saturating_sub(pf_entry.tidx);
                let compact_layer_span = (0..shape_record.max_layer_count)
                    .map(|layer_idx| {
                        tower_transcript_len::compact_layer_span(
                            layer_idx,
                            layer_record
                                .read_counts
                                .get(layer_idx)
                                .copied()
                                .unwrap_or(0)
                                != 0,
                            layer_record
                                .write_counts
                                .get(layer_idx)
                                .copied()
                                .unwrap_or(0)
                                != 0,
                            layer_record
                                .logup_counts
                                .get(layer_idx)
                                .copied()
                                .unwrap_or(0)
                                != 0,
                        )
                    })
                    .sum::<usize>();
                let computed_tower_span =
                    out_eval_span + tower_transcript_len::ALPHA_BETA_LEN + compact_layer_span;
                let fork_len = preflight.fork_log(pf_entry.fork_idx).len();
                eprintln!(
                    "rec-v2-debug module=tower source=trace proof_idx={proof_idx} fork_id={} chip_idx={} fork_len={} tower_start={} tower_alpha_tidx={} computed_span={} final_sample_tidx={} expected_final_tidx={} has_read_out={} has_write_out={} has_logup_out={} n_logup={}",
                    pf_entry.fork_idx,
                    chip_idx,
                    fork_len,
                    pf_entry.tidx,
                    tower_air_tidx,
                    computed_tower_span,
                    pf_entry.tidx + computed_tower_span,
                    fork_len.saturating_sub(D_EF),
                    chip_input_record.has_read_out,
                    chip_input_record.has_write_out,
                    chip_input_record.has_logup_out,
                    chip_input_record.n_logup,
                );
            }

            input_records.push(chip_input_record);
            proof_q0_claims.push(q0_claim);
            shape_records.push(shape_record);
            layer_records.push(layer_record);
            tower_records.push(tower_record);
            sumcheck_records.push(sumcheck_record);
            mus_records.push(mus_record);
            main_point_records.extend(chip_main_point_records);
            q0_claims.push(q0_claim);
        }

        if !has_chip {
            input_records.push(TowerInputRecord {
                proof_idx,
                idx: 0,
                ..Default::default()
            });
            proof_q0_claims.push(EF::ZERO);
            shape_records.push(TowerShapeRecord {
                idx: 0,
                proof_idx,
                ..Default::default()
            });
            layer_records.push(TowerLayerRecord {
                idx: 0,
                proof_idx,
                is_first_air_idx: true,
                ..Default::default()
            });
            tower_records.push(TowerTowerEvalRecord::default());
            sumcheck_records.push(TowerSumcheckRecord {
                proof_idx,
                idx: 0,
                is_first_air_idx: true,
                ..Default::default()
            });
            mus_records.push(vec![]);
            q0_claims.push(EF::ZERO);
        }
    }

    if input_records.is_empty() {
        shape_records.push(TowerShapeRecord::default());
        input_records.push(TowerInputRecord::default());
        proof_q0_claims.push(EF::ZERO);
        layer_records.push(TowerLayerRecord::default());
        sumcheck_records.push(TowerSumcheckRecord::default());
        tower_records.push(TowerTowerEvalRecord::default());
        mus_records.push(vec![]);
        q0_claims.push(EF::ZERO);
    }

    Ok(TowerBlobCpu {
        shape_records,
        input_records,
        proof_q0_claims,
        layer_records,
        tower_records,
        sumcheck_records,
        mus_records,
        main_point_records,
        q0_claims,
    })
}

pub(crate) fn build_tower_input_records(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    preflights: &[Preflight],
) -> Result<Vec<TowerInputRecord>> {
    eyre::ensure!(
        proofs.len() == preflights.len(),
        "proof/preflight length mismatch"
    );

    let mut input_records = Vec::new();
    for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights).enumerate() {
        let sorted_idx_by_chip: std::collections::BTreeMap<usize, usize> = preflight
            .proof_shape
            .sorted_trace_vdata
            .iter()
            .enumerate()
            .map(|(sorted_idx, (chip_idx, _))| (*chip_idx, sorted_idx))
            .collect();
        let mut sorted_pf_entries: Vec<_> = preflight.gkr.chips.iter().collect();
        sorted_pf_entries.sort_by_key(|entry| {
            (
                sorted_idx_by_chip
                    .get(&entry.chip_idx)
                    .copied()
                    .unwrap_or(usize::MAX),
                entry.chip_idx,
            )
        });

        for (entry_idx, pf_entry) in sorted_pf_entries.into_iter().enumerate() {
            let chip_idx = pf_entry.chip_idx;
            let chip_proof = proof
                .chip_proofs
                .get(&chip_idx)
                .ok_or_else(|| eyre::eyre!("missing chip proof for chip {chip_idx}"))?;
            let mut ts = {
                let fork_log = preflight.fork_log(pf_entry.fork_idx);
                ReadOnlyTranscript::new(fork_log, pf_entry.tidx)
            };
            let transcript_schedule = record_gkr_transcript(&mut ts, chip_idx, chip_proof);
            let circuit_vk = circuit_vk_for_idx(child_vk, chip_idx)
                .ok_or_else(|| eyre::eyre!("missing circuit verifying key for index {chip_idx}"))?;
            let tower_air_tidx = tower_pre_alpha_tidx(chip_proof, pf_entry.tidx);
            let fork_final_sample_tidx = preflight
                .fork_log(pf_entry.fork_idx)
                .len()
                .saturating_sub(D_EF);
            input_records.push(build_chip_input_record(
                proof_idx,
                entry_idx,
                pf_entry.fork_idx,
                chip_proof,
                circuit_vk,
                &transcript_schedule,
                tower_air_tidx,
                fork_final_sample_tidx,
            )?);
        }
    }

    Ok(input_records)
}

pub(crate) fn build_tower_main_point_records(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    preflights: &[Preflight],
) -> Result<Vec<crate::system::TowerMainPointRecord>> {
    Ok(build_gkr_blob(child_vk, proofs, preflights)?.main_point_records)
}

pub(crate) fn collect_tower_range_checks(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    preflights: &[Preflight],
) -> Result<Vec<usize>> {
    let mut values = Vec::new();
    eyre::ensure!(
        proofs.len() == preflights.len(),
        "proof/preflight length mismatch"
    );

    for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights).enumerate() {
        let sorted_idx_by_chip: std::collections::BTreeMap<usize, usize> = preflight
            .proof_shape
            .sorted_trace_vdata
            .iter()
            .enumerate()
            .map(|(sorted_idx, (chip_idx, _))| (*chip_idx, sorted_idx))
            .collect();
        let mut sorted_pf_entries: Vec<_> = preflight.gkr.chips.iter().collect();
        sorted_pf_entries.sort_by_key(|entry| {
            (
                sorted_idx_by_chip
                    .get(&entry.chip_idx)
                    .copied()
                    .unwrap_or(usize::MAX),
                entry.chip_idx,
            )
        });

        for (entry_idx, pf_entry) in sorted_pf_entries.into_iter().enumerate() {
            let chip_idx = pf_entry.chip_idx;
            let chip_proof = proof
                .chip_proofs
                .get(&chip_idx)
                .ok_or_else(|| eyre::eyre!("missing chip proof for chip {chip_idx}"))?;
            let circuit_vk = circuit_vk_for_idx(child_vk, chip_idx)
                .ok_or_else(|| eyre::eyre!("missing circuit verifying key for index {chip_idx}"))?;
            let record =
                build_tower_shape_record(proof_idx, entry_idx, entry_idx, chip_proof, circuit_vk);

            for tower_vars in [
                record.read_tower_vars,
                record.write_tower_vars,
                record.logup_tower_vars,
            ] {
                values.push(record.max_tower_vars - tower_vars);
            }

            for layer_idx in 0..record.max_layer_count {
                for kind in 0..shape::TOWER_ACTIVITY_KINDS {
                    let (has_kind, tower_vars) = match kind {
                        shape::TOWER_ACTIVITY_READ => (record.has_read, record.read_tower_vars),
                        shape::TOWER_ACTIVITY_WRITE => (record.has_write, record.write_tower_vars),
                        shape::TOWER_ACTIVITY_LOGUP => (record.has_logup, record.logup_tower_vars),
                        _ => unreachable!(),
                    };
                    let active = has_kind && layer_idx + 1 < tower_vars;
                    if active {
                        values.push(tower_vars - 1 - layer_idx);
                    } else if tower_vars == 0 {
                        values.push(layer_idx + 1);
                    } else {
                        values.push(layer_idx + 1 - tower_vars);
                    }
                }
            }
        }
    }

    Ok(values)
}

pub(crate) fn record_gkr_transcript<TS>(
    ts: &mut TS,
    _chip_idx: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
) -> TowerTranscriptSchedule
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    // Bind read/write/lookup out evals into transcript before deriving tower
    // challenges. Mirrors v1 verifier: append_field_element_ext for each eval.
    let mut _out_eval_count = 0usize;
    for eval in chip_proof
        .r_out_evals
        .iter()
        .chain(chip_proof.w_out_evals.iter())
        .chain(chip_proof.lk_out_evals.iter())
        .flatten()
    {
        ts.observe_ext(*eval);
        _out_eval_count += 1;
    }

    // Mirror native: get_challenge_pows calls
    // transcript.sample_and_append_challenge(b"combine subset evals")
    // which does append_message(label) then read_challenge().
    transcript_observe_label(ts, b"combine subset evals");
    let alpha_logup = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);

    // Mirror native: transcript.sample_and_append_vec(b"product_sum", log2_num_fanin)
    // which does append_message(label) then sample_vec(1).
    transcript_observe_label(ts, b"product_sum");
    let beta = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);

    // Reconstruct the transcript events consumed by tower-related AIRs.
    // This keeps preflight transcript history aligned with TowerLayer/Sumcheck/
    // ProdClaim/LogupClaim transcript bus interactions.
    let read_count = chip_proof.r_out_evals.len();
    let layer_count = chip_proof
        .tower_proof
        .logup_specs_eval
        .iter()
        .map(Vec::len)
        .chain(chip_proof.tower_proof.prod_specs_eval.iter().map(Vec::len))
        .max()
        .unwrap_or(0);

    let log2_num_fanin: usize = 1; // ceil_log2(NUM_FANIN=2) = 1

    let mut lambdas = Vec::with_capacity(layer_count);
    let mut mus = Vec::with_capacity(layer_count);
    let mut ris = Vec::new();

    for layer_idx in 0..layer_count {
        // For layer 0, there is no transcript lambda sample — the native verifier
        // goes straight from beta to sumcheck. Use alpha_logup as the weighting
        // challenge for the root layer (matching native's initial alpha_pows).
        // For layers > 0, this sample corresponds to get_challenge_pows in the
        // native verifier (the "next alpha" after the previous round's merge).
        let lambda = if layer_idx > 0 {
            transcript_observe_label(ts, b"combine subset evals");
            FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts)
        } else {
            alpha_logup
        };
        lambdas.push(lambda);

        if let Some(round_msgs) = chip_proof.tower_proof.proofs.get(layer_idx) {
            // Mirror native sumcheck IOPVerifierState::verify init:
            // append_message(max_num_variables.to_leBytes())
            // append_message(max_degree.to_leBytes())
            let max_num_variables = (layer_idx + 1) * log2_num_fanin;
            let max_degree: usize = 3; // NUM_FANIN + 1
            transcript_observe_label(ts, &max_num_variables.to_le_bytes());
            transcript_observe_label(ts, &max_degree.to_le_bytes());

            for (_ri_idx, msg) in round_msgs.iter().enumerate() {
                for eval in &msg.evaluations {
                    ts.observe_ext(*eval);
                }
                // Mirror native: sample_and_append_challenge(b"Internal round")
                transcript_observe_label(ts, b"Internal round");
                let ri = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
                ris.push(ri);
            }
        }

        observe_active_tower_eval_round(ts, chip_proof, layer_idx);

        // Mirror native: sample_and_append_vec(b"merge", log2_num_fanin)
        transcript_observe_label(ts, b"merge");
        let mu = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        mus.push(mu);
    }
    let final_alpha = if layer_count > 0 {
        transcript_observe_label(ts, b"combine subset evals");
        FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts)
    } else {
        EF::ZERO
    };

    let _ = read_count;
    TowerTranscriptSchedule {
        alpha_logup,
        beta,
        lambdas,
        final_alpha,
        mus,
        ris,
    }
}

fn observe_active_tower_eval_round<TS>(
    ts: &mut TS,
    chip_proof: &ZKVMChipProof<RecursionField>,
    round: usize,
) where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    for spec_rounds in &chip_proof.tower_proof.prod_specs_eval {
        if let Some(evals) = spec_rounds.get(round) {
            for eval in evals {
                ts.observe_ext(*eval);
            }
        }
    }
    for spec_rounds in &chip_proof.tower_proof.logup_specs_eval {
        if let Some(evals) = spec_rounds.get(round) {
            for eval in evals {
                ts.observe_ext(*eval);
            }
        }
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>> for TowerModule {
    type ModuleSpecificCtx<'a> = ExpBitsLenTraceGenerator;

    #[tracing::instrument(skip_all)]
    fn generate_proving_ctxs(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        ctx: &ExpBitsLenTraceGenerator,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let blob = match self.generate_blob(child_vk, proofs, preflights, ctx) {
            Ok(blob) => blob,
            Err(err) => {
                error!(?err, "failed to build GKR trace blob");
                return None;
            }
        };
        let chips = [
            TowerModuleChip::Shape,
            TowerModuleChip::Activity,
            TowerModuleChip::Input,
            TowerModuleChip::AlphaPow,
            TowerModuleChip::Layer,
            TowerModuleChip::LayerSumcheck,
            TowerModuleChip::MainPoint,
        ];

        let span = tracing::Span::current();
        chips
            .par_iter()
            .map(|chip| {
                let _guard = span.enter();
                chip.generate_proving_ctx(
                    &blob,
                    required_heights.and_then(|heights| heights.get(chip.index()).copied()),
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect()
    }
}

// To reduce the number of structs and trait implementations, we collect them into a single enum
// with enum dispatch.
#[derive(strum_macros::Display, strum::EnumDiscriminants)]
#[strum_discriminants(derive(strum_macros::EnumCount))]
#[strum_discriminants(repr(usize))]
enum TowerModuleChip {
    Shape,
    Activity,
    Input,
    AlphaPow,
    Layer,
    LayerSumcheck,
    MainPoint,
}

impl TowerModuleChip {
    fn index(&self) -> usize {
        TowerModuleChipDiscriminants::from(self) as usize
    }
}

impl RowMajorChip<F> for TowerModuleChip {
    type Ctx<'a> = TowerBlobCpu;

    #[tracing::instrument(
        name = "wrapper.generate_trace",
        level = "trace",
        skip_all,
        fields(air = %self)
    )]
    fn generate_trace(
        &self,
        blob: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        use TowerModuleChip::*;
        match self {
            Shape => TowerShapeTraceGenerator
                .generate_trace(&blob.shape_records.as_slice(), required_height),
            Activity => TowerActivityTraceGenerator
                .generate_trace(&blob.shape_records.as_slice(), required_height),
            Input => TowerInputTraceGenerator.generate_trace(
                &(&blob.input_records, &blob.proof_q0_claims),
                required_height,
            ),
            AlphaPow => TowerAlphaPowTraceGenerator
                .generate_trace(&blob.layer_records.as_slice(), required_height),
            Layer => TowerLayerTraceGenerator.generate_trace(
                &(
                    &blob.layer_records,
                    &blob.tower_records,
                    &blob.mus_records,
                    &blob.q0_claims,
                ),
                required_height,
            ),
            LayerSumcheck => TowerSumcheckTraceGenerator.generate_trace(
                &(&blob.sumcheck_records, &blob.mus_records),
                required_height,
            ),
            MainPoint => TowerMainPointTraceGenerator
                .generate_trace(&blob.main_point_records.as_slice(), required_height),
        }
    }
}

#[cfg(feature = "cuda")]
mod cuda_tracegen {
    use openvm_cuda_backend::GpuBackend;

    use super::*;
    use crate::{
        cuda::{GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, vk::VerifyingKeyGpu},
        tracegen::cuda::generate_gpu_proving_ctx,
    };

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for TowerModule {
        type ModuleSpecificCtx<'a> = ExpBitsLenTraceGenerator;

        #[tracing::instrument(skip_all)]
        fn generate_proving_ctxs(
            &self,
            child_vk: &VerifyingKeyGpu,
            proofs: &[ProofGpu],
            preflights: &[PreflightGpu],
            exp_bits_len_gen: &ExpBitsLenTraceGenerator,
            required_heights: Option<&[usize]>,
        ) -> Option<Vec<AirProvingContext<GpuBackend>>> {
            let proofs_cpu: Vec<_> = proofs.iter().map(|proof| proof.cpu.clone()).collect();
            let preflights_cpu: Vec<_> = preflights
                .iter()
                .map(|preflight| preflight.cpu.clone())
                .collect();
            let blob = match self.generate_blob(
                &child_vk.cpu,
                &proofs_cpu,
                &preflights_cpu,
                exp_bits_len_gen,
            ) {
                Ok(blob) => blob,
                Err(err) => {
                    error!(?err, "failed to build GKR trace blob (cuda)");
                    return None;
                }
            };

            let chips = [
                TowerModuleChip::Shape,
                TowerModuleChip::Activity,
                TowerModuleChip::Input,
                TowerModuleChip::Layer,
                TowerModuleChip::ProdReadClaim,
                TowerModuleChip::ProdWriteClaim,
                TowerModuleChip::LogupClaim,
                TowerModuleChip::LayerSumcheck,
            ];

            chips
                .iter()
                .map(|chip| {
                    generate_gpu_proving_ctx(
                        chip,
                        &blob,
                        required_heights.and_then(|heights| heights.get(chip.index()).copied()),
                    )
                })
                .collect()
        }
    }
}
