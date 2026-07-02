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
#[cfg(test)]
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use recursion_circuit::primitives::exp_bits_len::ExpBitsLenTraceGenerator;
use strum::EnumCount;
use tracing::error;

use crate::{
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, Preflight, RecursionField,
        RecursionProof, RecursionVk, TowerChipTranscriptRange, TraceGenModule,
    },
    tower::{
        bus::{TowerLayerInputBus, TowerLayerOutputBus},
        input::{TowerInputAir, TowerInputRecord, TowerInputTraceGenerator},
        layer::{
            TowerLayerAir, TowerLayerRecord, TowerLayerTraceGenerator, TowerLogupClaimAir,
            TowerLogupSumCheckClaimTraceGenerator, TowerProdReadClaimAir,
            TowerProdReadSumCheckClaimTraceGenerator, TowerProdWriteClaimAir,
            TowerProdWriteSumCheckClaimTraceGenerator,
        },
        sumcheck::{TowerLayerSumcheckAir, TowerSumcheckRecord, TowerSumcheckTraceGenerator},
    },
    tracegen::{ModuleChip, RowMajorChip},
    utils::transcript_observe_label,
};
use ceno_zkvm::{scheme::ZKVMChipProof, structs::VerifyingKey};
use eyre::Result;

// Internal bus definitions
mod bus;
pub use bus::{
    TowerClaimInputBus, TowerClaimLayerInputMessage, TowerClaimOp, TowerLogupClaimBus,
    TowerLogupClaimMessage, TowerLogupRootBus, TowerLogupRootInputBus, TowerLogupRootInputMessage,
    TowerLogupRootMessage, TowerProdInitMessage, TowerProdReadClaimBus, TowerProdRootInputMessage,
    TowerProdRootMessage, TowerProdSumClaimMessage, TowerProdWriteClaimBus, TowerReadInitBus,
    TowerReadRootBus, TowerReadRootInputBus, TowerSumcheckChallengeBus,
    TowerSumcheckChallengeMessage, TowerSumcheckInputBus, TowerSumcheckInputMessage,
    TowerSumcheckOutputBus, TowerSumcheckOutputMessage, TowerWriteInitBus, TowerWriteRootBus,
    TowerWriteRootInputBus,
};

/// Transcript field-element lengths per tower operation.
///
/// These match the native verifier (gkr-backend `BasicTranscript`) which absorbs
/// labels before each sample via `sample_and_append_challenge` /
/// `sample_and_append_vec`.  The recursion transcript must reproduce the exact
/// same sponge sequence.
pub mod tower_transcript_len {
    use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;

    // Label field-element counts: ceil(byte_len / 4).
    // b"combine subset evals" = 20 bytes → 5 field elements
    pub const LABEL_COMBINE: usize = 5;
    // b"product_sum" = 11 bytes → 3 field elements
    pub const LABEL_PRODUCT_SUM: usize = 3;
    // b"Internal round" = 14 bytes → 4 field elements
    pub const LABEL_INTERNAL_ROUND: usize = 4;
    // b"merge" = 5 bytes → 2 field elements
    pub const LABEL_MERGE: usize = 2;
    // usize::to_le_bytes() = 8 bytes → 2 field elements (64-bit platform)
    pub const LABEL_USIZE: usize = 2;

    pub const LABEL_COMBINE_VALUES: [usize; LABEL_COMBINE] =
        [1651339107, 543518313, 1935832435, 1696625765, 1936482678];
    pub const LABEL_PRODUCT_SUM_VALUES: [usize; LABEL_PRODUCT_SUM] =
        [1685025392, 1601463157, 7173491];
    pub const LABEL_INTERNAL_ROUND_VALUES: [usize; LABEL_INTERNAL_ROUND] =
        [1702129225, 1818324594, 1970237984, 25710];
    pub const LABEL_MERGE_VALUES: [usize; LABEL_MERGE] = [1735550317, 101];

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

    /// Post-sumcheck tidx span: claim observation slots (4*D_EF) + MERGE_LEN.
    /// This is the tidx gap from `tidx_after_sumcheck` to `tidx_end`.
    pub const POST_SUMCHECK_LEN: usize = 4 * D_EF + MERGE_LEN;

    /// Gap between consecutive sumcheck blocks across GKR layers:
    /// post-sumcheck of previous layer + pre-sumcheck of next layer.
    pub const LAYER_GAP_LEN: usize = POST_SUMCHECK_LEN + ALPHA_LEN + SUMCHECK_INIT_LEN;

    /// Tidx span of layer `layer_idx` (includes claim slots + transcript ops).
    /// Layer 0 (root): POST_SUMCHECK_LEN (no lambda sample — uses alpha_logup).
    /// Layer j>0: ALPHA_LEN + SUMCHECK_INIT_LEN + j*ROUND_LEN + POST_SUMCHECK_LEN.
    pub const fn layer_span(layer_idx: usize) -> usize {
        if layer_idx == 0 {
            POST_SUMCHECK_LEN
        } else {
            ALPHA_LEN + SUMCHECK_INIT_LEN + layer_idx * ROUND_LEN + POST_SUMCHECK_LEN
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
    /// Layer 0: 0.
    /// Layer j>0: ALPHA_LEN + SUMCHECK_INIT_LEN + j*ROUND_LEN.
    pub const fn claim_offset_in_layer(layer_idx: usize) -> usize {
        if layer_idx == 0 {
            0
        } else {
            ALPHA_LEN + SUMCHECK_INIT_LEN + layer_idx * ROUND_LEN
        }
    }
}

// Sub-modules for different AIRs
pub mod input;
pub mod layer;
pub mod sumcheck;
#[allow(clippy::module_inception)]
mod tower;
pub(crate) use tower::{TowerReplayResult, replay_tower_proof_poseidon};
pub struct TowerModule {
    // Global bus inventory
    bus_inventory: BusInventory,
    // Module buses
    layer_input_bus: TowerLayerInputBus,
    layer_output_bus: TowerLayerOutputBus,
    sumcheck_input_bus: TowerSumcheckInputBus,
    sumcheck_output_bus: TowerSumcheckOutputBus,
    sumcheck_challenge_bus: TowerSumcheckChallengeBus,
    claim_input_bus: TowerClaimInputBus,
    prod_read_claim_bus: TowerProdReadClaimBus,
    prod_write_claim_bus: TowerProdWriteClaimBus,
    logup_claim_bus: TowerLogupClaimBus,
    read_root_input_bus: TowerReadRootInputBus,
    read_root_bus: TowerReadRootBus,
    read_init_bus: TowerReadInitBus,
    write_root_input_bus: TowerWriteRootInputBus,
    write_root_bus: TowerWriteRootBus,
    write_init_bus: TowerWriteInitBus,
    logup_root_input_bus: TowerLogupRootInputBus,
    logup_root_bus: TowerLogupRootBus,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TowerTowerEvalRecord {
    pub(crate) read_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) write_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) logup_layers: Vec<Vec<[EF; 4]>>,
    pub(crate) read_active: Vec<Vec<bool>>,
    pub(crate) write_active: Vec<Vec<bool>>,
    pub(crate) logup_active: Vec<Vec<bool>>,
}

pub(crate) struct TowerBlobCpu {
    pub(crate) input_records: Vec<TowerInputRecord>,
    pub(crate) layer_records: Vec<TowerLayerRecord>,
    pub(crate) tower_records: Vec<TowerTowerEvalRecord>,
    pub(crate) sumcheck_records: Vec<TowerSumcheckRecord>,
    pub(crate) mus_records: Vec<Vec<EF>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TowerTranscriptSchedule {
    pub(crate) alpha_logup: EF,
    pub(crate) beta: EF,
    pub(crate) lambdas: Vec<EF>,
    pub(crate) mus: Vec<EF>,
    pub(crate) ris: Vec<EF>,
}

impl TowerModule {
    pub fn new(_vk: &RecursionVk, b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        TowerModule {
            bus_inventory,
            layer_input_bus: TowerLayerInputBus::new(b.new_bus_idx()),
            layer_output_bus: TowerLayerOutputBus::new(b.new_bus_idx()),
            sumcheck_input_bus: TowerSumcheckInputBus::new(b.new_bus_idx()),
            sumcheck_output_bus: TowerSumcheckOutputBus::new(b.new_bus_idx()),
            sumcheck_challenge_bus: TowerSumcheckChallengeBus::new(b.new_bus_idx()),
            claim_input_bus: TowerClaimInputBus::new(b.new_bus_idx()),
            prod_read_claim_bus: TowerProdReadClaimBus::new(b.new_bus_idx()),
            prod_write_claim_bus: TowerProdWriteClaimBus::new(b.new_bus_idx()),
            logup_claim_bus: TowerLogupClaimBus::new(b.new_bus_idx()),
            read_root_input_bus: TowerReadRootInputBus::new(b.new_bus_idx()),
            read_root_bus: TowerReadRootBus::new(b.new_bus_idx()),
            read_init_bus: TowerReadInitBus::new(b.new_bus_idx()),
            write_root_input_bus: TowerWriteRootInputBus::new(b.new_bus_idx()),
            write_root_bus: TowerWriteRootBus::new(b.new_bus_idx()),
            write_init_bus: TowerWriteInitBus::new(b.new_bus_idx()),
            logup_root_input_bus: TowerLogupRootInputBus::new(b.new_bus_idx()),
            logup_root_bus: TowerLogupRootBus::new(b.new_bus_idx()),
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
        for (&chip_id, chip_instances) in &proof.chip_proofs {
            for (instance_idx, chip_proof) in chip_instances.iter().enumerate() {
                let tidx = ts.len();
                let (_, tower_replay) =
                    record_and_replay_tower_preflight(ts, child_vk, chip_id, chip_proof);

                preflight.gkr.chips.push(TowerChipTranscriptRange {
                    chip_id,
                    instance_idx,
                    num_layers: circuit_vk_for_idx(child_vk, chip_id)
                        .map(|circuit_vk| tower_layer_count_from_vk(circuit_vk, chip_proof))
                        .unwrap_or(0),
                    tidx,
                    fork_idx: 0, // unused in forked flow
                    tower_replay,
                });
            }
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

fn ext_pow(base: EF, exp: usize) -> EF {
    (0..exp).fold(EF::ONE, |acc, _| acc * base)
}

fn accumulate_prod_claims(
    rows: &[[EF; 2]],
    lambda: EF,
    lambda_prime: EF,
    mu: EF,
    lambda_start: EF,
    lambda_prime_start: EF,
) -> (EF, EF) {
    let mut pow_lambda = lambda_start;
    let mut pow_lambda_prime = lambda_prime_start;
    let mut acc_sum = EF::ZERO;
    let mut acc_sum_prime = EF::ZERO;

    for pair in rows {
        let p_xi = interpolate_pair(*pair, mu);
        let prime_product = pair[0] * pair[1];
        acc_sum += pow_lambda * p_xi;
        acc_sum_prime += pow_lambda_prime * prime_product;
        pow_lambda *= lambda;
        pow_lambda_prime *= lambda_prime;
    }

    (acc_sum, acc_sum_prime)
}

fn accumulate_logup_claims(
    rows: &[[EF; 4]],
    lambda: EF,
    lambda_prime: EF,
    mu: EF,
    lambda_start: EF,
    lambda_prime_start: EF,
) -> (EF, EF) {
    let mut pow_lambda = lambda_start;
    let mut pow_lambda_prime = lambda_prime_start;
    let mut acc_sum = EF::ZERO;
    let mut acc_eval = EF::ZERO;

    for quad in rows {
        let p_vals = [quad[0], quad[1]];
        let q_vals = [quad[2], quad[3]];
        let p_xi = interpolate_pair(p_vals, mu);
        let q_xi = interpolate_pair(q_vals, mu);
        acc_sum += pow_lambda * (p_xi + lambda * q_xi);
        let p_cross = quad[0] * quad[3] + quad[1] * quad[2];
        let q_cross = quad[2] * quad[3];
        acc_eval += pow_lambda_prime * (p_cross + lambda_prime * q_cross);
        pow_lambda *= lambda * lambda;
        pow_lambda_prime *= lambda_prime * lambda_prime;
    }

    (acc_sum, acc_eval)
}

pub(crate) fn circuit_vk_for_idx(
    vk: &RecursionVk,
    chip_id: usize,
) -> Option<&VerifyingKey<RecursionField>> {
    vk.circuit_index_to_name
        .get(&chip_id)
        .and_then(|name| vk.circuit_vks.get(name))
}

pub(crate) fn tower_layer_count_from_vk(
    circuit_vk: &VerifyingKey<RecursionField>,
    chip_proof: &ZKVMChipProof<RecursionField>,
) -> usize {
    let proof_layer_count = chip_proof.tower_proof.proofs.len();
    let cs = &circuit_vk.cs;
    let has_root_specs = cs.num_reads() + cs.num_writes() + cs.num_lks() > 0;
    if proof_layer_count == 0 && !has_root_specs {
        0
    } else {
        proof_layer_count + 1
    }
}

/// Record all tower transcript events for one chip proof, then replay tower proof.
/// Keeping this in the tower module avoids preflight callsites duplicating
/// transcript/replay wiring logic.
pub(crate) fn record_and_replay_tower_preflight<TS>(
    ts: &mut TS,
    child_vk: &RecursionVk,
    chip_id: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
) -> (TowerTranscriptSchedule, TowerReplayResult)
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    let schedule = record_gkr_transcript(ts, chip_id, chip_proof);
    let replay = match circuit_vk_for_idx(child_vk, chip_id) {
        Some(circuit_vk) => match replay_tower_proof_poseidon(chip_proof, circuit_vk, &schedule) {
            Ok(replay) => replay,
            Err(err) => {
                error!(
                    ?err,
                    chip_id, "failed to replay Poseidon tower proof during preflight"
                );
                TowerReplayResult::default()
            }
        },
        None => TowerReplayResult::default(),
    };
    (schedule, replay)
}

pub(crate) fn derive_tower_input_claim_for_transcript(
    child_vk: &RecursionVk,
    chip_id: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
    replay: &TowerReplayResult,
    schedule: &TowerTranscriptSchedule,
) -> EF {
    let Some(circuit_vk) = circuit_vk_for_idx(child_vk, chip_id) else {
        return EF::ZERO;
    };

    match build_chip_records(
        0, 0, chip_id, 0, true, chip_proof, circuit_vk, replay, schedule, 0,
    ) {
        Ok((input_record, ..)) => input_record.input_layer_claim,
        Err(err) => {
            error!(
                ?err,
                chip_id, "failed to derive tower input claim during preflight"
            );
            EF::ZERO
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_chip_records(
    proof_idx: usize,
    chip_idx: usize,
    chip_id: usize,
    fork_idx: usize,
    is_first_air_idx: bool,
    chip_proof: &ZKVMChipProof<RecursionField>,
    _circuit_vk: &VerifyingKey<RecursionField>,
    replay: &TowerReplayResult,
    schedule: &TowerTranscriptSchedule,
    tidx: usize,
) -> Result<(
    TowerInputRecord,
    TowerLayerRecord,
    TowerTowerEvalRecord,
    TowerSumcheckRecord,
    Vec<EF>,
)> {
    let cs = &_circuit_vk.cs;
    let read_count = cs.num_reads();
    let write_count = cs.num_writes();
    let logup_count = cs.num_lks();
    let spec_layer_count = chip_proof
        .tower_proof
        .logup_specs_eval
        .iter()
        .map(Vec::len)
        .chain(chip_proof.tower_proof.prod_specs_eval.iter().map(Vec::len))
        .max()
        .unwrap_or(0);
    let proof_layer_count = chip_proof.tower_proof.proofs.len();
    let layer_count = tower_layer_count_from_vk(_circuit_vk, chip_proof);
    let _ = spec_layer_count;
    eyre::ensure!(
        chip_proof.r_out_evals.len() == read_count,
        "read root eval count mismatch at proof {proof_idx} chip {chip_id}: proof={}, vk={read_count}",
        chip_proof.r_out_evals.len()
    );
    eyre::ensure!(
        chip_proof.w_out_evals.len() == write_count,
        "write root eval count mismatch at proof {proof_idx} chip {chip_id}: proof={}, vk={write_count}",
        chip_proof.w_out_evals.len()
    );
    eyre::ensure!(
        chip_proof.lk_out_evals.len() == logup_count,
        "logup root eval count mismatch at proof {proof_idx} chip {chip_id}: proof={}, vk={logup_count}",
        chip_proof.lk_out_evals.len()
    );

    let mut read_layers = vec![vec![[EF::ZERO; 2]; read_count]; layer_count];
    let mut write_layers = vec![vec![[EF::ZERO; 2]; write_count]; layer_count];
    let mut logup_layers = vec![vec![[EF::ZERO; 4]; logup_count]; layer_count];
    let mut read_active = vec![vec![false; read_count]; layer_count];
    let mut write_active = vec![vec![false; write_count]; layer_count];
    let mut logup_active = vec![vec![false; logup_count]; layer_count];

    if layer_count > 0 {
        for (spec_idx, evals) in chip_proof.r_out_evals.iter().enumerate() {
            if spec_idx < read_count {
                let mut pair = [EF::ZERO; 2];
                for (dst, src) in pair.iter_mut().zip(evals.iter().take(2)) {
                    *dst = *src;
                }
                read_layers[0][spec_idx] = pair;
                read_active[0][spec_idx] = true;
            }
        }
        for (spec_idx, evals) in chip_proof.w_out_evals.iter().enumerate() {
            if spec_idx < write_count {
                let mut pair = [EF::ZERO; 2];
                for (dst, src) in pair.iter_mut().zip(evals.iter().take(2)) {
                    *dst = *src;
                }
                write_layers[0][spec_idx] = pair;
                write_active[0][spec_idx] = true;
            }
        }
        for (spec_idx, evals) in chip_proof.lk_out_evals.iter().enumerate() {
            if spec_idx < logup_count {
                let mut quad = [EF::ZERO; 4];
                for (dst, src) in quad.iter_mut().zip(evals.iter().take(4)) {
                    *dst = *src;
                }
                logup_layers[0][spec_idx] = quad;
                logup_active[0][spec_idx] = true;
            }
        }
    }

    for (spec_idx, rounds) in chip_proof.tower_proof.prod_specs_eval.iter().enumerate() {
        for round_idx in 0..proof_layer_count {
            if let Some(values) = rounds.get(round_idx) {
                let layer_idx = round_idx + 1;
                let mut pair = [EF::ZERO; 2];
                for (dst, src) in pair.iter_mut().zip(values.iter().take(2)) {
                    *dst = *src;
                }
                if spec_idx < read_count {
                    read_layers[layer_idx][spec_idx] = pair;
                    read_active[layer_idx][spec_idx] = true;
                } else {
                    let write_idx = spec_idx - read_count;
                    if write_idx < write_count {
                        write_layers[layer_idx][write_idx] = pair;
                        write_active[layer_idx][write_idx] = true;
                    }
                }
            }
        }
    }

    for (spec_idx, rounds) in chip_proof.tower_proof.logup_specs_eval.iter().enumerate() {
        #[allow(clippy::needless_range_loop)]
        for round_idx in 0..proof_layer_count {
            if let Some(values) = rounds.get(round_idx) {
                let layer_idx = round_idx + 1;
                let mut quad = [EF::ZERO; 4];
                for (dst, src) in quad.iter_mut().zip(values.iter().take(4)) {
                    *dst = *src;
                }
                if spec_idx < logup_count {
                    logup_layers[layer_idx][spec_idx] = quad;
                    logup_active[layer_idx][spec_idx] = true;
                }
            }
        }
    }

    let tower_record = TowerTowerEvalRecord {
        read_layers,
        write_layers,
        logup_layers,
        read_active,
        write_active,
        logup_active,
    };

    let mut layer_record = TowerLayerRecord {
        proof_idx,
        chip_idx,
        is_first_air_idx,
        tidx,
        initial_tower_claim: EF::ZERO,
        layer_claims: Vec::with_capacity(layer_count),
        lambdas: vec![EF::ZERO; layer_count],
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
        // NOTE: some chip only got read or write
        // eyre::ensure!(
        //     read_len == write_len,
        //     "read/write prod spec count mismatch at layer {layer_idx}: read={read_len}, write={write_len}"
        // );
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
        chip_idx,
        is_first_air_idx,
        tidx: 0,
        layer_tidxs: Vec::new(),
        evals: Vec::new(),
        ris: Vec::new(),
        claims: vec![EF::ZERO; layer_count.saturating_sub(1)],
    };

    // The sumcheck trace processes num_sumcheck_layers = layer_count - 1 layers.
    // Layer k (0-indexed) has layer_rounds(k) = k+1 sumcheck rounds.
    // Total rounds = num_sumcheck_layers*(num_sumcheck_layers+1)/2.
    // record_gkr_transcript produces ris/evals for ALL layer_count layers,
    // but the last layer is not processed by the sumcheck AIR (it corresponds
    // to the final input layer claim, not a sumcheck). Truncate to
    // total_rounds.
    let num_sumcheck_layers = layer_count.saturating_sub(1);
    let total_sumcheck_rounds = num_sumcheck_layers * (num_sumcheck_layers + 1) / 2;

    for (k, round_msgs) in chip_proof.tower_proof.proofs.iter().enumerate() {
        // Only include sumcheck evals for the first num_sumcheck_layers layers
        if k >= num_sumcheck_layers {
            break;
        }
        for msg in round_msgs {
            sumcheck_record.evals.push(convert_sumcheck_evals(msg));
        }
    }
    let mut mus_record = vec![EF::ZERO; layer_count];
    if !mus_record.is_empty() {
        mus_record[0] = schedule.beta;
    }
    for layer_idx in 0..layer_count {
        layer_record.lambdas[layer_idx] =
            schedule.lambdas.get(layer_idx).copied().unwrap_or(EF::ZERO);
        if layer_idx > 0 {
            mus_record[layer_idx] = schedule.mus.get(layer_idx - 1).copied().unwrap_or(EF::ZERO);
        }
    }

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
    let mut input_record = TowerInputRecord {
        proof_idx,
        chip_idx,
        tidx,
        final_tidx: tidx,
        num_layers: layer_count,
        num_read_specs: read_count,
        num_write_specs: write_count,
        num_logup_specs: logup_count,
        r0_claim: EF::ZERO,
        w0_claim: EF::ZERO,
        p0_claim: EF::ZERO,
        q0_claim: EF::ONE,
        alpha_logup: schedule.alpha_logup,
        r_1: schedule.beta,
        read_initial_claim: EF::ZERO,
        write_initial_claim: EF::ZERO,
        logup_initial_claim: EF::ZERO,
        initial_tower_claim: EF::ZERO,
        write_lambda_1_start: ext_pow(schedule.alpha_logup, read_count),
        logup_lambda_1_start: ext_pow(schedule.alpha_logup, read_count + write_count),
        input_layer_claim: EF::ZERO,
        layer_output_lambda,
        layer_output_mu,
    };
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
    for (round_idx, data) in replay.layers.iter().enumerate() {
        let layer_idx = round_idx + 1;
        if layer_idx < layer_record.eq_at_r_primes.len() {
            layer_record.eq_at_r_primes[layer_idx] = data.eq_at_r;
        }
        if round_idx < sumcheck_record.claims.len() {
            sumcheck_record.claims[round_idx] = data.claim_in;
        }
        if round_idx < layer_record.sumcheck_claims.len() {
            layer_record.sumcheck_claims[round_idx] = data.claim_in;
        }
    }

    for layer_idx in 0..layer_count {
        let lambda = layer_record
            .lambdas
            .get(layer_idx)
            .copied()
            .unwrap_or(EF::ZERO);
        let lambda_cur = layer_record.lambda_cur_at(layer_idx);
        let mu = mus_record.get(layer_idx).copied().unwrap_or(EF::ZERO);
        let read_count = layer_record.read_count_at(layer_idx);
        let write_count = layer_record.write_count_at(layer_idx);
        let read_lambda_start = EF::ONE;
        let read_lambda_prime_start = EF::ONE;
        let write_lambda_start = ext_pow(lambda, read_count);
        let write_lambda_prime_start = ext_pow(lambda_cur, read_count);
        let logup_lambda_start = ext_pow(lambda, read_count + write_count);
        let logup_lambda_prime_start = ext_pow(lambda_cur, read_count + write_count);

        if let Some(rows) = tower_record.read_layers.get(layer_idx) {
            let (claim, prime) = accumulate_prod_claims(
                rows,
                lambda,
                lambda_cur,
                mu,
                read_lambda_start,
                read_lambda_prime_start,
            );
            layer_record.read_claims[layer_idx] = claim;
            layer_record.read_prime_claims[layer_idx] = prime;
            if layer_idx == 0 {
                input_record.read_initial_claim = claim;
                input_record.r0_claim = rows
                    .iter()
                    .zip(tower_record.read_active[layer_idx].iter())
                    .filter_map(|(pair, is_active)| is_active.then_some(pair[0] * pair[1]))
                    .product::<EF>();
            }
        }
        if let Some(rows) = tower_record.write_layers.get(layer_idx) {
            let (claim, prime) = accumulate_prod_claims(
                rows,
                lambda,
                lambda_cur,
                mu,
                write_lambda_start,
                write_lambda_prime_start,
            );
            layer_record.write_claims[layer_idx] = claim;
            layer_record.write_prime_claims[layer_idx] = prime;
            if layer_idx == 0 {
                input_record.write_initial_claim = claim;
                input_record.w0_claim = rows
                    .iter()
                    .zip(tower_record.write_active[layer_idx].iter())
                    .filter_map(|(pair, is_active)| is_active.then_some(pair[0] * pair[1]))
                    .product::<EF>();
            }
        }
        if let Some(rows) = tower_record.logup_layers.get(layer_idx) {
            let (claim, prime) = accumulate_logup_claims(
                rows,
                lambda,
                lambda_cur,
                mu,
                logup_lambda_start,
                logup_lambda_prime_start,
            );
            layer_record.logup_claims[layer_idx] = claim;
            layer_record.logup_prime_claims[layer_idx] = prime;
            if layer_idx == 0 {
                input_record.logup_initial_claim = claim;
                let mut p0 = EF::ZERO;
                let mut q0 = EF::ONE;
                for (quad, is_active) in
                    rows.iter().zip(tower_record.logup_active[layer_idx].iter())
                {
                    if !*is_active {
                        continue;
                    }
                    let p_cross = quad[0] * quad[3] + quad[1] * quad[2];
                    let q_cross = quad[2] * quad[3];
                    p0 = p0 * q_cross + p_cross * q0;
                    q0 *= q_cross;
                }
                input_record.p0_claim = p0;
                input_record.q0_claim = q0;
            }
        }
    }
    input_record.initial_tower_claim = input_record.read_initial_claim
        + input_record.write_initial_claim
        + input_record.logup_initial_claim;
    layer_record.initial_tower_claim = input_record.initial_tower_claim;

    // Sync sumcheck claims with accumulated values so that the sumcheck trace
    // uses the same claim_in that TowerLayerAir sends on the sumcheck_input_bus.
    // TowerLayerAir layer j (j >= 1) sends: sumcheck_claim_in = read[j-1] + write[j-1] + logup[j-1]
    // Sumcheck internal layer k uses: claims[k], where k = j - 1.
    for k in 0..layer_count.saturating_sub(1) {
        let folded = layer_record.read_claims[k]
            + layer_record.write_claims[k]
            + layer_record.logup_claims[k];
        if let Some(replay_layer) = replay.layers.get(k) {
            eyre::ensure!(
                folded == replay_layer.claim_in,
                "tower folded claim mismatch at proof {proof_idx} chip {chip_idx} layer {k}: folded={folded:?}, replay={:?}",
                replay_layer.claim_in
            );
        }
        sumcheck_record.claims[k] = folded;
        layer_record.sumcheck_claims[k] = folded;
    }

    if let Some(last_layer_idx) = layer_count.checked_sub(1) {
        input_record.input_layer_claim = layer_record.read_claims[last_layer_idx]
            + layer_record.write_claims[last_layer_idx]
            + layer_record.logup_claims[last_layer_idx];
        input_record.layer_output_lambda = layer_record.lambdas[last_layer_idx];
        input_record.layer_output_mu = mus_record[last_layer_idx];
        input_record.final_tidx =
            layer_record.layer_tidx(last_layer_idx) + layer_record.layer_span(last_layer_idx);
    }

    // Compute eq_at_r_primes from ris and mus so that TowerLayerAir's eq values
    // match the sumcheck trace's eq_out on the sumcheck_output_bus.
    // Sumcheck internal layer k (0-indexed) → TowerLayerAir layer k+1.
    let num_sumcheck_layers = layer_count.saturating_sub(1);
    sumcheck_record.layer_tidxs = (0..num_sumcheck_layers)
        .map(|k| layer_record.layer_tidx(k + 1) + tower_transcript_len::SUMCHECK_INIT_LEN)
        .collect();
    if let Some(&first_tidx) = sumcheck_record.layer_tidxs.first() {
        sumcheck_record.tidx = first_tidx;
    }
    for k in 0..num_sumcheck_layers {
        let eq = TowerSumcheckRecord::compute_eq_for_layer(k, &mus_record, &sumcheck_record.ris);
        if k + 1 < layer_record.eq_at_r_primes.len() {
            layer_record.eq_at_r_primes[k + 1] = eq;
        }
    }
    for (round_idx, replay_layer) in replay.layers.iter().enumerate() {
        let layer_idx = round_idx + 1;
        if layer_idx < layer_record.layer_count() {
            let expected = layer_record.eq_at_r_primes[layer_idx]
                * (layer_record.read_prime_claims[layer_idx]
                    + layer_record.write_prime_claims[layer_idx]
                    + layer_record.logup_prime_claims[layer_idx]);
            eyre::ensure!(
                expected == replay_layer.claim_out,
                "tower expected-eval mismatch at proof {proof_idx} chip_idx {chip_idx} chip_id {chip_id} fork_idx {fork_idx} layer {layer_idx}: expected={expected:?}, replay={:?}, eq={:?}, read_prime={:?}, write_prime={:?}, logup_prime={:?}",
                replay_layer.claim_out,
                layer_record.eq_at_r_primes[layer_idx],
                layer_record.read_prime_claims[layer_idx],
                layer_record.write_prime_claims[layer_idx],
                layer_record.logup_prime_claims[layer_idx],
            );
        }
    }

    Ok((
        input_record,
        layer_record,
        tower_record,
        sumcheck_record,
        mus_record,
    ))
}

impl AirModule for TowerModule {
    fn num_airs(&self) -> usize {
        TowerModuleChipDiscriminants::COUNT
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let gkr_input_air = TowerInputAir {
            tower_module_bus: self.bus_inventory.tower_module_bus,
            tower_root_claim_bus: self.bus_inventory.tower_root_claim_bus,
            main_bus: self.bus_inventory.main_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
            read_root_input_bus: self.read_root_input_bus,
            read_root_bus: self.read_root_bus,
            read_init_bus: self.read_init_bus,
            write_root_input_bus: self.write_root_input_bus,
            write_root_bus: self.write_root_bus,
            write_init_bus: self.write_init_bus,
            logup_root_input_bus: self.logup_root_input_bus,
            logup_root_bus: self.logup_root_bus,
            sumcheck_challenge_bus: self.sumcheck_challenge_bus,
        };

        let gkr_layer_air = TowerLayerAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
            sumcheck_input_bus: self.sumcheck_input_bus,
            sumcheck_output_bus: self.sumcheck_output_bus,
            sumcheck_challenge_bus: self.sumcheck_challenge_bus,
            claim_input_bus: self.claim_input_bus,
            prod_read_claim_bus: self.prod_read_claim_bus,
            prod_write_claim_bus: self.prod_write_claim_bus,
            logup_claim_bus: self.logup_claim_bus,
        };

        let gkr_prod_read_claim_air = TowerProdReadClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            op: TowerClaimOp::Read,
            prod_claim_input_bus: self.claim_input_bus,
            prod_claim_bus: self.prod_read_claim_bus,
            root_input_bus: self.read_root_input_bus,
            root_bus: self.read_root_bus,
            init_bus: self.read_init_bus,
        };

        let gkr_prod_write_claim_air = TowerProdWriteClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            op: TowerClaimOp::Write,
            prod_claim_input_bus: self.claim_input_bus,
            prod_claim_bus: self.prod_write_claim_bus,
            root_input_bus: self.write_root_input_bus,
            root_bus: self.write_root_bus,
            init_bus: self.write_init_bus,
        };

        let gkr_logup_claim_air = TowerLogupClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            claim_input_bus: self.claim_input_bus,
            logup_claim_bus: self.logup_claim_bus,
            root_input_bus: self.logup_root_input_bus,
            root_bus: self.logup_root_bus,
        };

        let gkr_sumcheck_air = TowerLayerSumcheckAir::new(
            self.bus_inventory.transcript_bus,
            self.bus_inventory.xi_randomness_bus,
            self.sumcheck_input_bus,
            self.sumcheck_output_bus,
            self.sumcheck_challenge_bus,
        );

        vec![
            Arc::new(gkr_input_air) as AirRef<_>,
            Arc::new(gkr_layer_air) as AirRef<_>,
            Arc::new(gkr_prod_read_claim_air) as AirRef<_>,
            Arc::new(gkr_prod_write_claim_air) as AirRef<_>,
            Arc::new(gkr_logup_claim_air) as AirRef<_>,
            Arc::new(gkr_sumcheck_air) as AirRef<_>,
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
    let mut input_records = Vec::new();
    let mut layer_records = Vec::new();
    let mut tower_records = Vec::new();
    let mut sumcheck_records = Vec::new();
    let mut mus_records = Vec::new();

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
            .map(|(sorted_idx, (chip_id, _))| (*chip_id, sorted_idx))
            .collect();
        let mut sorted_pf_entries: Vec<_> = preflight.gkr.chips.iter().collect();
        sorted_pf_entries.sort_by_key(|entry| {
            (
                sorted_idx_by_chip
                    .get(&entry.chip_id)
                    .copied()
                    .unwrap_or(usize::MAX),
                entry.instance_idx,
            )
        });
        for (entry_idx, pf_entry) in sorted_pf_entries.into_iter().enumerate() {
            let chip_id = pf_entry.chip_id;
            let chip_idx = sorted_idx_by_chip
                .get(&chip_id)
                .copied()
                .ok_or_else(|| eyre::eyre!("missing proof-shape index for chip {chip_id}"))?;
            eyre::ensure!(
                chip_idx == entry_idx,
                "proof-local chip index mismatch for chip {chip_id}: proof-shape={chip_idx}, tower-row={entry_idx}"
            );
            let instance_idx = pf_entry.instance_idx;
            let chip_instances = proof
                .chip_proofs
                .get(&chip_id)
                .ok_or_else(|| eyre::eyre!("missing chip proof instances for chip {chip_id}"))?;
            let chip_proof = chip_instances.get(instance_idx).ok_or_else(|| {
                eyre::eyre!("missing chip proof instance {instance_idx} for chip {chip_id}")
            })?;
            has_chip = true;
            // Access the fork log directly using fork_idx and fork-local tidx.
            let mut ts = {
                let fork_log = preflight.fork_log(pf_entry.fork_idx);
                ReadOnlyTranscript::new(fork_log, pf_entry.tidx)
            };
            let schedule = record_gkr_transcript(&mut ts, chip_id, chip_proof);

            let circuit_vk = circuit_vk_for_idx(child_vk, chip_id)
                .ok_or_else(|| eyre::eyre!("missing circuit verifying key for index {chip_id}"))?;

            // Re-run the tower replay with Poseidon2-derived challenges from the
            // schedule so that eq_at_r / claim_in / mu / lambda match the native
            // DuplexSponge verifier (the preflight replay used a fresh keccak
            // BasicTranscript and is wrong).
            let poseidon_replay = replay_tower_proof_poseidon(chip_proof, circuit_vk, &schedule)
                .unwrap_or_else(|_err| TowerReplayResult::default());

            // Tower buses are keyed by the proof-local chip proof index. The
            // VK/circuit index (`chip_id`) is only used above to fetch metadata.
            // Compute global tidx from fork-local tidx for trace column values.
            let global_tidx = preflight.fork_global_offset(pf_entry.fork_idx) + pf_entry.tidx;
            let (chip_input_record, layer_record, tower_record, sumcheck_record, mus_record) =
                build_chip_records(
                    proof_idx,
                    chip_idx,
                    chip_id,
                    pf_entry.fork_idx,
                    chip_idx == 0,
                    chip_proof,
                    circuit_vk,
                    &poseidon_replay,
                    &schedule,
                    global_tidx,
                )?;

            input_records.push(chip_input_record);
            layer_records.push(layer_record);
            tower_records.push(tower_record);
            sumcheck_records.push(sumcheck_record);
            mus_records.push(mus_record);
        }

        if !has_chip {
            layer_records.push(TowerLayerRecord {
                chip_idx: 0,
                proof_idx,
                is_first_air_idx: true,
                ..Default::default()
            });
            tower_records.push(TowerTowerEvalRecord::default());
            sumcheck_records.push(TowerSumcheckRecord {
                proof_idx,
                chip_idx: 0,
                is_first_air_idx: true,
                ..Default::default()
            });
            mus_records.push(vec![]);
        }
    }

    Ok(TowerBlobCpu {
        input_records,
        layer_records,
        tower_records,
        sumcheck_records,
        mus_records,
    })
}

pub(crate) fn record_gkr_transcript<TS>(
    ts: &mut TS,
    _chip_id: usize,
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
    let round_count = chip_proof.tower_proof.proofs.len();

    let log2_num_fanin: usize = 1; // ceil_log2(NUM_FANIN=2) = 1

    let mut lambdas = Vec::with_capacity(round_count + 1);
    lambdas.push(alpha_logup);
    let mut mus = Vec::with_capacity(round_count);
    let mut ris = Vec::new();

    for round_idx in 0..round_count {
        let round_msgs = &chip_proof.tower_proof.proofs[round_idx];
        // Mirror native sumcheck IOPVerifierState::verify init:
        // append_message(max_num_variables.to_leBytes())
        // append_message(max_degree.to_leBytes())
        let max_num_variables = (round_idx + 1) * log2_num_fanin;
        let max_degree: usize = 3; // NUM_FANIN + 1
        transcript_observe_label(ts, &max_num_variables.to_le_bytes());
        transcript_observe_label(ts, &max_degree.to_le_bytes());

        for msg in round_msgs {
            for eval in &msg.evaluations {
                ts.observe_ext(*eval);
            }
            // Mirror native: sample_and_append_challenge(b"Internal round")
            transcript_observe_label(ts, b"Internal round");
            let ri = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
            ris.push(ri);
        }

        for rounds in &chip_proof.tower_proof.prod_specs_eval {
            if let Some(evals) = rounds.get(round_idx) {
                for eval in evals {
                    ts.observe_ext(*eval);
                }
            }
        }
        for rounds in &chip_proof.tower_proof.logup_specs_eval {
            if let Some(evals) = rounds.get(round_idx) {
                for eval in evals {
                    ts.observe_ext(*eval);
                }
            }
        }

        // Mirror native: sample_and_append_vec(b"merge", log2_num_fanin)
        transcript_observe_label(ts, b"merge");
        let mu = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        mus.push(mu);

        transcript_observe_label(ts, b"combine subset evals");
        let next_lambda = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        lambdas.push(next_lambda);
    }

    TowerTranscriptSchedule {
        alpha_logup,
        beta,
        lambdas,
        mus,
        ris,
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
            TowerModuleChip::Input,
            TowerModuleChip::Layer,
            TowerModuleChip::ProdReadClaim,
            TowerModuleChip::ProdWriteClaim,
            TowerModuleChip::LogupClaim,
            TowerModuleChip::LayerSumcheck,
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

#[cfg(test)]
mod debug_tests {
    use super::*;
    use crate::{
        system::RecursionPcs,
        utils::{TranscriptLabel, transcript_observe_label},
    };
    use ceno_zkvm::scheme::{constants::NUM_FANIN, verifier::TowerVerify};
    use mpcs::PolynomialCommitmentScheme;
    use multilinear_extensions::util::ceil_log2;
    use openvm_stark_sdk::config::baby_bear_poseidon2::default_duplex_sponge_recorder;
    use p3_field::BasedVectorSpace;
    use transcript::{Transcript, basic::BasicTranscript};
    use witness::next_pow2_instance_padding;

    fn limbs(value: RecursionField) -> [F; D_EF] {
        value.as_basis_coefficients_slice().try_into().unwrap()
    }

    fn fixture_path(file_name: &str) -> Option<std::path::PathBuf> {
        std::env::var_os("CENO_RECURSION_V2_FIXTURE_DIR")
            .map(std::path::PathBuf::from)
            .into_iter()
            .chain([std::path::PathBuf::from("./src/imported")])
            .map(|dir| dir.join(file_name))
            .find(|path| path.exists())
    }

    fn load_fixture() -> Option<(RecursionProof, RecursionVk)> {
        let proof_path = fixture_path("proof.bin")?;
        let vk_path = fixture_path("vk.bin")?;
        let proof_bytes = std::fs::read(proof_path).ok()?;
        let proof = bincode::deserialize::<Vec<RecursionProof>>(&proof_bytes)
            .ok()
            .and_then(|proofs| proofs.into_iter().next())
            .or_else(|| bincode::deserialize::<RecursionProof>(&proof_bytes).ok())?;
        let mut vk = bincode::deserialize::<RecursionVk>(&std::fs::read(vk_path).ok()?).ok()?;
        vk.rebuild_circuit_index();
        Some((proof, vk))
    }

    fn observe_basic_prefix(
        ts: &mut BasicTranscript<RecursionField>,
        vk: &RecursionVk,
        proof: &RecursionProof,
    ) {
        ts.append_field_element_exts(&vk.compute_digest());
        for (_, circuit_vk) in vk.circuit_vks.iter() {
            for instance_value in circuit_vk.get_cs().zkvm_v1_css.instance.iter() {
                ts.append_field_element(
                    &proof
                        .public_values
                        .query_by_index::<RecursionField>(instance_value.0),
                );
            }
        }
        if let Some(commitment) = vk.fixed_commit.as_ref() {
            RecursionPcs::write_commitment(commitment, ts).unwrap();
        }
        if let Some(commitment) = vk.fixed_no_omc_init_commit.as_ref() {
            RecursionPcs::write_commitment(commitment, ts).unwrap();
        }
        RecursionPcs::write_commitment(&proof.witin_commit, ts).unwrap();
    }

    fn observe_basic_tower(
        ts: &mut BasicTranscript<RecursionField>,
        chip_proof: &ZKVMChipProof<RecursionField>,
    ) -> TowerTranscriptSchedule {
        for eval in chip_proof
            .r_out_evals
            .iter()
            .chain(chip_proof.w_out_evals.iter())
            .chain(chip_proof.lk_out_evals.iter())
            .flatten()
        {
            ts.append_field_element_ext(eval);
        }
        let alpha_logup = ::sumcheck::util::get_challenge_pows::<RecursionField>(
            chip_proof.r_out_evals.len()
                + chip_proof.w_out_evals.len()
                + 2 * chip_proof.lk_out_evals.len(),
            ts,
        )
        .get(1)
        .copied()
        .unwrap_or(RecursionField::ONE);
        let beta = ts.sample_and_append_vec(b"product_sum", 1)[0];
        let mut lambdas = vec![alpha_logup];
        let mut mus = Vec::new();
        let mut ris = Vec::new();
        for (round_idx, round_msgs) in chip_proof.tower_proof.proofs.iter().enumerate() {
            ts.append_message(&(round_idx + 1).to_le_bytes());
            ts.append_message(&3usize.to_le_bytes());
            for msg in round_msgs {
                for eval in &msg.evaluations {
                    ts.append_field_element_ext(eval);
                }
                ris.push(ts.sample_and_append_challenge(b"Internal round").elements);
            }
            for rounds in &chip_proof.tower_proof.prod_specs_eval {
                if let Some(evals) = rounds.get(round_idx) {
                    ts.append_field_element_exts(evals);
                }
            }
            for rounds in &chip_proof.tower_proof.logup_specs_eval {
                if let Some(evals) = rounds.get(round_idx) {
                    ts.append_field_element_exts(evals);
                }
            }
            mus.push(ts.sample_and_append_vec(b"merge", 1)[0]);
            let next_lambda = ::sumcheck::util::get_challenge_pows::<RecursionField>(
                chip_proof.r_out_evals.len()
                    + chip_proof.w_out_evals.len()
                    + 2 * chip_proof.lk_out_evals.len(),
                ts,
            )
            .get(1)
            .copied()
            .unwrap_or(RecursionField::ONE);
            lambdas.push(next_lambda);
        }
        TowerTranscriptSchedule {
            alpha_logup,
            beta,
            lambdas,
            mus,
            ris,
        }
    }

    fn manual_first_expected(chip_proof: &ZKVMChipProof<RecursionField>, lambda: EF, eq: EF) -> EF {
        let prod_count = chip_proof.r_out_evals.len() + chip_proof.w_out_evals.len();
        let mut total = EF::ZERO;
        let mut pow = EF::ONE;
        for rounds in &chip_proof.tower_proof.prod_specs_eval {
            if let Some(evals) = rounds.first() {
                total += pow * evals.iter().copied().product::<EF>();
            }
            pow *= lambda;
        }
        debug_assert_eq!(prod_count, chip_proof.tower_proof.prod_specs_eval.len());
        for rounds in &chip_proof.tower_proof.logup_specs_eval {
            if let Some(evals) = rounds.first() {
                let (p1, p2, q1, q2) = (evals[0], evals[1], evals[2], evals[3]);
                total += pow * (p1 * q2 + p2 * q1);
                pow *= lambda;
                total += pow * (q1 * q2);
                pow *= lambda;
            }
        }
        eq * total
    }

    #[test]
    #[ignore]
    fn debug_chip_15_tower() {
        let Some((proof, vk)) = load_fixture() else {
            return;
        };

        let target_fork = 10usize;
        let (chip_id, chip_proof) = proof
            .chip_proofs
            .iter()
            .flat_map(|(chip_id, proofs)| {
                proofs.iter().map(move |chip_proof| (*chip_id, chip_proof))
            })
            .nth(target_fork)
            .expect("target fork should exist");
        assert_eq!(chip_id, 15);
        let circuit_vk = circuit_vk_for_idx(&vk, chip_id).unwrap();

        let mut basic = BasicTranscript::<RecursionField>::new(b"riscv");
        observe_basic_prefix(&mut basic, &vk, &proof);
        let basic_alpha = basic.read_challenge().elements;
        let basic_beta = basic.read_challenge().elements;

        let mut basic_fork = BasicTranscript::<RecursionField>::new(b"fork");
        basic_fork.append_field_element_ext(&basic_alpha);
        basic_fork.append_field_element_ext(&basic_beta);
        basic_fork.append_field_element(&F::from_usize(target_fork));
        basic_fork.append_field_element(&F::from_usize(chip_id));
        for num_instance in &chip_proof.num_instances {
            basic_fork.append_field_element(&F::from_usize(*num_instance));
        }
        let basic_schedule = observe_basic_tower(&mut basic_fork, chip_proof);

        let num_instances: usize = chip_proof.num_instances.iter().sum();
        let mut num_vars = ceil_log2(next_pow2_instance_padding(num_instances));
        if circuit_vk.get_cs().has_ecc_ops() {
            num_vars += 1;
        }
        num_vars += circuit_vk.get_cs().rotation_vars().unwrap_or(0);
        let num_batched = chip_proof.r_out_evals.len()
            + chip_proof.w_out_evals.len()
            + chip_proof.lk_out_evals.len();

        let eq0 = basic_schedule.beta * basic_schedule.ris[0]
            + (EF::ONE - basic_schedule.beta) * (EF::ONE - basic_schedule.ris[0]);
        eprintln!(
            "chip_id={chip_id} fork={target_fork} num_vars={num_vars} num_batched={num_batched} r={} w={} lk={} proofs={} prod_specs={} logup_specs={} lambda0={:?} beta0={:?} ri0={:?} manual_expected={:?}",
            chip_proof.r_out_evals.len(),
            chip_proof.w_out_evals.len(),
            chip_proof.lk_out_evals.len(),
            chip_proof.tower_proof.proofs.len(),
            chip_proof.tower_proof.prod_specs_eval.len(),
            chip_proof.tower_proof.logup_specs_eval.len(),
            limbs(basic_schedule.alpha_logup),
            limbs(basic_schedule.beta),
            limbs(basic_schedule.ris[0]),
            limbs(manual_first_expected(
                chip_proof,
                basic_schedule.alpha_logup,
                eq0
            )),
        );

        let replay = replay_tower_proof_poseidon(chip_proof, circuit_vk, &basic_schedule).unwrap();
        if let Some(layer0) = replay.layers.first() {
            eprintln!(
                "poseidon replay claim_in={:?} claim_out={:?} eq={:?}",
                limbs(layer0.claim_in),
                limbs(layer0.claim_out),
                limbs(layer0.eq_at_r),
            );
        }

        let mut basic_verify = BasicTranscript::<RecursionField>::new(b"fork");
        basic_verify.append_field_element_ext(&basic_alpha);
        basic_verify.append_field_element_ext(&basic_beta);
        basic_verify.append_field_element(&F::from_usize(target_fork));
        basic_verify.append_field_element(&F::from_usize(chip_id));
        for num_instance in &chip_proof.num_instances {
            basic_verify.append_field_element(&F::from_usize(*num_instance));
        }
        for eval in chip_proof
            .r_out_evals
            .iter()
            .chain(chip_proof.w_out_evals.iter())
            .chain(chip_proof.lk_out_evals.iter())
            .flatten()
        {
            basic_verify.append_field_element_ext(eval);
        }
        let tower_verify_result = TowerVerify::verify(
            chip_proof
                .r_out_evals
                .iter()
                .cloned()
                .chain(chip_proof.w_out_evals.iter().cloned())
                .collect(),
            chip_proof.lk_out_evals.clone(),
            &chip_proof.tower_proof,
            vec![num_vars; num_batched],
            NUM_FANIN,
            &mut basic_verify,
        );
        eprintln!(
            "native TowerVerify result={:?}",
            tower_verify_result.as_ref().map(|_| ())
        );
    }

    #[test]
    #[ignore]
    fn debug_compare_all_tower_schedules() {
        let Some((proof, vk)) = load_fixture() else {
            return;
        };

        let mut basic = BasicTranscript::<RecursionField>::new(b"riscv");
        observe_basic_prefix(&mut basic, &vk, &proof);
        let basic_alpha = basic.read_challenge().elements;
        let basic_beta = basic.read_challenge().elements;

        let mut sponge = default_duplex_sponge_recorder();
        transcript_observe_label(&mut sponge, TranscriptLabel::Riscv.as_bytes());
        let mut openvm_preflight = Preflight::default();
        super::super::circuit::inner::vm_pvs::run_preflight(
            &vk,
            &proof,
            &mut openvm_preflight,
            &mut sponge,
        );
        let openvm_alpha = openvm_preflight.vm_pvs.lookup_challenge_alpha;
        let openvm_beta = openvm_preflight.vm_pvs.lookup_challenge_beta;

        eprintln!(
            "global basic alpha={:?} beta={:?}; openvm alpha={:?} beta={:?}",
            limbs(basic_alpha),
            limbs(basic_beta),
            limbs(openvm_alpha),
            limbs(openvm_beta),
        );

        let mut checked = 0usize;
        let mut mismatches = 0usize;
        for (fork_id, (&chip_id, chip_proof)) in proof
            .chip_proofs
            .iter()
            .flat_map(|(chip_id, proofs)| {
                proofs.iter().map(move |chip_proof| (chip_id, chip_proof))
            })
            .enumerate()
        {
            let mut basic_fork = BasicTranscript::<RecursionField>::new(b"fork");
            basic_fork.append_field_element_ext(&basic_alpha);
            basic_fork.append_field_element_ext(&basic_beta);
            basic_fork.append_field_element(&F::from_usize(fork_id));
            basic_fork.append_field_element(&F::from_usize(chip_id));
            for num_instance in &chip_proof.num_instances {
                basic_fork.append_field_element(&F::from_usize(*num_instance));
            }
            let basic_schedule = observe_basic_tower(&mut basic_fork, chip_proof);

            let mut openvm_fork = default_duplex_sponge_recorder();
            transcript_observe_label(&mut openvm_fork, TranscriptLabel::Fork.as_bytes());
            FiatShamirTranscript::<BabyBearPoseidon2Config>::observe_ext(
                &mut openvm_fork,
                openvm_alpha,
            );
            FiatShamirTranscript::<BabyBearPoseidon2Config>::observe_ext(
                &mut openvm_fork,
                openvm_beta,
            );
            FiatShamirTranscript::<BabyBearPoseidon2Config>::observe(
                &mut openvm_fork,
                F::from_usize(fork_id),
            );
            FiatShamirTranscript::<BabyBearPoseidon2Config>::observe(
                &mut openvm_fork,
                F::from_usize(chip_id),
            );
            for num_instance in &chip_proof.num_instances {
                FiatShamirTranscript::<BabyBearPoseidon2Config>::observe(
                    &mut openvm_fork,
                    F::from_usize(*num_instance),
                );
            }
            let openvm_schedule = record_gkr_transcript(&mut openvm_fork, chip_id, chip_proof);

            let same = basic_schedule.alpha_logup == openvm_schedule.alpha_logup
                && basic_schedule.beta == openvm_schedule.beta
                && basic_schedule.lambdas == openvm_schedule.lambdas
                && basic_schedule.mus == openvm_schedule.mus
                && basic_schedule.ris == openvm_schedule.ris;
            if !same {
                mismatches += 1;
                eprintln!(
                    "schedule mismatch fork={fork_id} chip_id={chip_id} basic lambda0={:?} beta0={:?} ri0={:?}; openvm lambda0={:?} beta0={:?} ri0={:?}",
                    limbs(basic_schedule.alpha_logup),
                    limbs(basic_schedule.beta),
                    basic_schedule.ris.first().copied().map(limbs),
                    limbs(openvm_schedule.alpha_logup),
                    limbs(openvm_schedule.beta),
                    openvm_schedule.ris.first().copied().map(limbs),
                );
            }
            checked += 1;
        }

        eprintln!("checked {checked} fork schedules, mismatches={mismatches}");
        assert_eq!(mismatches, 0);
    }

    #[test]
    #[ignore]
    fn debug_compare_tower_transcripts() {
        let Some((proof, vk)) = load_fixture() else {
            return;
        };
        let (&chip_id, chip_instances) = proof.chip_proofs.iter().next().unwrap();
        let chip_proof = &chip_instances[0];
        let circuit_vk = circuit_vk_for_idx(&vk, chip_id).unwrap();

        let mut basic = BasicTranscript::<RecursionField>::new(b"riscv");
        observe_basic_prefix(&mut basic, &vk, &proof);
        let basic_alpha = basic.read_challenge().elements;
        let basic_beta = basic.read_challenge().elements;

        let mut basic_fork = BasicTranscript::<RecursionField>::new(b"fork");
        basic_fork.append_field_element_ext(&basic_alpha);
        basic_fork.append_field_element_ext(&basic_beta);
        basic_fork.append_field_element(&F::from_usize(0));
        basic_fork.append_field_element(&F::from_usize(chip_id));
        for num_instance in &chip_proof.num_instances {
            basic_fork.append_field_element(&F::from_usize(*num_instance));
        }
        let basic_schedule = observe_basic_tower(&mut basic_fork, chip_proof);

        let mut sponge = default_duplex_sponge_recorder();
        transcript_observe_label(&mut sponge, TranscriptLabel::Riscv.as_bytes());
        let mut openvm_preflight = Preflight::default();
        super::super::circuit::inner::vm_pvs::run_preflight(
            &vk,
            &proof,
            &mut openvm_preflight,
            &mut sponge,
        );
        let openvm_alpha = openvm_preflight.vm_pvs.lookup_challenge_alpha;
        let openvm_beta = openvm_preflight.vm_pvs.lookup_challenge_beta;
        let mut openvm_fork = default_duplex_sponge_recorder();
        transcript_observe_label(&mut openvm_fork, TranscriptLabel::Fork.as_bytes());
        FiatShamirTranscript::<BabyBearPoseidon2Config>::observe_ext(
            &mut openvm_fork,
            openvm_alpha,
        );
        FiatShamirTranscript::<BabyBearPoseidon2Config>::observe_ext(&mut openvm_fork, openvm_beta);
        FiatShamirTranscript::<BabyBearPoseidon2Config>::observe(
            &mut openvm_fork,
            F::from_usize(0),
        );
        FiatShamirTranscript::<BabyBearPoseidon2Config>::observe(
            &mut openvm_fork,
            F::from_usize(chip_id),
        );
        for num_instance in &chip_proof.num_instances {
            FiatShamirTranscript::<BabyBearPoseidon2Config>::observe(
                &mut openvm_fork,
                F::from_usize(*num_instance),
            );
        }
        let openvm_schedule = record_gkr_transcript(&mut openvm_fork, chip_id, chip_proof);

        eprintln!(
            "basic alpha={:?} beta={:?} tower_lambda0={:?} beta0={:?} ri0={:?}",
            limbs(basic_alpha),
            limbs(basic_beta),
            limbs(basic_schedule.alpha_logup),
            limbs(basic_schedule.beta),
            limbs(basic_schedule.ris[0]),
        );
        eprintln!(
            "openvm alpha={:?} beta={:?} tower_lambda0={:?} beta0={:?} ri0={:?}",
            limbs(openvm_alpha),
            limbs(openvm_beta),
            limbs(openvm_schedule.alpha_logup),
            limbs(openvm_schedule.beta),
            limbs(openvm_schedule.ris[0]),
        );
        let eq0 = basic_schedule.beta * basic_schedule.ris[0]
            + (EF::ONE - basic_schedule.beta) * (EF::ONE - basic_schedule.ris[0]);
        eprintln!(
            "manual expected cur={:?} next={:?} eq={:?}",
            limbs(manual_first_expected(
                chip_proof,
                basic_schedule.lambdas[0],
                eq0
            )),
            limbs(manual_first_expected(
                chip_proof,
                basic_schedule.lambdas[1],
                eq0
            )),
            limbs(eq0),
        );

        let mut basic_verify = BasicTranscript::<RecursionField>::new(b"fork");
        basic_verify.append_field_element_ext(&basic_alpha);
        basic_verify.append_field_element_ext(&basic_beta);
        basic_verify.append_field_element(&F::from_usize(0));
        basic_verify.append_field_element(&F::from_usize(chip_id));
        for num_instance in &chip_proof.num_instances {
            basic_verify.append_field_element(&F::from_usize(*num_instance));
        }
        for eval in chip_proof
            .r_out_evals
            .iter()
            .chain(chip_proof.w_out_evals.iter())
            .chain(chip_proof.lk_out_evals.iter())
            .flatten()
        {
            basic_verify.append_field_element_ext(eval);
        }
        let num_instances: usize = chip_proof.num_instances.iter().sum();
        let mut num_vars = ceil_log2(next_pow2_instance_padding(num_instances));
        if circuit_vk.get_cs().has_ecc_ops() {
            num_vars += 1;
        }
        num_vars += circuit_vk.get_cs().rotation_vars().unwrap_or(0);
        let num_batched = chip_proof.r_out_evals.len()
            + chip_proof.w_out_evals.len()
            + chip_proof.lk_out_evals.len();
        let tower_verify_result = TowerVerify::verify(
            chip_proof
                .r_out_evals
                .iter()
                .cloned()
                .chain(chip_proof.w_out_evals.iter().cloned())
                .collect(),
            chip_proof.lk_out_evals.clone(),
            &chip_proof.tower_proof,
            vec![num_vars; num_batched],
            NUM_FANIN,
            &mut basic_verify,
        );
        eprintln!(
            "native TowerVerify result={:?}",
            tower_verify_result.as_ref().map(|_| ())
        );
    }
}

// To reduce the number of structs and trait implementations, we collect them into a single enum
// with enum dispatch.
#[derive(strum_macros::Display, strum::EnumDiscriminants)]
#[strum_discriminants(derive(strum_macros::EnumCount))]
#[strum_discriminants(repr(usize))]
enum TowerModuleChip {
    Input,
    Layer,
    ProdReadClaim,
    ProdWriteClaim,
    LogupClaim,
    LayerSumcheck,
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
            Input => TowerInputTraceGenerator
                .generate_trace(&blob.input_records.as_slice(), required_height),
            Layer => TowerLayerTraceGenerator
                .generate_trace(&(&blob.layer_records, &blob.mus_records), required_height),
            ProdReadClaim => TowerProdReadSumCheckClaimTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.tower_records, &blob.mus_records),
                required_height,
            ),
            ProdWriteClaim => TowerProdWriteSumCheckClaimTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.tower_records, &blob.mus_records),
                required_height,
            ),
            LogupClaim => TowerLogupSumCheckClaimTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.tower_records, &blob.mus_records),
                required_height,
            ),
            LayerSumcheck => TowerSumcheckTraceGenerator.generate_trace(
                &(&blob.sumcheck_records, &blob.mus_records),
                required_height,
            ),
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
