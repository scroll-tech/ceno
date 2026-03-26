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
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, Preflight, RecursionField,
        RecursionProof, RecursionVk, TowerChipTranscriptRange, TraceGenModule,
    },
    tower::{
        bus::{TowerLayerInputBus, TowerLayerOutputBus},
        input::{TowerInputAir, TowerInputRecord, TowerInputTraceGenerator},
        layer::{
            TowerLayerAir, TowerLayerRecord, TowerLayerTraceGenerator, TowerLogupSumCheckClaimAir,
            TowerLogupSumCheckClaimTraceGenerator, TowerProdReadSumCheckClaimAir,
            TowerProdReadSumCheckClaimTraceGenerator, TowerProdWriteSumCheckClaimAir,
            TowerProdWriteSumCheckClaimTraceGenerator,
        },
        sumcheck::{TowerLayerSumcheckAir, TowerSumcheckRecord, TowerSumcheckTraceGenerator},
        tower::replay_tower_proof,
    },
    tracegen::{ModuleChip, RowMajorChip},
};
use ceno_zkvm::{scheme::ZKVMChipProof, structs::VerifyingKey};
use eyre::Result;

// Internal bus definitions
mod bus;
pub use bus::{
    TowerLogupClaimBus, TowerLogupClaimInputBus, TowerLogupClaimMessage,
    TowerLogupLayerChallengeMessage, TowerProdLayerChallengeMessage, TowerProdReadClaimBus,
    TowerProdReadClaimInputBus, TowerProdSumClaimMessage, TowerProdWriteClaimBus,
    TowerProdWriteClaimInputBus, TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage,
    TowerSumcheckInputBus, TowerSumcheckInputMessage, TowerSumcheckOutputBus,
    TowerSumcheckOutputMessage,
};

// Sub-modules for different AIRs
pub mod input;
pub mod layer;
pub mod sumcheck;
mod tower;
pub(crate) use tower::TowerReplayResult;
pub struct TowerModule {
    // Global bus inventory
    bus_inventory: BusInventory,
    // Module buses
    layer_input_bus: TowerLayerInputBus,
    layer_output_bus: TowerLayerOutputBus,
    sumcheck_input_bus: TowerSumcheckInputBus,
    sumcheck_output_bus: TowerSumcheckOutputBus,
    sumcheck_challenge_bus: TowerSumcheckChallengeBus,
    prod_read_claim_input_bus: TowerProdReadClaimInputBus,
    prod_read_claim_bus: TowerProdReadClaimBus,
    prod_write_claim_input_bus: TowerProdWriteClaimInputBus,
    prod_write_claim_bus: TowerProdWriteClaimBus,
    logup_claim_input_bus: TowerLogupClaimInputBus,
    logup_claim_bus: TowerLogupClaimBus,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TowerTowerEvalRecord {
    pub(crate) read_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) write_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) logup_layers: Vec<Vec<[EF; 4]>>,
}

struct TowerBlobCpu {
    input_records: Vec<TowerInputRecord>,
    /// Per-proof q0 claims matching input_records (one per proof).
    proof_q0_claims: Vec<EF>,
    layer_records: Vec<TowerLayerRecord>,
    tower_records: Vec<TowerTowerEvalRecord>,
    sumcheck_records: Vec<TowerSumcheckRecord>,
    mus_records: Vec<Vec<EF>>,
    /// Per-chip q0 claims matching layer_records.
    q0_claims: Vec<EF>,
}

#[derive(Debug, Clone, Default)]
struct TowerTranscriptSchedule {
    alpha_logup: EF,
    lambdas: Vec<EF>,
    mus: Vec<EF>,
    ris: Vec<EF>,
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
            prod_read_claim_input_bus: TowerProdReadClaimInputBus::new(b.new_bus_idx()),
            prod_read_claim_bus: TowerProdReadClaimBus::new(b.new_bus_idx()),
            prod_write_claim_input_bus: TowerProdWriteClaimInputBus::new(b.new_bus_idx()),
            prod_write_claim_bus: TowerProdWriteClaimBus::new(b.new_bus_idx()),
            logup_claim_input_bus: TowerLogupClaimInputBus::new(b.new_bus_idx()),
            logup_claim_bus: TowerLogupClaimBus::new(b.new_bus_idx()),
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
        let _ = (self, child_vk);
        for (&chip_idx, chip_instances) in &proof.chip_proofs {
            for (instance_idx, chip_proof) in chip_instances.iter().enumerate() {
                let tidx = ts.len();
                let _ = record_gkr_transcript(ts, chip_idx, chip_proof);

                let tower_replay = match circuit_vk_for_idx(child_vk, chip_idx) {
                    Some(circuit_vk) => match replay_tower_proof(chip_proof, circuit_vk) {
                        Ok(replay) => replay,
                        Err(err) => {
                            error!(
                                ?err,
                                chip_idx, "failed to replay tower proof during preflight"
                            );
                            eprintln!(
                                "failed to replay tower proof during preflight for chip {chip_idx}: {err:?}"
                            );
                            TowerReplayResult::default()
                        }
                    },
                    None => {
                        eprintln!(
                            "missing circuit verifying key during GKR preflight for chip {chip_idx}"
                        );
                        TowerReplayResult::default()
                    }
                };

                preflight.gkr.chips.push(TowerChipTranscriptRange {
                    chip_idx,
                    instance_idx,
                    tidx,
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

fn accumulate_prod_claims(rows: &[[EF; 2]], lambda: EF, lambda_prime: EF, mu: EF) -> (EF, EF) {
    let mut pow_lambda = EF::ONE;
    let mut pow_lambda_prime = EF::ONE;
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

fn accumulate_logup_claims(rows: &[[EF; 4]], lambda: EF, lambda_prime: EF, mu: EF) -> (EF, EF) {
    let mut pow_lambda = EF::ONE;
    let mut pow_lambda_prime = EF::ONE;
    let mut acc_sum = EF::ZERO;
    let mut acc_q = EF::ZERO;

    for quad in rows {
        let p_vals = [quad[0], quad[1]];
        let q_vals = [quad[2], quad[3]];
        let p_xi = interpolate_pair(p_vals, mu);
        let q_xi = interpolate_pair(q_vals, mu);
        acc_sum += pow_lambda * (p_xi + lambda * q_xi);
        let q_cross = quad[2] * quad[3];
        acc_q += pow_lambda_prime * lambda_prime * q_cross;
        pow_lambda *= lambda;
        pow_lambda_prime *= lambda_prime;
    }

    (acc_sum, acc_q)
}

fn circuit_vk_for_idx<'a>(
    vk: &'a RecursionVk,
    chip_idx: usize,
) -> Option<&'a VerifyingKey<RecursionField>> {
    vk.circuit_index_to_name
        .get(&chip_idx)
        .and_then(|name| vk.circuit_vks.get(name))
}

fn build_chip_records(
    proof_idx: usize,
    idx: usize,
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
    EF,
)> {
    let spec_layer_count = chip_proof
        .tower_proof
        .logup_specs_eval
        .iter()
        .map(Vec::len)
        .chain(chip_proof.tower_proof.prod_specs_eval.iter().map(Vec::len))
        .max()
        .unwrap_or(0);
    let layer_count = replay.layers.len().max(spec_layer_count);

    let read_count = chip_proof.r_out_evals.len();
    let write_count = chip_proof.w_out_evals.len();
    let logup_count = chip_proof.lk_out_evals.len();

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
            if spec_idx < read_count {
                read_layers[layer_idx].push(pair);
            } else {
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
            logup_layers[layer_idx].push(quad);
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
        is_first_air_idx,
        // TowerLayerAir starts after alpha/beta sampling and q0 observe in TowerInputAir.
        tidx: tidx + 3 * D_EF,
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
        layer_record.read_counts[layer_idx] = read_len.max(1);
        layer_record.write_counts[layer_idx] = write_len.max(1);
        layer_record.logup_counts[layer_idx] = logup_len.max(1);
    }

    for layer_idx in 0..layer_count {
        layer_record
            .layer_claims
            .push(convert_logup_claim(chip_proof, layer_idx));
    }

    let input_layer_claim = layer_record
        .layer_claims
        .last()
        .map(|claim| claim[0])
        .unwrap_or(EF::ZERO);

    let mut sumcheck_record = TowerSumcheckRecord {
        proof_idx,
        idx,
        is_first_air_idx,
        // First sumcheck transcript row starts at layer_tidx(1) + D_EF.
        tidx: tidx + 9 * D_EF,
        evals: Vec::new(),
        ris: Vec::new(),
        claims: vec![EF::ZERO; layer_count.saturating_sub(1)],
    };

    for round_msgs in chip_proof
        .tower_proof
        .proofs
        .iter()
        .take(chip_proof.tower_proof.proofs.len().saturating_sub(1))
    {
        for msg in round_msgs {
            sumcheck_record.evals.push(convert_sumcheck_evals(msg));
        }
    }
    let mut mus_record = vec![EF::ZERO; layer_count];

    let q0_claim = chip_proof
        .lk_out_evals
        .get(0)
        .and_then(|evals| evals.get(2))
        .copied()
        .unwrap_or(EF::ZERO);

    let layer_output_lambda = schedule.lambdas.last().copied().unwrap_or(EF::ZERO);
    let layer_output_mu = schedule.mus.last().copied().unwrap_or(EF::ZERO);
    let input_record = TowerInputRecord {
        proof_idx,
        idx,
        tidx,
        n_logup: layer_count,
        alpha_logup: schedule.alpha_logup,
        input_layer_claim,
        layer_output_lambda,
        layer_output_mu,
    };
    sumcheck_record.ris = schedule.ris.clone();
    if !replay.layers.is_empty() {
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
            layer_record.lambdas[layer_idx] = schedule.lambdas.get(layer_idx).copied().unwrap_or(EF::ZERO);
            mus_record[layer_idx] = schedule.mus.get(layer_idx).copied().unwrap_or(EF::ZERO);
        }
        if layer_idx + 1 < layer_count {
            if layer_idx < sumcheck_record.claims.len() {
                sumcheck_record.claims[layer_idx] = data.claim_in;
            }
            if layer_idx < layer_record.sumcheck_claims.len() {
                layer_record.sumcheck_claims[layer_idx] = data.claim_in;
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

    // Sync sumcheck claims with accumulated values so that the sumcheck trace
    // uses the same claim_in that TowerLayerAir sends on the sumcheck_input_bus.
    // TowerLayerAir layer j (j >= 1) sends: sumcheck_claim_in = read[j-1] + write[j-1] + logup[j-1]
    // Sumcheck internal layer k uses: claims[k], where k = j - 1.
    for k in 0..layer_count.saturating_sub(1) {
        let folded = layer_record.read_claims[k]
            + layer_record.write_claims[k]
            + layer_record.logup_claims[k];
        sumcheck_record.claims[k] = folded;
        layer_record.sumcheck_claims[k] = folded;
    }

    // Compute eq_at_r_primes from ris and mus so that TowerLayerAir's eq values
    // match the sumcheck trace's eq_out on the sumcheck_output_bus.
    // Sumcheck internal layer k (0-indexed) → TowerLayerAir layer k+1.
    let num_sumcheck_layers = layer_count.saturating_sub(1);
    for k in 0..num_sumcheck_layers {
        let eq = TowerSumcheckRecord::compute_eq_for_layer(k, &mus_record, &sumcheck_record.ris);
        if k + 1 < layer_record.eq_at_r_primes.len() {
            layer_record.eq_at_r_primes[k + 1] = eq;
        }
    }

    Ok((
        input_record,
        layer_record,
        tower_record,
        sumcheck_record,
        mus_record,
        q0_claim,
    ))
}

impl AirModule for TowerModule {
    fn num_airs(&self) -> usize {
        TowerModuleChipDiscriminants::COUNT
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let gkr_input_air = TowerInputAir {
            tower_module_bus: self.bus_inventory.tower_module_bus,
            main_bus: self.bus_inventory.main_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
        };

        let gkr_layer_air = TowerLayerAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            air_shape_bus: self.bus_inventory.air_shape_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
            sumcheck_input_bus: self.sumcheck_input_bus,
            sumcheck_output_bus: self.sumcheck_output_bus,
            sumcheck_challenge_bus: self.sumcheck_challenge_bus,
            prod_read_claim_input_bus: self.prod_read_claim_input_bus,
            prod_read_claim_bus: self.prod_read_claim_bus,
            prod_write_claim_input_bus: self.prod_write_claim_input_bus,
            prod_write_claim_bus: self.prod_write_claim_bus,
            logup_claim_input_bus: self.logup_claim_input_bus,
            logup_claim_bus: self.logup_claim_bus,
        };

        let gkr_prod_read_sum_air = TowerProdReadSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            prod_claim_input_bus: self.prod_read_claim_input_bus,
            prod_claim_bus: self.prod_read_claim_bus,
        };

        let gkr_prod_write_sum_air = TowerProdWriteSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            prod_claim_input_bus: self.prod_write_claim_input_bus,
            prod_claim_bus: self.prod_write_claim_bus,
        };

        let gkr_logup_sum_air = TowerLogupSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            logup_claim_input_bus: self.logup_claim_input_bus,
            logup_claim_bus: self.logup_claim_bus,
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
            Arc::new(gkr_prod_read_sum_air) as AirRef<_>,
            Arc::new(gkr_prod_write_sum_air) as AirRef<_>,
            Arc::new(gkr_logup_sum_air) as AirRef<_>,
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
    let mut proof_q0_claims = Vec::new();
    let mut layer_records = Vec::new();
    let mut tower_records = Vec::new();
    let mut sumcheck_records = Vec::new();
    let mut mus_records = Vec::new();
    let mut q0_claims = Vec::new();

    eyre::ensure!(
        proofs.len() == preflights.len(),
        "proof/preflight length mismatch"
    );

    for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights).enumerate() {
        let mut has_chip = false;
        let mut first_chip_alpha = EF::ZERO;
        let mut first_chip_q0 = EF::ZERO;
        let mut last_input_layer_claim = EF::ZERO;
        let mut last_layer_output_lambda = EF::ZERO;
        let mut last_layer_output_mu = EF::ZERO;

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
                sorted_idx_by_chip.get(&entry.chip_idx).copied().unwrap_or(usize::MAX),
                entry.instance_idx,
            )
        });
        for (entry_idx, pf_entry) in sorted_pf_entries.into_iter().enumerate() {
            let chip_idx = pf_entry.chip_idx;
            let instance_idx = pf_entry.instance_idx;
            let chip_instances = proof.chip_proofs.get(&chip_idx).ok_or_else(|| {
                eyre::eyre!("missing chip proof instances for chip {chip_idx}")
            })?;
            let chip_proof = chip_instances.get(instance_idx).ok_or_else(|| {
                eyre::eyre!("missing chip proof instance {instance_idx} for chip {chip_idx}")
            })?;
                has_chip = true;
                let mut ts = ReadOnlyTranscript::new(&preflight.transcript, pf_entry.tidx);
                let schedule = record_gkr_transcript(&mut ts, chip_idx, chip_proof);

                let circuit_vk = circuit_vk_for_idx(child_vk, chip_idx).ok_or_else(|| {
                    eyre::eyre!("missing circuit verifying key for index {chip_idx}")
                })?;
                // Use sequential index for NestedForLoop compatibility (idx must increment
                // by 0 or 1 within each proof_idx group).
                let idx = entry_idx;
                println!(
                    "processing chip name: {:?}",
                    child_vk.circuit_index_to_name.get(&chip_idx)
                );
                let (
                    chip_input_record,
                    layer_record,
                    tower_record,
                    sumcheck_record,
                    mus_record,
                    q0_claim,
                ) = build_chip_records(
                    proof_idx,
                    idx,
                    entry_idx == 0,
                    chip_proof,
                    circuit_vk,
                    &pf_entry.tower_replay,
                    &schedule,
                    pf_entry.tidx,
                )?;

                // Capture first chip's alpha and q0 for the proof-level record
                if entry_idx == 0 {
                    first_chip_alpha = chip_input_record.alpha_logup;
                    first_chip_q0 = q0_claim;
                }
                // Always update to latest chip for combined values
                last_input_layer_claim = chip_input_record.input_layer_claim;
                last_layer_output_lambda = chip_input_record.layer_output_lambda;
                last_layer_output_mu = chip_input_record.layer_output_mu;

                // Per-chip records (not input_records)
                layer_records.push(layer_record);
                tower_records.push(tower_record);
                sumcheck_records.push(sumcheck_record);
                mus_records.push(mus_record);
                q0_claims.push(q0_claim);
        }

        // ONE input record per proof (matching ProofIdxSubAir constraint)
        input_records.push(TowerInputRecord {
            proof_idx,
            idx: 0,
            tidx: preflight.proof_shape.post_tidx,
            n_logup: preflight.proof_shape.n_logup,
            alpha_logup: first_chip_alpha,
            input_layer_claim: last_input_layer_claim,
            layer_output_lambda: last_layer_output_lambda,
            layer_output_mu: last_layer_output_mu,
        });
        proof_q0_claims.push(first_chip_q0);

        if !has_chip {
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
        input_records.push(TowerInputRecord::default());
        proof_q0_claims.push(EF::ZERO);
        layer_records.push(TowerLayerRecord::default());
        sumcheck_records.push(TowerSumcheckRecord::default());
        tower_records.push(TowerTowerEvalRecord::default());
        mus_records.push(vec![]);
        q0_claims.push(EF::ZERO);
    }

    Ok(TowerBlobCpu {
        input_records,
        proof_q0_claims,
        layer_records,
        tower_records,
        sumcheck_records,
        mus_records,
        q0_claims,
    })
}

fn record_gkr_transcript<TS>(
    ts: &mut TS,
    _chip_idx: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
) -> TowerTranscriptSchedule
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>,
{
    let alpha_logup = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
    // Keep transcript index alignment with TowerInputAir's `tidx + 2 * D_EF` for q0.
    let _beta_placeholder = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
    if let Some(q0) = chip_proof
        .lk_out_evals
        .get(0)
        .and_then(|evals| evals.get(2))
    {
        ts.observe_ext(*q0);
    }

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

    let mut lambdas = Vec::with_capacity(layer_count);
    let mut mus = Vec::with_capacity(layer_count);
    let mut ris = Vec::new();

    for layer_idx in 0..layer_count {
        let lambda = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        lambdas.push(lambda);

        if layer_idx + 1 < layer_count {
            if let Some(round_msgs) = chip_proof.tower_proof.proofs.get(layer_idx) {
                for msg in round_msgs {
                    for eval in msg.evaluations.iter().take(3) {
                        ts.observe_ext(*eval);
                    }
                    let ri = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
                    ris.push(ri);
                }
            }
        }

        let mu = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        mus.push(mu);
    }

    let _ = read_count;
    TowerTranscriptSchedule {
        alpha_logup,
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
                eprintln!("failed to build GKR trace blob: {err:?}");
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
                .generate_trace(&(&blob.input_records, &blob.proof_q0_claims), required_height),
            Layer => TowerLayerTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.mus_records, &blob.q0_claims),
                required_height,
            ),
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
