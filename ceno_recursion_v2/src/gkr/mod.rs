//! # GKR Air Module
//!
//! The GKR protocol reduces a fractional sum claim $\sum_{y \in H_{\ell+n}}
//! \frac{\hat{p}(y)}{\hat{q}(y)} = 0$ to evaluation claims on the input layer polynomials at a
//! random point. This is done through a layer-by-layer recursive reduction, where each layer uses a
//! sumcheck protocol.
//!
//! The GKR Air Module verifies the [`GkrProof`](openvm_stark_backend::proof::GkrProof) struct and
//! consists of four AIRs:
//!
//! 1. **GkrInputAir** - Handles initial setup, coordinates other AIRs, and sends final claims to
//!    batch constraint module
//! 2. **GkrLayerAir** - Manages layer-by-layer GKR reduction (verifies
//!    [`verify_gkr`](openvm_stark_backend::verifier::fractional_sumcheck_gkr::verify_gkr))
//! 3. **GkrLayerSumcheckAir** - Executes sumcheck protocol for each layer (verifies
//!    [`verify_gkr_sumcheck`](openvm_stark_backend::verifier::fractional_sumcheck_gkr::verify_gkr_sumcheck))
//!
//! ## Architecture
//!
//! ```text
//!                                ┌─────────────────┐
//!                                │                 │───────────────────► TranscriptBus
//!                                │                 │
//!  GkrModuleBus ────────────────►│   GkrInputAir   │───────────────────► ExpBitsLenBus
//!                                │                 │
//!                                │                 │───────────────────► BatchConstraintModuleBus
//!                                └─────────────────┘
//!                                      ┆      ▲
//!                                      ┆      ┆
//!                     GkrLayerInputBus ┆      ┆ GkrLayerOutputBus
//!                                      ┆      ┆
//!                                      ▼      ┆
//!                             ┌─────────────────────────┐
//!                             │                         │──────────────► TranscriptBus
//!   ┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│       GkrLayerAir       │
//!   ┆                         │                         │──────────────► XiRandomnessBus
//!   ┆                         └─────────────────────────┘
//!   ┆                                  ┆      ▲
//!   ┆                                  ┆      ┆
//!   ┆              GkrSumcheckInputBus ┆      ┆ GkrSumcheckOutputBus
//!   ┆                                  ┆      ┆
//!   ┆                                  ▼      ┆
//!   ┆ GkrSumcheckChallengeBus ┌─────────────────────────┐
//!   ┆┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│                         │──────────────► TranscriptBus
//!   ┆                         │   GkrLayerSumcheckAir   │
//!   └┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄►│                         │──────────────► XiRandomnessBus
//!                             └─────────────────────────┘
//! ```

use std::sync::Arc;

use ::sumcheck::structs::IOPProverMessage;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory,
    p3_maybe_rayon::prelude::*,
    prover::{AirProvingContext, CpuBackend},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use recursion_circuit::primitives::exp_bits_len::ExpBitsLenTraceGenerator;
use strum::EnumCount;
use tracing::error;

use crate::{
    gkr::{
        bus::{GkrLayerInputBus, GkrLayerOutputBus},
        input::{GkrInputAir, GkrInputRecord, GkrInputTraceGenerator},
        layer::{
            GkrLayerAir, GkrLayerRecord, GkrLayerTraceGenerator, GkrLogupSumCheckClaimAir,
            GkrLogupSumCheckClaimTraceGenerator, GkrProdReadSumCheckClaimAir,
            GkrProdReadSumCheckClaimTraceGenerator, GkrProdWriteSumCheckClaimAir,
            GkrProdWriteSumCheckClaimTraceGenerator,
        },
        sumcheck::{GkrLayerSumcheckAir, GkrSumcheckRecord, GkrSumcheckTraceGenerator},
        tower::replay_tower_proof,
    },
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, Preflight, RecursionField,
        RecursionProof, RecursionVk, TraceGenModule,
    },
    tracegen::{ModuleChip, RowMajorChip},
};
use ceno_zkvm::{scheme::ZKVMChipProof, structs::VerifyingKey};
use eyre::{Result, WrapErr};
use tower::TowerReplayResult;

// Internal bus definitions
mod bus;
pub use bus::{
    GkrLogupClaimBus, GkrLogupClaimInputBus, GkrLogupClaimMessage, GkrLogupLayerChallengeMessage,
    GkrProdLayerChallengeMessage, GkrProdReadClaimBus, GkrProdReadClaimInputBus,
    GkrProdSumClaimMessage, GkrProdWriteClaimBus, GkrProdWriteClaimInputBus,
    GkrSumcheckChallengeBus, GkrSumcheckChallengeMessage, GkrSumcheckInputBus,
    GkrSumcheckInputMessage, GkrSumcheckOutputBus, GkrSumcheckOutputMessage,
};

// Sub-modules for different AIRs
pub mod input;
pub mod layer;
pub mod sumcheck;
mod tower;
pub struct GkrModule {
    // System Params
    l_skip: usize,
    // Global bus inventory
    bus_inventory: BusInventory,
    // Module buses
    layer_input_bus: GkrLayerInputBus,
    layer_output_bus: GkrLayerOutputBus,
    sumcheck_input_bus: GkrSumcheckInputBus,
    sumcheck_output_bus: GkrSumcheckOutputBus,
    sumcheck_challenge_bus: GkrSumcheckChallengeBus,
    prod_read_claim_input_bus: GkrProdReadClaimInputBus,
    prod_read_claim_bus: GkrProdReadClaimBus,
    prod_write_claim_input_bus: GkrProdWriteClaimInputBus,
    prod_write_claim_bus: GkrProdWriteClaimBus,
    logup_claim_input_bus: GkrLogupClaimInputBus,
    logup_claim_bus: GkrLogupClaimBus,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GkrTowerEvalRecord {
    pub(crate) read_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) write_layers: Vec<Vec<[EF; 2]>>,
    pub(crate) logup_layers: Vec<Vec<[EF; 4]>>,
}

struct GkrBlobCpu {
    input_records: Vec<GkrInputRecord>,
    layer_records: Vec<GkrLayerRecord>,
    tower_records: Vec<GkrTowerEvalRecord>,
    sumcheck_records: Vec<GkrSumcheckRecord>,
    mus_records: Vec<Vec<EF>>,
    q0_claims: Vec<EF>,
}

impl GkrModule {
    pub fn new(_vk: &RecursionVk, b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        GkrModule {
            l_skip: 0,
            bus_inventory,
            layer_input_bus: GkrLayerInputBus::new(b.new_bus_idx()),
            layer_output_bus: GkrLayerOutputBus::new(b.new_bus_idx()),
            sumcheck_input_bus: GkrSumcheckInputBus::new(b.new_bus_idx()),
            sumcheck_output_bus: GkrSumcheckOutputBus::new(b.new_bus_idx()),
            sumcheck_challenge_bus: GkrSumcheckChallengeBus::new(b.new_bus_idx()),
            prod_read_claim_input_bus: GkrProdReadClaimInputBus::new(b.new_bus_idx()),
            prod_read_claim_bus: GkrProdReadClaimBus::new(b.new_bus_idx()),
            prod_write_claim_input_bus: GkrProdWriteClaimInputBus::new(b.new_bus_idx()),
            prod_write_claim_bus: GkrProdWriteClaimBus::new(b.new_bus_idx()),
            logup_claim_input_bus: GkrLogupClaimInputBus::new(b.new_bus_idx()),
            logup_claim_bus: GkrLogupClaimBus::new(b.new_bus_idx()),
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
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        let _ = (self, child_vk, proof, preflight);
        ts.observe_ext(EF::ZERO);
    }
}

fn convert_logup_claim(chip_proof: &ZKVMChipProof<RecursionField>, layer_idx: usize) -> [EF; 4] {
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
    chip_idx: usize,
    chip_proof: &ZKVMChipProof<RecursionField>,
    circuit_vk: &VerifyingKey<RecursionField>,
) -> Result<(
    GkrInputRecord,
    GkrLayerRecord,
    GkrTowerEvalRecord,
    GkrSumcheckRecord,
    Vec<EF>,
    EF,
)> {
    let replay =
        replay_tower_proof(chip_proof, circuit_vk).wrap_err("failed to replay tower proof")?;

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

    let tower_record = GkrTowerEvalRecord {
        read_layers,
        write_layers,
        logup_layers,
    };

    let mut layer_record = GkrLayerRecord {
        proof_idx,
        idx: chip_idx,
        tidx: 0,
        layer_claims: Vec::with_capacity(layer_count),
        lambdas: vec![EF::ZERO; layer_count],
        eq_at_r_primes: vec![EF::ZERO; layer_count],
        prod_counts: vec![1; layer_count],
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
        debug_assert_eq!(
            read_len, write_len,
            "read/write prod spec count mismatch at layer {layer_idx}"
        );
        layer_record.prod_counts[layer_idx] = read_len.max(1);
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

    let mut sumcheck_record = GkrSumcheckRecord {
        proof_idx,
        tidx: 0,
        evals: Vec::new(),
        ris: Vec::new(),
        claims: vec![EF::ZERO; layer_count],
    };

    for round_msgs in &chip_proof.tower_proof.proofs {
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

    let input_record = GkrInputRecord {
        proof_idx,
        idx: chip_idx,
        tidx: 0,
        n_logup: layer_count,
        n_max: layer_count,
        alpha_logup: EF::ZERO,
        input_layer_claim,
    };
    let flattened_ris: Vec<EF> = replay
        .layers
        .iter()
        .flat_map(|layer| layer.challenges.iter().copied())
        .collect();
    sumcheck_record.ris = flattened_ris;
    debug_assert_eq!(
        sumcheck_record.ris.len(),
        sumcheck_record.evals.len(),
        "tower replay produced mismatched round counts",
    );
    for (layer_idx, data) in replay.layers.iter().enumerate() {
        if layer_idx < layer_record.eq_at_r_primes.len() {
            layer_record.eq_at_r_primes[layer_idx] = data.eq_at_r;
            layer_record.lambdas[layer_idx] = data.lambda;
            mus_record[layer_idx] = data.mu;
        }
        if layer_idx < sumcheck_record.claims.len() {
            sumcheck_record.claims[layer_idx] = data.claim_in;
            layer_record.sumcheck_claims[layer_idx] = data.claim_in;
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

    Ok((
        input_record,
        layer_record,
        tower_record,
        sumcheck_record,
        mus_record,
        q0_claim,
    ))
}

impl AirModule for GkrModule {
    fn num_airs(&self) -> usize {
        GkrModuleChipDiscriminants::COUNT
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let gkr_input_air = GkrInputAir {
            l_skip: self.l_skip,
            gkr_module_bus: self.bus_inventory.gkr_module_bus,
            bc_module_bus: self.bus_inventory.bc_module_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            layer_input_bus: self.layer_input_bus,
            layer_output_bus: self.layer_output_bus,
        };

        let gkr_layer_air = GkrLayerAir {
            transcript_bus: self.bus_inventory.transcript_bus,
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

        let gkr_prod_read_sum_air = GkrProdReadSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            prod_claim_input_bus: self.prod_read_claim_input_bus,
            prod_claim_bus: self.prod_read_claim_bus,
        };

        let gkr_prod_write_sum_air = GkrProdWriteSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            prod_claim_input_bus: self.prod_write_claim_input_bus,
            prod_claim_bus: self.prod_write_claim_bus,
        };

        let gkr_logup_sum_air = GkrLogupSumCheckClaimAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            logup_claim_input_bus: self.logup_claim_input_bus,
            logup_claim_bus: self.logup_claim_bus,
        };

        let gkr_sumcheck_air = GkrLayerSumcheckAir::new(
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

impl GkrModule {
    #[tracing::instrument(skip_all)]
    fn generate_blob(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        exp_bits_len_gen: &ExpBitsLenTraceGenerator,
    ) -> Result<GkrBlobCpu> {
        let _ = (self, preflights, exp_bits_len_gen);
        let mut input_records = Vec::new();
        let mut layer_records = Vec::new();
        let mut tower_records = Vec::new();
        let mut sumcheck_records = Vec::new();
        let mut mus_records = Vec::new();
        let mut q0_claims = Vec::new();

        for (proof_idx, proof) in proofs.iter().enumerate() {
            let mut has_chip = false;
            for (&chip_idx, chip_instances) in &proof.chip_proofs {
                if let Some(chip_proof) = chip_instances.first() {
                    has_chip = true;
                    let circuit_vk = circuit_vk_for_idx(child_vk, chip_idx).ok_or_else(|| {
                        eyre::eyre!("missing circuit verifying key for index {chip_idx}")
                    })?;
                    let (
                        input_record,
                        layer_record,
                        tower_record,
                        sumcheck_record,
                        mus_record,
                        q0_claim,
                    ) = build_chip_records(proof_idx, chip_idx, chip_proof, circuit_vk)?;
                    input_records.push(input_record);
                    layer_records.push(layer_record);
                    tower_records.push(tower_record);
                    sumcheck_records.push(sumcheck_record);
                    mus_records.push(mus_record);
                    q0_claims.push(q0_claim);
                }
            }

            if !has_chip {
                input_records.push(GkrInputRecord {
                    proof_idx,
                    ..Default::default()
                });
                layer_records.push(GkrLayerRecord {
                    idx: 0,
                    proof_idx,
                    ..Default::default()
                });
                tower_records.push(GkrTowerEvalRecord::default());
                sumcheck_records.push(GkrSumcheckRecord {
                    proof_idx,
                    ..Default::default()
                });
                mus_records.push(vec![]);
                q0_claims.push(EF::ZERO);
            }
        }

        if input_records.is_empty() {
            input_records.push(GkrInputRecord::default());
            layer_records.push(GkrLayerRecord::default());
            sumcheck_records.push(GkrSumcheckRecord::default());
            tower_records.push(GkrTowerEvalRecord::default());
            mus_records.push(vec![]);
            q0_claims.push(EF::ZERO);
        }

        Ok(GkrBlobCpu {
            input_records,
            layer_records,
            tower_records,
            sumcheck_records,
            mus_records,
            q0_claims,
        })
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>> for GkrModule {
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
            GkrModuleChip::Input,
            GkrModuleChip::Layer,
            GkrModuleChip::ProdReadClaim,
            GkrModuleChip::ProdWriteClaim,
            GkrModuleChip::LogupClaim,
            GkrModuleChip::LayerSumcheck,
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
enum GkrModuleChip {
    Input,
    Layer,
    ProdReadClaim,
    ProdWriteClaim,
    LogupClaim,
    LayerSumcheck,
}

impl GkrModuleChip {
    fn index(&self) -> usize {
        GkrModuleChipDiscriminants::from(self) as usize
    }
}

impl RowMajorChip<F> for GkrModuleChip {
    type Ctx<'a> = GkrBlobCpu;

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
        use GkrModuleChip::*;
        match self {
            Input => GkrInputTraceGenerator
                .generate_trace(&(&blob.input_records, &blob.q0_claims), required_height),
            Layer => GkrLayerTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.mus_records, &blob.q0_claims),
                required_height,
            ),
            ProdReadClaim => GkrProdReadSumCheckClaimTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.tower_records, &blob.mus_records),
                required_height,
            ),
            ProdWriteClaim => GkrProdWriteSumCheckClaimTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.tower_records, &blob.mus_records),
                required_height,
            ),
            LogupClaim => GkrLogupSumCheckClaimTraceGenerator.generate_trace(
                &(&blob.layer_records, &blob.tower_records, &blob.mus_records),
                required_height,
            ),
            LayerSumcheck => GkrSumcheckTraceGenerator.generate_trace(
                &(&blob.sumcheck_records, &blob.mus_records),
                required_height,
            ),
        }
    }
}

#[cfg(feature = "cuda")]
mod cuda_tracegen {
    use openvm_cuda_backend::GpuBackend;
    use openvm_stark_backend::p3_maybe_rayon::prelude::*;

    use super::*;
    use crate::{
        cuda::{GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, vk::VerifyingKeyGpu},
        tracegen::cuda::generate_gpu_proving_ctx,
    };

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for GkrModule {
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
            let _ = (
                self,
                child_vk,
                proofs,
                preflights,
                exp_bits_len_gen,
                required_heights,
            );
            unimplemented!("GKR GPU trace generation is not implemented for ZKVM proofs");
        }
    }
}
