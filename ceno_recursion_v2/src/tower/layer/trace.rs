use core::borrow::BorrowMut;

use openvm_stark_backend::p3_maybe_rayon::prelude::*;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::TowerLayerCols;
use crate::{
    tower::{TowerTowerEvalRecord, interpolate_pair, tower_transcript_len},
    tracegen::RowMajorChip,
};

fn ef_one() -> EF {
    EF::ONE
}

fn weight_values(record: &TowerLayerRecord, layer_idx: usize) -> (EF, EF, EF, EF) {
    let alpha = record.lambda_at(layer_idx);
    let mut pow = ef_one();
    let has_read = record.read_counts.iter().any(|&count| count != 0);
    let has_write = record.write_counts.iter().any(|&count| count != 0);
    let has_logup = record.logup_counts.iter().any(|&count| count != 0);

    let read_weight = if has_read && record.read_active_at(layer_idx) {
        let weight = pow;
        pow *= alpha;
        weight
    } else {
        if has_read {
            pow *= alpha;
        }
        EF::ZERO
    };
    let write_weight = if has_write && record.write_active_at(layer_idx) {
        let weight = pow;
        pow *= alpha;
        weight
    } else {
        if has_write {
            pow *= alpha;
        }
        EF::ZERO
    };
    let (logup_p_weight, logup_q_weight) = if has_logup && record.logup_active_at(layer_idx) {
        let p_weight = pow;
        let q_weight = pow * alpha;
        (p_weight, q_weight)
    } else {
        (EF::ZERO, EF::ZERO)
    };
    (read_weight, write_weight, logup_p_weight, logup_q_weight)
}

fn weight_bases(
    record: &TowerLayerRecord,
    layer_idx: usize,
) -> ([F; D_EF], [F; D_EF], [F; D_EF], [F; D_EF]) {
    let (read_weight, write_weight, logup_p_weight, logup_q_weight) =
        weight_values(record, layer_idx);
    (
        read_weight
            .as_basis_coefficients_slice()
            .try_into()
            .unwrap(),
        write_weight
            .as_basis_coefficients_slice()
            .try_into()
            .unwrap(),
        logup_p_weight
            .as_basis_coefficients_slice()
            .try_into()
            .unwrap(),
        logup_q_weight
            .as_basis_coefficients_slice()
            .try_into()
            .unwrap(),
    )
}

/// Minimal record for parallel tower layer trace generation
#[derive(Debug, Clone, Default)]
pub struct TowerLayerRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub fork_id: usize,
    pub is_first_air_idx: bool,
    pub tidx: usize,
    pub layer_claims: Vec<[EF; 4]>,
    pub lambdas: Vec<EF>,
    pub final_alpha: EF,
    pub eq_at_r_primes: Vec<EF>,
    pub read_counts: Vec<usize>,
    pub write_counts: Vec<usize>,
    pub logup_counts: Vec<usize>,
    pub read_claims: Vec<EF>,
    pub read_prime_claims: Vec<EF>,
    pub write_claims: Vec<EF>,
    pub write_prime_claims: Vec<EF>,
    pub logup_claims: Vec<EF>,
    pub logup_prime_claims: Vec<EF>,
    pub sumcheck_claims: Vec<EF>,
    pub sumcheck_claim_outs: Vec<EF>,
}

impl TowerLayerRecord {
    #[inline]
    pub(crate) fn layer_count(&self) -> usize {
        self.layer_claims.len()
    }

    #[inline]
    pub(crate) fn lambda_at(&self, layer_idx: usize) -> EF {
        self.lambdas.get(layer_idx).copied().unwrap_or(EF::ZERO)
    }

    #[inline]
    pub(crate) fn lambda_prime_at(&self, layer_idx: usize) -> EF {
        if layer_idx == 0 {
            EF::ONE
        } else {
            self.lambdas
                .get(layer_idx.saturating_sub(1))
                .copied()
                .unwrap_or(EF::ONE)
        }
    }

    #[inline]
    pub(crate) fn eq_at(&self, layer_idx: usize) -> EF {
        self.eq_at_r_primes
            .get(layer_idx)
            .copied()
            .unwrap_or(EF::ZERO)
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn sumcheck_claim_at(&self, layer_idx: usize) -> EF {
        self.sumcheck_claims
            .get(layer_idx)
            .copied()
            .unwrap_or(EF::ZERO)
    }

    #[inline]
    pub(crate) fn read_claim_at(&self, layer_idx: usize) -> (EF, EF) {
        (
            self.read_claims.get(layer_idx).copied().unwrap_or(EF::ZERO),
            self.read_prime_claims
                .get(layer_idx)
                .copied()
                .unwrap_or(EF::ZERO),
        )
    }

    #[inline]
    pub(crate) fn write_claim_at(&self, layer_idx: usize) -> (EF, EF) {
        (
            self.write_claims
                .get(layer_idx)
                .copied()
                .unwrap_or(EF::ZERO),
            self.write_prime_claims
                .get(layer_idx)
                .copied()
                .unwrap_or(EF::ZERO),
        )
    }

    #[inline]
    pub(crate) fn logup_claim_at(&self, layer_idx: usize) -> (EF, EF) {
        (
            self.logup_claims
                .get(layer_idx)
                .copied()
                .unwrap_or(EF::ZERO),
            self.logup_prime_claims
                .get(layer_idx)
                .copied()
                .unwrap_or(EF::ZERO),
        )
    }

    #[inline]
    pub(crate) fn layer_tidx(&self, layer_idx: usize) -> usize {
        self.tidx
            + (0..layer_idx)
                .map(|idx| {
                    tower_transcript_len::compact_layer_span(
                        idx,
                        self.read_active_at(idx),
                        self.write_active_at(idx),
                        self.logup_active_at(idx),
                    )
                })
                .sum::<usize>()
    }

    #[inline]
    pub(crate) fn read_active_at(&self, layer_idx: usize) -> bool {
        self.read_counts.get(layer_idx).copied().unwrap_or(0) != 0
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn read_count_at(&self, layer_idx: usize) -> usize {
        self.read_counts.get(layer_idx).copied().unwrap_or(0)
    }

    #[inline]
    pub(crate) fn write_active_at(&self, layer_idx: usize) -> bool {
        self.write_counts.get(layer_idx).copied().unwrap_or(0) != 0
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn write_count_at(&self, layer_idx: usize) -> usize {
        self.write_counts.get(layer_idx).copied().unwrap_or(0)
    }

    #[inline]
    pub(crate) fn logup_active_at(&self, layer_idx: usize) -> bool {
        self.logup_counts.get(layer_idx).copied().unwrap_or(0) != 0
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn logup_count_at(&self, layer_idx: usize) -> usize {
        self.logup_counts.get(layer_idx).copied().unwrap_or(0)
    }

    #[inline]
    pub(crate) fn claim_tidx(&self, layer_idx: usize) -> usize {
        self.layer_tidx(layer_idx) + tower_transcript_len::claim_offset_in_layer(layer_idx)
    }
}

pub struct TowerLayerTraceGenerator;

impl RowMajorChip<F> for TowerLayerTraceGenerator {
    // (gkr_layer_records, tower eval records, mus, q0_claims)
    type Ctx<'a> = (
        &'a [TowerLayerRecord],
        &'a [TowerTowerEvalRecord],
        &'a [Vec<EF>],
        &'a [EF],
    );

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (gkr_layer_records, tower_records, mus, q0_claims) = ctx;
        debug_assert_eq!(gkr_layer_records.len(), mus.len());
        debug_assert_eq!(gkr_layer_records.len(), tower_records.len());
        debug_assert_eq!(gkr_layer_records.len(), q0_claims.len());

        let width = TowerLayerCols::<F>::width();
        let rows_per_proof: Vec<usize> = gkr_layer_records
            .iter()
            .map(|record| record.layer_count().max(1))
            .collect();
        let num_valid_rows: usize = rows_per_proof.iter().sum();
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two().max(1)
        };
        let mut trace = vec![F::ZERO; height * width];

        let (data_slice, _) = trace.split_at_mut(num_valid_rows * width);
        let mut trace_slices: Vec<&mut [F]> = Vec::with_capacity(rows_per_proof.len());
        let mut remaining = data_slice;

        for &num_rows in &rows_per_proof {
            let chunk_size = num_rows * width;
            let (chunk, rest) = remaining.split_at_mut(chunk_size);
            trace_slices.push(chunk);
            remaining = rest;
        }

        trace_slices
            .par_iter_mut()
            .zip(
                gkr_layer_records
                    .par_iter()
                    .zip(tower_records.par_iter())
                    .zip(mus.par_iter())
                    .zip(q0_claims.par_iter()),
            )
            .for_each(|(chunk, (((record, tower), mus_for_proof), q0_claim))| {
                let q0_basis = q0_claim.as_basis_coefficients_slice();
                let mus_for_proof = mus_for_proof.as_slice();

                if record.layer_claims.is_empty() {
                    debug_assert_eq!(chunk.len(), width);
                    let row_data = &mut chunk[..width];
                    let cols: &mut TowerLayerCols<F> = row_data.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.idx = F::from_usize(record.idx);
                    cols.fork_id = F::from_usize(record.fork_id);
                    cols.is_first_air_idx = F::from_bool(record.is_first_air_idx);
                    cols.is_first = F::ONE;
                    cols.is_dummy = F::ONE;
                    cols.layer_idx = F::ZERO;
                    cols.tidx = F::from_usize(record.tidx);
                    cols.lambda = [F::ZERO; D_EF];
                    cols.final_alpha = [F::ZERO; D_EF];
                    let mut lambda_prime_one = [F::ZERO; D_EF];
                    lambda_prime_one[0] = F::ONE;
                    cols.lambda_prime = lambda_prime_one;
                    cols.mu = [F::ZERO; D_EF];
                    cols.sumcheck_claim_in = [F::ZERO; D_EF];
                    cols.sumcheck_claim_out = [F::ZERO; D_EF];
                    cols.read_claim = [F::ZERO; D_EF];
                    cols.read_claim_prime = [F::ZERO; D_EF];
                    cols.write_claim = [F::ZERO; D_EF];
                    cols.write_claim_prime = [F::ZERO; D_EF];
                    cols.logup_claim = [F::ZERO; D_EF];
                    cols.logup_claim_prime = [F::ZERO; D_EF];
                    cols.read_active = F::ZERO;
                    cols.write_active = F::ZERO;
                    cols.logup_active = F::ZERO;
                    cols.read_p0 = [F::ZERO; D_EF];
                    cols.read_p1 = [F::ZERO; D_EF];
                    cols.read_p_xi = [F::ZERO; D_EF];
                    cols.write_p0 = [F::ZERO; D_EF];
                    cols.write_p1 = [F::ZERO; D_EF];
                    cols.write_p_xi = [F::ZERO; D_EF];
                    cols.logup_p0 = [F::ZERO; D_EF];
                    cols.logup_p1 = [F::ZERO; D_EF];
                    cols.logup_q0 = [F::ZERO; D_EF];
                    cols.logup_q1 = [F::ZERO; D_EF];
                    cols.logup_p_xi = [F::ZERO; D_EF];
                    cols.logup_q_xi = [F::ZERO; D_EF];
                    cols.read_weight = [F::ZERO; D_EF];
                    cols.write_weight = [F::ZERO; D_EF];
                    cols.logup_p_weight = [F::ZERO; D_EF];
                    cols.logup_q_weight = [F::ZERO; D_EF];
                    cols.weighted_prime_fold = [F::ZERO; D_EF];
                    cols.eq_at_r_prime = [F::ZERO; D_EF];
                    cols.r0_claim.copy_from_slice(q0_basis);
                    cols.w0_claim.copy_from_slice(q0_basis);
                    cols.q0_claim.copy_from_slice(q0_basis);
                    return;
                }

                for (layer_idx, row_data) in chunk
                    .chunks_mut(width)
                    .take(record.layer_count())
                    .enumerate()
                {
                    let cols: &mut TowerLayerCols<F> = row_data.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.is_dummy = F::ZERO;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.idx = F::from_usize(record.idx);
                    cols.fork_id = F::from_usize(record.fork_id);
                    cols.is_first_air_idx = F::from_bool(layer_idx == 0 && record.is_first_air_idx);
                    cols.is_first = F::from_bool(layer_idx == 0);
                    cols.layer_idx = F::from_usize(layer_idx);
                    cols.tidx = F::from_usize(record.layer_tidx(layer_idx));
                    cols.lambda = record
                        .lambda_at(layer_idx)
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.final_alpha = record
                        .final_alpha
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.lambda_prime = record
                        .lambda_prime_at(layer_idx)
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    let mu = mus_for_proof.get(layer_idx).copied().unwrap_or(EF::ZERO);
                    cols.mu = mu.as_basis_coefficients_slice().try_into().unwrap();
                    let sumcheck_claim = record.sumcheck_claim_at(layer_idx);
                    cols.sumcheck_claim_in = sumcheck_claim
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.sumcheck_claim_out = record
                        .sumcheck_claim_outs
                        .get(layer_idx)
                        .copied()
                        .unwrap_or(EF::ZERO)
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    let (read_claim, read_prime) = record.read_claim_at(layer_idx);
                    cols.read_claim = read_claim.as_basis_coefficients_slice().try_into().unwrap();
                    let (write_claim, write_prime) = record.write_claim_at(layer_idx);
                    cols.write_claim = write_claim
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    let (logup_claim, logup_prime) = record.logup_claim_at(layer_idx);
                    cols.logup_claim = logup_claim
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.read_active = F::from_bool(record.read_active_at(layer_idx));
                    cols.write_active = F::from_bool(record.write_active_at(layer_idx));
                    cols.logup_active = F::from_bool(record.logup_active_at(layer_idx));
                    let read_pair = tower
                        .read_layers
                        .get(layer_idx)
                        .and_then(|rows| rows.first())
                        .copied()
                        .unwrap_or([EF::ZERO; 2]);
                    let write_pair = tower
                        .write_layers
                        .get(layer_idx)
                        .and_then(|rows| rows.first())
                        .copied()
                        .unwrap_or([EF::ZERO; 2]);
                    let logup_quad = tower
                        .logup_layers
                        .get(layer_idx)
                        .and_then(|rows| rows.first())
                        .copied()
                        .unwrap_or([EF::ZERO; 4]);
                    cols.read_p0 = read_pair[0]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.read_p1 = read_pair[1]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.read_p_xi = interpolate_pair(read_pair, mu)
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.write_p0 = write_pair[0]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.write_p1 = write_pair[1]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.write_p_xi = interpolate_pair(write_pair, mu)
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.logup_p0 = logup_quad[0]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.logup_p1 = logup_quad[1]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.logup_q0 = logup_quad[2]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.logup_q1 = logup_quad[3]
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.logup_p_xi = interpolate_pair([logup_quad[0], logup_quad[1]], mu)
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.logup_q_xi = interpolate_pair([logup_quad[2], logup_quad[3]], mu)
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    let (read_weight, write_weight, logup_p_weight, logup_q_weight) =
                        weight_bases(record, layer_idx);
                    cols.read_weight = read_weight;
                    cols.write_weight = write_weight;
                    cols.logup_p_weight = logup_p_weight;
                    cols.logup_q_weight = logup_q_weight;
                    let eq_at_r_prime = record.eq_at(layer_idx);
                    cols.eq_at_r_prime = eq_at_r_prime
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    let weighted_prime_fold = record
                        .sumcheck_claim_outs
                        .get(layer_idx)
                        .copied()
                        .unwrap_or(EF::ZERO)
                        * eq_at_r_prime.inverse();
                    cols.weighted_prime_fold = weighted_prime_fold
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.r0_claim.copy_from_slice(q0_basis);
                    cols.w0_claim.copy_from_slice(q0_basis);
                    cols.q0_claim.copy_from_slice(q0_basis);
                    cols.read_claim_prime =
                        read_prime.as_basis_coefficients_slice().try_into().unwrap();
                    cols.write_claim_prime = write_prime
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.logup_claim_prime = logup_prime
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                }
            });

        Some(RowMajorMatrix::new(trace, width))
    }
}
