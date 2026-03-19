use core::borrow::BorrowMut;

use openvm_stark_backend::p3_maybe_rayon::prelude::*;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::TowerLayerCols;
use crate::tracegen::RowMajorChip;

/// Minimal record for parallel tower layer trace generation
#[derive(Debug, Clone, Default)]
pub struct TowerLayerRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub tidx: usize,
    pub layer_claims: Vec<[EF; 4]>,
    pub lambdas: Vec<EF>,
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
        if layer_idx == 0 {
            self.tidx
        } else {
            let j = layer_idx;
            self.tidx + D_EF * (2 * j * j + 4 * j - 1)
        }
    }

    #[inline]
    pub(crate) fn read_count_at(&self, layer_idx: usize) -> usize {
        self.read_counts.get(layer_idx).copied().unwrap_or(1)
    }

    #[inline]
    pub(crate) fn write_count_at(&self, layer_idx: usize) -> usize {
        self.write_counts.get(layer_idx).copied().unwrap_or(1)
    }

    #[inline]
    pub(crate) fn logup_count_at(&self, layer_idx: usize) -> usize {
        self.logup_counts.get(layer_idx).copied().unwrap_or(1)
    }

    #[inline]
    pub(crate) fn claim_tidx(&self, layer_idx: usize) -> usize {
        let base = self.layer_tidx(layer_idx);
        let extra = if layer_idx == 0 { 0 } else { D_EF };
        base + extra + layer_idx * 4 * D_EF
    }
}

pub struct TowerLayerTraceGenerator;

impl RowMajorChip<F> for TowerLayerTraceGenerator {
    // (gkr_layer_records, mus, q0_claims)
    type Ctx<'a> = (&'a [TowerLayerRecord], &'a [Vec<EF>], &'a [EF]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (gkr_layer_records, mus, q0_claims) = ctx;
        debug_assert_eq!(gkr_layer_records.len(), mus.len());
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
                    .zip(mus.par_iter())
                    .zip(q0_claims.par_iter()),
            )
            .for_each(|(chunk, ((record, mus_for_proof), q0_claim))| {
                let q0_basis = q0_claim.as_basis_coefficients_slice();
                let mus_for_proof = mus_for_proof.as_slice();

                if record.layer_claims.is_empty() {
                    debug_assert_eq!(chunk.len(), width);
                    let row_data = &mut chunk[..width];
                    let cols: &mut TowerLayerCols<F> = row_data.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.idx = F::from_usize(record.idx);
                    cols.is_first_air_idx = F::ONE;
                    cols.is_first = F::ONE;
                    cols.is_dummy = F::ONE;
                    cols.layer_idx = F::ZERO;
                    cols.tidx = F::from_usize(record.tidx);
                    cols.lambda = [F::ZERO; D_EF];
                    let mut lambda_prime_one = [F::ZERO; D_EF];
                    lambda_prime_one[0] = F::ONE;
                    cols.lambda_prime = lambda_prime_one;
                    cols.mu = [F::ZERO; D_EF];
                    cols.sumcheck_claim_in = [F::ZERO; D_EF];
                    cols.read_claim = [F::ZERO; D_EF];
                    cols.read_claim_prime = [F::ZERO; D_EF];
                    cols.write_claim = [F::ZERO; D_EF];
                    cols.write_claim_prime = [F::ZERO; D_EF];
                    cols.logup_claim = [F::ZERO; D_EF];
                    cols.logup_claim_prime = [F::ZERO; D_EF];
                    cols.num_read_count = F::ZERO;
                    cols.num_write_count = F::ZERO;
                    cols.num_logup_count = F::ZERO;
                    cols.eq_at_r_prime = [F::ZERO; D_EF];
                    cols.r0_claim.copy_from_slice(q0_basis);
                    cols.w0_claim.copy_from_slice(q0_basis);
                    cols.q0_claim.copy_from_slice(q0_basis);
                    return;
                }

                chunk
                    .chunks_mut(width)
                    .take(record.layer_count())
                    .enumerate()
                    .for_each(|(layer_idx, row_data)| {
                        let cols: &mut TowerLayerCols<F> = row_data.borrow_mut();
                        cols.is_enabled = F::ONE;
                        cols.is_dummy = F::ZERO;
                        cols.proof_idx = F::from_usize(record.proof_idx);
                        cols.idx = F::from_usize(record.idx);
                        cols.is_first_air_idx = F::from_bool(layer_idx == 0);
                        cols.is_first = F::from_bool(layer_idx == 0);
                        cols.layer_idx = F::from_usize(layer_idx);
                        cols.tidx = F::from_usize(record.layer_tidx(layer_idx));
                        cols.lambda = record
                            .lambda_at(layer_idx)
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
                        let sumcheck_claim = if layer_idx == 0 {
                            EF::ZERO
                        } else {
                            record.sumcheck_claim_at(layer_idx)
                        };
                        cols.sumcheck_claim_in = sumcheck_claim
                            .as_basis_coefficients_slice()
                            .try_into()
                            .unwrap();
                        let (read_claim, read_prime) = record.read_claim_at(layer_idx);
                        cols.read_claim =
                            read_claim.as_basis_coefficients_slice().try_into().unwrap();
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
                        cols.num_read_count = F::from_usize(record.read_count_at(layer_idx).max(1));
                        cols.num_write_count =
                            F::from_usize(record.write_count_at(layer_idx).max(1));
                        cols.num_logup_count =
                            F::from_usize(record.logup_count_at(layer_idx).max(1));
                        cols.eq_at_r_prime = record
                            .eq_at(layer_idx)
                            .as_basis_coefficients_slice()
                            .try_into()
                            .unwrap();
                        cols.r0_claim.copy_from_slice(q0_basis);
                        cols.w0_claim.copy_from_slice(q0_basis);
                        cols.q0_claim.copy_from_slice(q0_basis);
                        if layer_idx == 0 {
                            cols.read_claim_prime.copy_from_slice(&cols.r0_claim);
                            cols.write_claim_prime.copy_from_slice(&cols.w0_claim);
                            cols.logup_claim_prime.copy_from_slice(&cols.q0_claim);
                        } else {
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
            });

        Some(RowMajorMatrix::new(trace, width))
    }
}
