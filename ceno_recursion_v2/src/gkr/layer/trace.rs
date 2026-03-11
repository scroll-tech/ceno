use core::borrow::BorrowMut;

use openvm_stark_backend::p3_maybe_rayon::prelude::*;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::GkrLayerCols;
use crate::tracegen::RowMajorChip;

/// Minimal record for parallel gkr layer trace generation
#[derive(Debug, Clone, Default)]
pub struct GkrLayerRecord {
    pub tidx: usize,
    pub layer_claims: Vec<[EF; 4]>,
    pub lambdas: Vec<EF>,
    pub eq_at_r_primes: Vec<EF>,
    pub prod_counts: Vec<usize>,
    pub logup_counts: Vec<usize>,
}

impl GkrLayerRecord {
    #[inline]
    pub(crate) fn layer_count(&self) -> usize {
        self.layer_claims.len()
    }

    #[inline]
    pub(crate) fn lambda_at(&self, layer_idx: usize) -> EF {
        self.lambdas.get(layer_idx).copied().unwrap_or(EF::ZERO)
    }

    #[inline]
    pub(crate) fn eq_at(&self, layer_idx: usize) -> EF {
        self.eq_at_r_primes.get(layer_idx).copied().unwrap_or(EF::ZERO)
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
    pub(crate) fn prod_count_at(&self, layer_idx: usize) -> usize {
        self.prod_counts.get(layer_idx).copied().unwrap_or(1)
    }

    #[inline]
    pub(crate) fn logup_count_at(&self, layer_idx: usize) -> usize {
        self.logup_counts.get(layer_idx).copied().unwrap_or(1)
    }
}

pub struct GkrLayerTraceGenerator;

impl RowMajorChip<F> for GkrLayerTraceGenerator {
    // (gkr_layer_records, mus, q0_claims)
    type Ctx<'a> = (&'a [GkrLayerRecord], &'a [Vec<EF>], &'a [EF]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (gkr_layer_records, mus, q0_claims) = ctx;
        debug_assert_eq!(gkr_layer_records.len(), mus.len());
        debug_assert_eq!(gkr_layer_records.len(), q0_claims.len());

        let width = GkrLayerCols::<F>::width();
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
            .enumerate()
            .for_each(|(proof_idx, (chunk, ((record, mus_for_proof), q0_claim)))| {
                let q0_basis = q0_claim.as_basis_coefficients_slice();
                let mus_for_proof = mus_for_proof.as_slice();

                if record.layer_claims.is_empty() {
                    debug_assert_eq!(chunk.len(), width);
                    let row_data = &mut chunk[..width];
                    let cols: &mut GkrLayerCols<F> = row_data.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.proof_idx = F::from_usize(proof_idx);
                    cols.idx = F::ZERO;
                    cols.is_first_air_idx = F::ONE;
                    cols.is_first = F::ONE;
                    cols.is_dummy = F::ONE;
                    cols.layer_idx = F::ZERO;
                    cols.tidx = F::from_usize(record.tidx);
                    cols.lambda = [F::ZERO; D_EF];
                    cols.mu = [F::ZERO; D_EF];
                    cols.sumcheck_claim_in = [F::ZERO; D_EF];
                    cols.read_claim = [F::ZERO; D_EF];
                    cols.write_claim = [F::ZERO; D_EF];
                    cols.logup_claim = [F::ZERO; D_EF];
                    cols.num_prod_count = F::ZERO;
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
                        let cols: &mut GkrLayerCols<F> = row_data.borrow_mut();
                        cols.is_enabled = F::ONE;
                        cols.is_dummy = F::ZERO;
                        cols.proof_idx = F::from_usize(proof_idx);
                        cols.idx = F::ZERO;
                        cols.is_first_air_idx = F::from_bool(layer_idx == 0);
                        cols.is_first = F::from_bool(layer_idx == 0);
                        cols.layer_idx = F::from_usize(layer_idx);
                        cols.tidx = F::from_usize(record.layer_tidx(layer_idx));
                        cols.lambda = record
                            .lambda_at(layer_idx)
                            .as_basis_coefficients_slice()
                            .try_into()
                            .unwrap();
                        let mu = mus_for_proof.get(layer_idx).copied().unwrap_or(EF::ZERO);
                        cols.mu = mu.as_basis_coefficients_slice().try_into().unwrap();
                        cols.sumcheck_claim_in = [F::ZERO; D_EF];
                        cols.read_claim = [F::ZERO; D_EF];
                        cols.write_claim = [F::ZERO; D_EF];
                        cols.logup_claim = [F::ZERO; D_EF];
                        cols.num_prod_count =
                            F::from_usize(record.prod_count_at(layer_idx).max(1));
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
                    });
            });

        Some(RowMajorMatrix::new(trace, width))
    }
}
