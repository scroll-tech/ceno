use core::borrow::BorrowMut;

use openvm_circuit_primitives::{TraceSubRowGenerator, is_zero::IsZeroSubAir};
use openvm_stark_backend::p3_maybe_rayon::prelude::*;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::TowerLayerCols;
use crate::{tower::tower_transcript_len, tracegen::RowMajorChip};

/// Minimal record for parallel tower layer trace generation
#[derive(Debug, Clone, Default)]
pub struct TowerLayerRecord {
    pub proof_idx: usize,
    pub chip_idx: usize,
    pub is_first_air_idx: bool,
    pub tidx: usize,
    pub initial_tower_claim: EF,
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
    pub(crate) fn lambda_cur_at(&self, layer_idx: usize) -> EF {
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
        let mut tidx = self.tidx;
        for prior_layer_idx in 0..layer_idx {
            tidx += self.layer_span(prior_layer_idx);
        }
        tidx
    }

    #[inline]
    pub(crate) fn read_count_at(&self, layer_idx: usize) -> usize {
        self.read_counts.get(layer_idx).copied().unwrap_or(0)
    }

    #[inline]
    pub(crate) fn write_count_at(&self, layer_idx: usize) -> usize {
        self.write_counts.get(layer_idx).copied().unwrap_or(0)
    }

    #[inline]
    pub(crate) fn logup_count_at(&self, layer_idx: usize) -> usize {
        self.logup_counts.get(layer_idx).copied().unwrap_or(0)
    }

    #[inline]
    pub(crate) fn claim_tidx(&self, layer_idx: usize) -> usize {
        self.layer_tidx(layer_idx) + self.claim_offset_in_layer(layer_idx)
    }

    #[inline]
    pub(crate) fn out_eval_span(&self, layer_idx: usize) -> usize {
        let words = 2 * self.read_count_at(layer_idx)
            + 2 * self.write_count_at(layer_idx)
            + 4 * self.logup_count_at(layer_idx);
        words * D_EF
    }

    #[inline]
    pub(crate) fn claim_offset_in_layer(&self, layer_idx: usize) -> usize {
        if layer_idx == 0 {
            0
        } else {
            tower_transcript_len::SUMCHECK_INIT_LEN + layer_idx * tower_transcript_len::ROUND_LEN
        }
    }

    #[inline]
    pub(crate) fn lambda_tidx(&self, layer_idx: usize) -> usize {
        if layer_idx == 0 {
            self.layer_tidx(0) + self.out_eval_span(0) + tower_transcript_len::LABEL_COMBINE
        } else {
            self.mu_tidx(layer_idx) + D_EF + tower_transcript_len::LABEL_COMBINE
        }
    }

    #[inline]
    pub(crate) fn mu_tidx(&self, layer_idx: usize) -> usize {
        if layer_idx == 0 {
            self.lambda_tidx(0) + D_EF + tower_transcript_len::LABEL_PRODUCT_SUM
        } else {
            self.claim_tidx(layer_idx)
                + self.out_eval_span(layer_idx)
                + tower_transcript_len::LABEL_MERGE
        }
    }

    #[inline]
    pub(crate) fn layer_span(&self, layer_idx: usize) -> usize {
        if layer_idx == 0 {
            self.out_eval_span(0) + tower_transcript_len::ALPHA_BETA_LEN
        } else {
            tower_transcript_len::SUMCHECK_INIT_LEN
                + layer_idx * tower_transcript_len::ROUND_LEN
                + self.out_eval_span(layer_idx)
                + tower_transcript_len::MERGE_LEN
                + tower_transcript_len::ALPHA_LEN
        }
    }
}

#[inline]
pub(crate) fn ext_pow(base: EF, exp: usize) -> EF {
    (0..exp).fold(EF::ONE, |acc, _| acc * base)
}

#[inline]
fn ext_to_base(value: EF) -> [F; D_EF] {
    value.as_basis_coefficients_slice().try_into().unwrap()
}

#[inline]
fn ext_one_base() -> [F; D_EF] {
    ext_to_base(EF::ONE)
}

#[inline]
fn fill_noop_flag(cols: &mut TowerLayerCols<F>) {
    let noop_poly = cols.num_layers * (cols.num_layers - F::ONE);
    IsZeroSubAir.generate_subrow(noop_poly, (&mut cols.is_noop_aux.inv, &mut cols.is_noop));
}

pub struct TowerLayerTraceGenerator;

impl RowMajorChip<F> for TowerLayerTraceGenerator {
    type Ctx<'a> = (&'a [TowerLayerRecord], &'a [Vec<EF>]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (gkr_layer_records, mus) = ctx;
        debug_assert_eq!(gkr_layer_records.len(), mus.len());

        let width = TowerLayerCols::<F>::width();
        let rows_per_proof: Vec<usize> = gkr_layer_records
            .iter()
            .map(|record| record.layer_count().saturating_sub(1).max(1))
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
            .zip(gkr_layer_records.par_iter().zip(mus.par_iter()))
            .for_each(|(chunk, (record, mus_for_proof))| {
                let mus_for_proof = mus_for_proof.as_slice();
                let initial_tower_claim = ext_to_base(record.initial_tower_claim);
                let lambda_one = ext_one_base();
                let layer_count = record.layer_count();

                if layer_count <= 1 {
                    debug_assert_eq!(chunk.len(), width);
                    let row_data = &mut chunk[..width];
                    let cols: &mut TowerLayerCols<F> = row_data.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.chip_idx = F::from_usize(record.chip_idx);
                    cols.is_first_proof_idx = F::from_bool(record.is_first_air_idx);
                    cols.is_first_chip_idx = F::ONE;
                    cols.layer_idx = F::ZERO;
                    cols.tidx = F::from_usize(if layer_count == 0 {
                        record.tidx
                    } else {
                        record.layer_tidx(1)
                    });
                    let lambda_cur = if layer_count == 0 {
                        EF::ONE
                    } else {
                        record.lambda_at(0)
                    };
                    let mu = if layer_count == 0 {
                        EF::ZERO
                    } else {
                        mus_for_proof.first().copied().unwrap_or(EF::ZERO)
                    };
                    cols.lambda_next = ext_to_base(lambda_cur);
                    cols.lambda_cur = ext_to_base(lambda_cur);
                    cols.mu = ext_to_base(mu);
                    cols.sumcheck_claim_in = if layer_count == 0 {
                        [F::ZERO; D_EF]
                    } else {
                        initial_tower_claim
                    };
                    cols.read_claim_next = [F::ZERO; D_EF];
                    cols.read_claim_cur = [F::ZERO; D_EF];
                    cols.write_claim_next = [F::ZERO; D_EF];
                    cols.write_claim_cur = [F::ZERO; D_EF];
                    cols.logup_claim_next = [F::ZERO; D_EF];
                    cols.logup_claim_cur = [F::ZERO; D_EF];
                    cols.read_lambda_next_end = lambda_one;
                    cols.read_lambda_cur_end = lambda_one;
                    cols.write_lambda_next_end = lambda_one;
                    cols.write_lambda_cur_end = lambda_one;
                    cols.num_read_count = F::from_usize(record.read_count_at(0));
                    cols.num_write_count = F::from_usize(record.write_count_at(0));
                    cols.num_logup_count = F::from_usize(record.logup_count_at(0));
                    cols.num_layers = F::from_usize(layer_count);
                    fill_noop_flag(cols);
                    cols.eq_at_r_prime = [F::ZERO; D_EF];
                    return;
                }

                let mut prev_folded_claim = record.initial_tower_claim;
                for (row_position, row_data) in chunk
                    .chunks_mut(width)
                    .take(layer_count.saturating_sub(1))
                    .enumerate()
                {
                    let layer_idx = row_position + 1;
                    let cols: &mut TowerLayerCols<F> = row_data.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.chip_idx = F::from_usize(record.chip_idx);
                    cols.is_first_proof_idx =
                        F::from_bool(row_position == 0 && record.is_first_air_idx);
                    cols.is_first_chip_idx = F::from_bool(row_position == 0);
                    cols.layer_idx = F::from_usize(layer_idx);
                    cols.tidx = F::from_usize(record.layer_tidx(layer_idx));
                    cols.lambda_next = ext_to_base(record.lambda_at(layer_idx));
                    cols.lambda_cur = ext_to_base(record.lambda_cur_at(layer_idx));
                    let mu = mus_for_proof.get(layer_idx).copied().unwrap_or(EF::ZERO);
                    cols.mu = ext_to_base(mu);
                    cols.sumcheck_claim_in = ext_to_base(prev_folded_claim);
                    let (read_claim_next, read_claim_cur) = record.read_claim_at(layer_idx);
                    cols.read_claim_next = ext_to_base(read_claim_next);
                    let (write_claim_next, write_claim_cur) = record.write_claim_at(layer_idx);
                    cols.write_claim_next = ext_to_base(write_claim_next);
                    let (logup_claim_next, logup_claim_cur) = record.logup_claim_at(layer_idx);
                    cols.logup_claim_next = ext_to_base(logup_claim_next);
                    let read_count = record.read_count_at(layer_idx);
                    let write_count = record.write_count_at(layer_idx);
                    let logup_count = record.logup_count_at(layer_idx);
                    cols.num_read_count = F::from_usize(read_count);
                    cols.num_write_count = F::from_usize(write_count);
                    cols.num_logup_count = F::from_usize(logup_count);
                    cols.num_layers = F::from_usize(layer_count);
                    fill_noop_flag(cols);
                    let lambda_next = record.lambda_at(layer_idx);
                    let lambda_cur = record.lambda_cur_at(layer_idx);
                    let read_lambda_next_end = ext_pow(lambda_next, read_count);
                    let read_lambda_cur_end = ext_pow(lambda_cur, read_count);
                    let write_lambda_next_end =
                        read_lambda_next_end * ext_pow(lambda_next, write_count);
                    let write_lambda_cur_end =
                        read_lambda_cur_end * ext_pow(lambda_cur, write_count);
                    cols.read_lambda_next_end = ext_to_base(read_lambda_next_end);
                    cols.read_lambda_cur_end = ext_to_base(read_lambda_cur_end);
                    cols.write_lambda_next_end = ext_to_base(write_lambda_next_end);
                    cols.write_lambda_cur_end = ext_to_base(write_lambda_cur_end);
                    cols.eq_at_r_prime = ext_to_base(record.eq_at(layer_idx));
                    cols.read_claim_cur = ext_to_base(read_claim_cur);
                    cols.write_claim_cur = ext_to_base(write_claim_cur);
                    cols.logup_claim_cur = ext_to_base(logup_claim_cur);
                    prev_folded_claim = read_claim_next + write_claim_next + logup_claim_next;
                }
            });

        Some(RowMajorMatrix::new(trace, width))
    }
}
