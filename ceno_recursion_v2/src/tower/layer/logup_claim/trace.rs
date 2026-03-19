use core::borrow::BorrowMut;

use openvm_stark_backend::p3_maybe_rayon::prelude::*;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::TowerLogupSumCheckClaimCols;
use crate::{
    tower::{TowerTowerEvalRecord, interpolate_pair, layer::trace::TowerLayerRecord},
    tracegen::RowMajorChip,
};

pub struct TowerLogupSumCheckClaimTraceGenerator;

type LogupTraceCtx<'a> = (
    &'a [TowerLayerRecord],
    &'a [TowerTowerEvalRecord],
    &'a [Vec<EF>],
);

fn logup_rows_for_record(record: &TowerLayerRecord) -> usize {
    if record.layer_count() == 0 {
        1
    } else {
        (0..record.layer_count())
            .map(|layer_idx| record.logup_count_at(layer_idx).max(1))
            .sum()
    }
}

impl RowMajorChip<F> for TowerLogupSumCheckClaimTraceGenerator {
    type Ctx<'a> = LogupTraceCtx<'a>;

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (records, towers, mus_records) = ctx;
        let width = TowerLogupSumCheckClaimCols::<F>::width();
        let rows_per_proof: Vec<usize> = records.iter().map(logup_rows_for_record).collect();
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
        for &rows in &rows_per_proof {
            let (chunk, rest) = remaining.split_at_mut(rows * width);
            trace_slices.push(chunk);
            remaining = rest;
        }

        trace_slices
            .par_iter_mut()
            .zip(
                records
                    .par_iter()
                    .zip(towers.par_iter())
                    .zip(mus_records.par_iter()),
            )
            .for_each(|(chunk, ((record, tower), mus_for_proof))| {
                if record.layer_count() == 0 {
                    debug_assert_eq!(chunk.len(), width);
                    let row_data = &mut chunk[..width];
                    let cols: &mut TowerLogupSumCheckClaimCols<F> = row_data.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.is_first_layer = F::ONE;
                    cols.is_first = F::ONE;
                    cols.is_dummy = F::ONE;
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.idx = F::from_usize(record.idx);
                    cols.layer_idx = F::ZERO;
                    cols.index_id = F::ZERO;
                    cols.tidx = F::from_usize(record.tidx);
                    cols.lambda = [F::ZERO; D_EF];
                    let mut lambda_prime_one = [F::ZERO; D_EF];
                    lambda_prime_one[0] = F::ONE;
                    cols.lambda_prime = lambda_prime_one;
                    cols.mu = [F::ZERO; D_EF];
                    cols.p_xi_0 = [F::ZERO; D_EF];
                    cols.p_xi_1 = [F::ZERO; D_EF];
                    cols.q_xi_0 = [F::ZERO; D_EF];
                    cols.q_xi_1 = [F::ZERO; D_EF];
                    cols.p_xi = [F::ZERO; D_EF];
                    cols.q_xi = [F::ZERO; D_EF];
                    cols.pow_lambda = lambda_prime_one;
                    cols.pow_lambda_prime = lambda_prime_one;
                    cols.acc_sum = [F::ZERO; D_EF];
                    cols.acc_p_cross = [F::ZERO; D_EF];
                    cols.acc_q_cross = [F::ZERO; D_EF];
                    cols.num_logup_count = F::ONE;
                    return;
                }

                let mut proof_row_idx = 0usize;
                let mut chunk_iter = chunk.chunks_mut(width);

                for layer_idx in 0..record.layer_count() {
                    let logup_rows = tower
                        .logup_layers
                        .get(layer_idx)
                        .map(|rows| rows.as_slice())
                        .unwrap_or(&[]);
                    let total_rows = record.logup_count_at(layer_idx).max(1);
                    debug_assert!(
                        total_rows == logup_rows.len().max(1),
                        "unexpected logup count mismatch at layer {layer_idx}"
                    );

                    let lambda = record.lambda_at(layer_idx);
                    let lambda_prime = record.lambda_prime_at(layer_idx);
                    let mu = mus_for_proof.get(layer_idx).copied().unwrap_or(EF::ZERO);
                    let lambda_basis: [F; D_EF] =
                        lambda.as_basis_coefficients_slice().try_into().unwrap();
                    let lambda_prime_basis: [F; D_EF] = lambda_prime
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    let mu_basis: [F; D_EF] = mu.as_basis_coefficients_slice().try_into().unwrap();
                    let tidx = record.claim_tidx(layer_idx);

                    let mut pow_lambda = EF::ONE;
                    let mut pow_lambda_prime = EF::ONE;
                    let mut acc_sum = EF::ZERO;
                    let mut acc_p_cross = EF::ZERO;
                    let mut acc_q_cross = EF::ZERO;

                    for row_in_layer in 0..total_rows {
                        let row = chunk_iter
                            .next()
                            .expect("chunk should have enough rows for layer");
                        let cols: &mut TowerLogupSumCheckClaimCols<F> = row.borrow_mut();
                        let is_real = row_in_layer < logup_rows.len();
                        let quad = if is_real {
                            logup_rows[row_in_layer]
                        } else {
                            [EF::ZERO; 4]
                        };
                        let p_vals = [quad[0], quad[1]];
                        let q_vals = [quad[2], quad[3]];
                        let p_xi_0 = p_vals[0];
                        let p_xi_1 = p_vals[1];
                        let q_xi_0 = q_vals[0];
                        let q_xi_1 = q_vals[1];
                        let p_xi = interpolate_pair(p_vals, mu);
                        let q_xi = interpolate_pair(q_vals, mu);
                        let combined = p_xi + lambda * q_xi;
                        let p_cross = p_xi_0 * q_xi_1 + p_xi_1 * q_xi_0;
                        let q_cross = q_xi_0 * q_xi_1;

                        let contribution = if is_real {
                            pow_lambda * combined
                        } else {
                            EF::ZERO
                        };
                        let p_cross_contribution = if is_real {
                            pow_lambda_prime * p_cross
                        } else {
                            EF::ZERO
                        };
                        let q_cross_contribution = if is_real {
                            pow_lambda_prime * lambda_prime * q_cross
                        } else {
                            EF::ZERO
                        };

                        cols.is_enabled = F::ONE;
                        cols.is_dummy = F::from_bool(!is_real);
                        cols.is_first_layer = F::from_bool(proof_row_idx == 0);
                        cols.is_first = F::from_bool(row_in_layer == 0);
                        cols.proof_idx = F::from_usize(record.proof_idx);
                        cols.idx = F::from_usize(record.idx);
                        cols.layer_idx = F::from_usize(layer_idx);
                        cols.index_id = F::from_usize(row_in_layer);
                        cols.tidx = F::from_usize(tidx);
                        cols.lambda = lambda_basis;
                        cols.lambda_prime = lambda_prime_basis;
                        cols.mu = mu_basis;
                        cols.p_xi_0 = p_xi_0.as_basis_coefficients_slice().try_into().unwrap();
                        cols.p_xi_1 = p_xi_1.as_basis_coefficients_slice().try_into().unwrap();
                        cols.q_xi_0 = q_xi_0.as_basis_coefficients_slice().try_into().unwrap();
                        cols.q_xi_1 = q_xi_1.as_basis_coefficients_slice().try_into().unwrap();
                        cols.p_xi = p_xi.as_basis_coefficients_slice().try_into().unwrap();
                        cols.q_xi = q_xi.as_basis_coefficients_slice().try_into().unwrap();
                        cols.pow_lambda =
                            pow_lambda.as_basis_coefficients_slice().try_into().unwrap();
                        cols.pow_lambda_prime = pow_lambda_prime
                            .as_basis_coefficients_slice()
                            .try_into()
                            .unwrap();
                        cols.acc_sum = acc_sum.as_basis_coefficients_slice().try_into().unwrap();
                        cols.acc_p_cross = acc_p_cross
                            .as_basis_coefficients_slice()
                            .try_into()
                            .unwrap();
                        cols.acc_q_cross = acc_q_cross
                            .as_basis_coefficients_slice()
                            .try_into()
                            .unwrap();
                        cols.num_logup_count = F::from_usize(total_rows);

                        acc_sum += contribution;
                        acc_p_cross += p_cross_contribution;
                        acc_q_cross += q_cross_contribution;
                        pow_lambda *= lambda;
                        pow_lambda_prime *= lambda_prime;

                        proof_row_idx += 1;
                    }
                }
            });

        Some(RowMajorMatrix::new(trace, width))
    }
}
