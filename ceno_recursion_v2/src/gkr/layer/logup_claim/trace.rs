use core::borrow::BorrowMut;

use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::GkrLogupSumCheckClaimCols;
use crate::{gkr::layer::trace::GkrLayerRecord, tracegen::RowMajorChip};

pub struct GkrLogupSumCheckClaimTraceGenerator;

impl RowMajorChip<F> for GkrLogupSumCheckClaimTraceGenerator {
    type Ctx<'a> = (&'a [GkrLayerRecord], &'a [Vec<EF>]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (records, mus_records) = ctx;
        debug_assert_eq!(records.len(), mus_records.len());

        let width = GkrLogupSumCheckClaimCols::<F>::width();
        let rows_per_proof: Vec<usize> = records
            .iter()
            .map(|record| record.layer_claims.len().max(1))
            .collect();
        let num_valid_rows: usize = rows_per_proof.iter().sum();
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        let (data_slice, _) = trace.split_at_mut(num_valid_rows * width);
        let mut trace_slices: Vec<&mut [F]> = Vec::with_capacity(rows_per_proof.len());
        let mut remaining = data_slice;
        for &rows in &rows_per_proof {
            let chunk_size = rows * width;
            let (chunk, rest) = remaining.split_at_mut(chunk_size);
            trace_slices.push(chunk);
            remaining = rest;
        }

        trace_slices
            .iter_mut()
            .zip(records.iter().zip(mus_records.iter()))
            .enumerate()
            .for_each(|(proof_idx, (chunk, (record, mus_values)))| {
                if record.layer_claims.is_empty() {
                    debug_assert_eq!(chunk.len(), width);
                    let row = &mut chunk[..width];
                    let cols: &mut GkrLogupSumCheckClaimCols<F> = row.borrow_mut();
                    cols.is_enabled = F::ONE;
                    cols.is_dummy = F::ONE;
                    cols.is_first = F::ONE;
                    cols.is_first_air_idx = F::ONE;
                    cols.is_first_layer = F::ONE;
                    cols.proof_idx = F::from_usize(proof_idx);
                    cols.idx = F::ZERO;
                    cols.layer_idx = F::ZERO;
                    cols.index_id = F::ZERO;
                    cols.tidx = F::ZERO;
                    cols.lambda = [F::ZERO; D_EF];
                    cols.mu = [F::ZERO; D_EF];
                    cols.p_xi_0 = [F::ZERO; D_EF];
                    cols.p_xi_1 = [F::ZERO; D_EF];
                    cols.q_xi_0 = [F::ZERO; D_EF];
                    cols.q_xi_1 = [F::ZERO; D_EF];
                    cols.p_xi = [F::ZERO; D_EF];
                    cols.q_xi = [F::ZERO; D_EF];
                    cols.pow_lambda = {
                        let mut arr = [F::ZERO; D_EF];
                        arr[0] = F::ONE;
                        arr
                    };
                    cols.acc_sum = [F::ZERO; D_EF];
                    cols.num_logup_count = F::ZERO;
                    return;
                }

                let mut pow_lambda = EF::ONE;
                let mut acc_sum = EF::ZERO;
                let mus_for_proof = mus_values.as_slice();

                chunk
                    .chunks_mut(width)
                    .take(record.layer_count())
                    .enumerate()
                    .for_each(|(layer_idx, row)| {
                        let cols: &mut GkrLogupSumCheckClaimCols<F> = row.borrow_mut();
                        let num_logup = record.logup_count_at(layer_idx);
                        cols.is_enabled = F::ONE;
                        cols.is_dummy = F::ZERO;
                        cols.proof_idx = F::from_usize(proof_idx);
                        cols.idx = F::ZERO;
                        cols.is_first_air_idx = F::from_bool(layer_idx == 0);
                        cols.is_first_layer = F::ONE;
                        cols.is_first = F::from_bool(layer_idx == 0);
                        cols.layer_idx = F::from_usize(layer_idx);
                        cols.index_id = F::ZERO;
                        cols.tidx = F::from_usize(record.layer_tidx(layer_idx));

                        let lambda_next = record.lambda_at(layer_idx + 1);
                        cols.lambda = lambda_next
                            .as_basis_coefficients_slice()
                            .try_into()
                            .unwrap();

                        let mu = mus_for_proof[layer_idx];
                        cols.mu = mu.as_basis_coefficients_slice().try_into().unwrap();

                        let claims = record.layer_claims[layer_idx];
                        cols.p_xi_0 = claims[0].as_basis_coefficients_slice().try_into().unwrap();
                        cols.q_xi_0 = claims[1].as_basis_coefficients_slice().try_into().unwrap();
                        cols.p_xi_1 = claims[2].as_basis_coefficients_slice().try_into().unwrap();
                        cols.q_xi_1 = claims[3].as_basis_coefficients_slice().try_into().unwrap();

                        let mu_one_minus = EF::ONE - mu;
                        let p_xi = claims[0] * mu_one_minus + claims[2] * mu;
                        let q_xi = claims[1] * mu_one_minus + claims[3] * mu;
                        cols.p_xi = p_xi.as_basis_coefficients_slice().try_into().unwrap();
                        cols.q_xi = q_xi.as_basis_coefficients_slice().try_into().unwrap();

                        cols.pow_lambda =
                            pow_lambda.as_basis_coefficients_slice().try_into().unwrap();
                        cols.acc_sum = acc_sum.as_basis_coefficients_slice().try_into().unwrap();
                        cols.num_logup_count = F::from_usize(num_logup);

                        let acc_sum_with_cur = acc_sum + lambda_next * q_xi * pow_lambda;
                        acc_sum = acc_sum_with_cur;
                        pow_lambda *= lambda_next;
                    });
            });

        Some(RowMajorMatrix::new(trace, width))
    }
}
