use core::borrow::BorrowMut;

use openvm_stark_backend::p3_maybe_rayon::prelude::*;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::TowerProdSumCheckClaimCols;
use crate::{
    tower::{TowerTowerEvalRecord, interpolate_pair, layer::trace::TowerLayerRecord},
    tracegen::RowMajorChip,
};

pub struct TowerProdReadSumCheckClaimTraceGenerator;
pub struct TowerProdWriteSumCheckClaimTraceGenerator;

type ProdTraceCtx<'a> = (
    &'a [TowerLayerRecord],
    &'a [TowerTowerEvalRecord],
    &'a [Vec<EF>],
);

fn prod_rows_for_record(record: &TowerLayerRecord, is_write: bool) -> usize {
    if record.layer_count() == 0 {
        1
    } else {
        (0..record.layer_count())
            .map(|layer_idx| {
                if is_write {
                    record.write_count_at(layer_idx).max(1)
                } else {
                    record.read_count_at(layer_idx).max(1)
                }
            })
            .sum()
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_prod_trace(
    records: &[TowerLayerRecord],
    towers: &[TowerTowerEvalRecord],
    mus_records: &[Vec<EF>],
    is_write: bool,
    required_height: Option<usize>,
) -> Option<RowMajorMatrix<F>> {
    let width = TowerProdSumCheckClaimCols::<F>::width();
    let rows_per_proof: Vec<usize> = records
        .iter()
        .map(|record| prod_rows_for_record(record, is_write))
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
                let cols: &mut TowerProdSumCheckClaimCols<F> = row_data.borrow_mut();
                cols.is_enabled = F::ONE;
                cols.is_first_layer = F::from_bool(record.is_first_air_idx);
                cols.is_first = F::ONE; // single row = first of its (degenerate) layer
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
                cols.p_xi = [F::ZERO; D_EF];
                cols.pow_lambda = lambda_prime_one;
                cols.pow_lambda_prime = lambda_prime_one;
                cols.acc_sum = [F::ZERO; D_EF];
                cols.acc_sum_prime = [F::ZERO; D_EF];
                cols.num_prod_count = F::ONE;
                return;
            }

            let mut proof_row_idx = 0usize;
            let mut chunk_iter = chunk.chunks_mut(width);

            for layer_idx in 0..record.layer_count() {
                let active_rows = if is_write {
                    tower
                        .write_layers
                        .get(layer_idx)
                        .map(|rows| rows.as_slice())
                        .unwrap_or(&[])
                } else {
                    tower
                        .read_layers
                        .get(layer_idx)
                        .map(|rows| rows.as_slice())
                        .unwrap_or(&[])
                };
                let total_rows = if is_write {
                    record.write_count_at(layer_idx).max(1)
                } else {
                    record.read_count_at(layer_idx).max(1)
                };
                debug_assert!(
                    total_rows == active_rows.len().max(1),
                    "unexpected prod count mismatch at layer {layer_idx}"
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
                    let layer_tidx = record.claim_tidx(layer_idx);

                let mut pow_lambda = EF::ONE;
                let mut pow_lambda_prime = EF::ONE;
                let mut acc_sum = EF::ZERO;
                let mut acc_sum_prime = EF::ZERO;

                for row_in_layer in 0..total_rows {
                    let row = chunk_iter
                        .next()
                        .expect("chunk should have enough rows for layer");
                    let cols: &mut TowerProdSumCheckClaimCols<F> = row.borrow_mut();
                    let is_placeholder = active_rows.is_empty() && row_in_layer == 0;
                    let is_real = row_in_layer < active_rows.len() || is_placeholder;
                    let pair = if row_in_layer < active_rows.len() {
                        active_rows[row_in_layer]
                    } else {
                        [EF::ZERO; 2]
                    };
                    let p_xi_0 = pair[0];
                    let p_xi_1 = pair[1];
                    let p_xi = interpolate_pair(pair, mu);
                    let prime_product = p_xi_0 * p_xi_1;
                    let contribution = if is_real { pow_lambda * p_xi } else { EF::ZERO };
                    let prime_contribution = if is_real {
                        pow_lambda_prime * prime_product
                    } else {
                        EF::ZERO
                    };

                    cols.is_enabled = F::ONE;
                    cols.is_dummy = F::from_bool(layer_idx == 0 || !is_real);
                    let is_first_row_of_layer = row_in_layer == 0;
                    let is_first_row_of_record = proof_row_idx == 0;
                    cols.is_first_layer =
                        F::from_bool(is_first_row_of_record && record.is_first_air_idx);
                    cols.is_first = F::from_bool(is_first_row_of_layer);
                    cols.proof_idx = F::from_usize(record.proof_idx);
                    cols.idx = F::from_usize(record.idx);
                    cols.layer_idx = F::from_usize(layer_idx);
                    cols.index_id = F::from_usize(row_in_layer);
                    cols.tidx = F::from_usize(layer_tidx + row_in_layer * 2 * D_EF);
                    cols.lambda = lambda_basis;
                    cols.lambda_prime = lambda_prime_basis;
                    cols.mu = mu_basis;
                    cols.p_xi_0 = p_xi_0.as_basis_coefficients_slice().try_into().unwrap();
                    cols.p_xi_1 = p_xi_1.as_basis_coefficients_slice().try_into().unwrap();
                    cols.p_xi = p_xi.as_basis_coefficients_slice().try_into().unwrap();
                    cols.pow_lambda = pow_lambda.as_basis_coefficients_slice().try_into().unwrap();
                    cols.pow_lambda_prime = pow_lambda_prime
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.acc_sum = acc_sum.as_basis_coefficients_slice().try_into().unwrap();
                    cols.acc_sum_prime = acc_sum_prime
                        .as_basis_coefficients_slice()
                        .try_into()
                        .unwrap();
                    cols.num_prod_count = F::from_usize(total_rows);

                    acc_sum += contribution;
                    acc_sum_prime += prime_contribution;
                    pow_lambda *= lambda;
                    pow_lambda_prime *= lambda_prime;

                    proof_row_idx += 1;
                }
            }
        });

    Some(RowMajorMatrix::new(trace, width))
}

impl RowMajorChip<F> for TowerProdReadSumCheckClaimTraceGenerator {
    type Ctx<'a> = ProdTraceCtx<'a>;

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (records, towers, mus_records) = ctx;
        generate_prod_trace(records, towers, mus_records, false, required_height)
    }
}

impl RowMajorChip<F> for TowerProdWriteSumCheckClaimTraceGenerator {
    type Ctx<'a> = ProdTraceCtx<'a>;

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (records, towers, mus_records) = ctx;
        generate_prod_trace(records, towers, mus_records, true, required_height)
    }
}
