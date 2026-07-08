use core::borrow::BorrowMut;

use super::TowerInputCols;
use crate::tracegen::RowMajorChip;
use openvm_circuit_primitives::{TraceSubRowGenerator, is_zero::IsZeroSubAir};
use openvm_stark_sdk::config::baby_bear_poseidon2::{EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

#[derive(Debug, Clone, Default)]
pub struct TowerInputRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub fork_id: usize,
    pub tidx: usize,
    pub fork_final_sample_tidx: usize,
    pub n_logup: usize,
    pub alpha_logup: EF,
    pub beta: EF,
    pub read_out_evals: [EF; 2],
    pub write_out_evals: [EF; 2],
    pub logup_out_evals: [EF; 4],
    pub has_read_out: bool,
    pub has_write_out: bool,
    pub has_logup_out: bool,
    pub has_read: bool,
    pub has_write: bool,
    pub has_logup: bool,
    pub read_tower_vars: usize,
    pub write_tower_vars: usize,
    pub logup_tower_vars: usize,
    pub max_layer_count: usize,
    pub input_layer_claim: EF,
    pub layer_output_lambda: EF,
    pub layer_output_mu: EF,
}

pub struct TowerInputTraceGenerator;

impl RowMajorChip<F> for TowerInputTraceGenerator {
    // (gkr_input_records, q0_claims)
    type Ctx<'a> = (&'a [TowerInputRecord], &'a [EF]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (gkr_input_records, q0_claims) = ctx;
        debug_assert_eq!(gkr_input_records.len(), q0_claims.len());

        let width = TowerInputCols::<F>::width();

        // Each record generates exactly 1 row
        let num_valid_rows = gkr_input_records.len();
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

        let mut prev_proof_idx = usize::MAX;
        let mut prev_idx = usize::MAX;
        for (row_data, (record, q0_claim)) in data_slice
            .chunks_exact_mut(width)
            .zip(gkr_input_records.iter().zip(q0_claims.iter()))
        {
            let cols: &mut TowerInputCols<F> = row_data.borrow_mut();
            let is_new_proof_idx = prev_proof_idx != record.proof_idx;
            let is_new_idx = is_new_proof_idx || prev_idx != record.idx;

            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.is_first_idx = F::from_bool(is_new_proof_idx);
            cols.is_first = F::from_bool(is_new_idx);
            cols.fork_id = F::from_usize(record.fork_id);

            cols.tidx = F::from_usize(record.tidx);
            cols.fork_final_sample_tidx = F::from_usize(record.fork_final_sample_tidx);

            cols.n_logup = F::from_usize(record.n_logup);
            IsZeroSubAir.generate_subrow(
                cols.n_logup,
                (&mut cols.is_n_logup_zero_aux.inv, &mut cols.is_n_logup_zero),
            );
            let tower_transcript_count = usize::from(record.has_read_out)
                + usize::from(record.has_write_out)
                + usize::from(record.has_logup_out)
                + usize::from(record.n_logup != 0);
            IsZeroSubAir.generate_subrow(
                F::from_usize(tower_transcript_count),
                (
                    &mut cols.is_tower_transcript_zero_aux.inv,
                    &mut cols.is_tower_transcript_zero,
                ),
            );

            let q0_basis = q0_claim.as_basis_coefficients_slice();
            cols.r0_claim.copy_from_slice(q0_basis);
            cols.w0_claim.copy_from_slice(q0_basis);
            cols.q0_claim.copy_from_slice(q0_basis);
            cols.read_out_0
                .copy_from_slice(record.read_out_evals[0].as_basis_coefficients_slice());
            cols.read_out_1
                .copy_from_slice(record.read_out_evals[1].as_basis_coefficients_slice());
            cols.write_out_0
                .copy_from_slice(record.write_out_evals[0].as_basis_coefficients_slice());
            cols.write_out_1
                .copy_from_slice(record.write_out_evals[1].as_basis_coefficients_slice());
            cols.logup_out_0
                .copy_from_slice(record.logup_out_evals[0].as_basis_coefficients_slice());
            cols.logup_out_1
                .copy_from_slice(record.logup_out_evals[1].as_basis_coefficients_slice());
            cols.logup_out_2
                .copy_from_slice(record.logup_out_evals[2].as_basis_coefficients_slice());
            cols.logup_out_3
                .copy_from_slice(record.logup_out_evals[3].as_basis_coefficients_slice());
            cols.has_read_out = F::from_bool(record.has_read_out);
            cols.has_write_out = F::from_bool(record.has_write_out);
            cols.has_logup_out = F::from_bool(record.has_logup_out);
            cols.has_read = F::from_bool(record.has_read);
            cols.has_write = F::from_bool(record.has_write);
            cols.has_logup = F::from_bool(record.has_logup);
            cols.read_tower_vars = F::from_usize(record.read_tower_vars);
            cols.write_tower_vars = F::from_usize(record.write_tower_vars);
            cols.logup_tower_vars = F::from_usize(record.logup_tower_vars);
            cols.max_layer_count = F::from_usize(record.max_layer_count);
            cols.alpha_logup = record
                .alpha_logup
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.beta = record
                .beta
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.input_layer_claim = record
                .input_layer_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.layer_output_lambda = record
                .layer_output_lambda
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.layer_output_mu = record
                .layer_output_mu
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            prev_proof_idx = record.proof_idx;
            prev_idx = record.idx;
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
