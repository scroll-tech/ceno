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
    pub chip_id: usize,
    pub tidx: usize,
    pub final_tidx: usize,
    pub num_layers: usize,
    pub num_read_specs: usize,
    pub num_write_specs: usize,
    pub num_logup_specs: usize,
    pub r0_claim: EF,
    pub w0_claim: EF,
    pub p0_claim: EF,
    pub q0_claim: EF,
    pub alpha_logup: EF,
    pub r_1: EF,
    pub read_initial_claim: EF,
    pub write_initial_claim: EF,
    pub logup_initial_claim: EF,
    pub initial_tower_claim: EF,
    pub write_lambda_1_start: EF,
    pub logup_lambda_1_start: EF,
    pub input_layer_claim: EF,
    pub layer_output_lambda: EF,
    pub layer_output_mu: EF,
}

pub struct TowerInputTraceGenerator;

impl RowMajorChip<F> for TowerInputTraceGenerator {
    type Ctx<'a> = &'a [TowerInputRecord];

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let gkr_input_records = *ctx;

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

        for (row_data, record) in data_slice
            .chunks_exact_mut(width)
            .zip(gkr_input_records.iter())
        {
            let cols: &mut TowerInputCols<F> = row_data.borrow_mut();

            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.chip_id = F::from_usize(record.chip_id);

            cols.tidx = F::from_usize(record.tidx);
            cols.final_tidx = F::from_usize(record.final_tidx);

            cols.num_layers = F::from_usize(record.num_layers);
            cols.num_read_specs = F::from_usize(record.num_read_specs);
            cols.num_write_specs = F::from_usize(record.num_write_specs);
            cols.num_logup_specs = F::from_usize(record.num_logup_specs);
            IsZeroSubAir.generate_subrow(
                cols.num_layers,
                (
                    &mut cols.is_num_layers_zero_aux.inv,
                    &mut cols.is_num_layers_zero,
                ),
            );

            cols.r0_claim = record
                .r0_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.w0_claim = record
                .w0_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.p0_claim = record
                .p0_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.q0_claim = record
                .q0_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.alpha_logup = record
                .alpha_logup
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.r_1 = record.r_1.as_basis_coefficients_slice().try_into().unwrap();
            cols.read_initial_claim = record
                .read_initial_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.write_initial_claim = record
                .write_initial_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.logup_initial_claim = record
                .logup_initial_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.initial_tower_claim = record
                .initial_tower_claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.write_lambda_1_start = record
                .write_lambda_1_start
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.logup_lambda_1_start = record
                .logup_lambda_1_start
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
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
