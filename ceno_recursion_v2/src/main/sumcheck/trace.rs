use core::{borrow::BorrowMut, convert::TryInto};

use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::air::MainSumcheckCols;
use crate::tracegen::RowMajorChip;

#[derive(Default, Debug, Clone)]
pub struct MainSumcheckRoundRecord {
    pub evaluations: [EF; 3],
}

#[derive(Default, Debug, Clone)]
pub struct MainSumcheckRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub tidx: usize,
    pub claim: EF,
    pub rounds: Vec<MainSumcheckRoundRecord>,
}

impl MainSumcheckRecord {
    fn total_rows(&self) -> usize {
        self.rounds.len().max(1)
    }
}

pub struct MainSumcheckTraceGenerator;

impl RowMajorChip<F> for MainSumcheckTraceGenerator {
    type Ctx<'a> = &'a [MainSumcheckRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainSumcheckCols::<F>::width();
        let num_valid_rows: usize = records.iter().map(MainSumcheckRecord::total_rows).sum();
        let num_valid_rows = num_valid_rows.max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        if records.is_empty() {
            return Some(RowMajorMatrix::new(trace, width));
        }

        let zero_challenge: [F; D_EF] = EF::ZERO.as_basis_coefficients_slice().try_into().unwrap();
        let mut row_offset = 0;
        let mut prev_proof_idx = usize::MAX;

        for record in records.iter() {
            let rows = record.total_rows();
            let has_rounds = !record.rounds.is_empty();
            let claim_value = record.claim;
            let eq_value = EF::ONE;
            let is_first_record_of_proof = prev_proof_idx != record.proof_idx;

            for round_idx in 0..rows {
                let offset = row_offset * width;
                let cols_slice = &mut trace[offset..offset + width];
                let cols: &mut MainSumcheckCols<F> = cols_slice.borrow_mut();

                let is_first_round = round_idx == 0;
                let is_last_round = round_idx + 1 == rows;
                cols.is_enabled = F::ONE;
                cols.proof_idx = F::from_usize(record.proof_idx);
                cols.idx = F::from_usize(record.idx);
                cols.is_first_idx = F::from_bool(is_first_record_of_proof && is_first_round);
                cols.is_first_round = F::from_bool(is_first_round);
                cols.is_last_round = F::from_bool(is_last_round);
                cols.is_dummy = F::from_bool(!has_rounds);
                cols.round = F::from_usize(round_idx);
                cols.tidx = F::from_usize(record.tidx + 4 * D_EF * round_idx);

                let evals = record
                    .rounds
                    .get(round_idx)
                    .map(|round| round.evaluations)
                    .unwrap_or([EF::ZERO; 3]);
                cols.ev1 = evals[0].as_basis_coefficients_slice().try_into().unwrap();
                cols.ev2 = evals[1].as_basis_coefficients_slice().try_into().unwrap();
                cols.ev3 = evals[2].as_basis_coefficients_slice().try_into().unwrap();

                let claim_in_basis: [F; D_EF] = claim_value
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap();
                cols.claim_in = claim_in_basis;
                cols.claim_out = claim_in_basis;

                let eq_basis: [F; D_EF] =
                    eq_value.as_basis_coefficients_slice().try_into().unwrap();
                cols.eq_in = eq_basis;
                cols.eq_out = eq_basis;

                cols.prev_challenge = zero_challenge;
                cols.challenge = zero_challenge;

                row_offset += 1;
            }

            prev_proof_idx = record.proof_idx;
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
