use core::borrow::BorrowMut;

use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::air::MainCols;
use crate::tracegen::RowMajorChip;

#[derive(Clone, Debug, Default)]
pub struct MainRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub is_dummy: bool,
    pub tidx: usize,
    pub claim: EF,
}

pub struct MainTraceGenerator;

impl RowMajorChip<F> for MainTraceGenerator {
    type Ctx<'a> = &'a [MainRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        generate_trace::<MainCols<F>, _>(records, required_height, fill_main_cols)
    }
}

fn generate_trace<C, Fill>(
    records: &[MainRecord],
    required_height: Option<usize>,
    mut fill: Fill,
) -> Option<RowMajorMatrix<F>>
where
    C: ColumnAccess<F>,
    Fill: FnMut(&MainRecord, &mut C, bool),
{
    let width = C::width();
    let num_rows = records.len().max(1);
    let height = if let Some(height) = required_height {
        if height < num_rows {
            return None;
        }
        height
    } else {
        num_rows.next_power_of_two().max(1)
    };
    let mut trace = vec![F::ZERO; height * width];
    if records.is_empty() {
        return Some(RowMajorMatrix::new(trace, width));
    }

    let mut prev_proof_idx = usize::MAX;
    for (row_idx, record) in records.iter().enumerate() {
        let offset = row_idx * width;
        let cols_slice = &mut trace[offset..offset + width];
        let cols = C::from_bytes(cols_slice);
        fill(record, cols, prev_proof_idx != record.proof_idx);
        prev_proof_idx = record.proof_idx;
    }

    Some(RowMajorMatrix::new(trace, width))
}

trait ColumnAccess<F>: Sized {
    fn width() -> usize;
    fn from_bytes(slice: &mut [F]) -> &mut Self;
}

impl ColumnAccess<F> for MainCols<F> {
    fn width() -> usize {
        MainCols::<F>::width()
    }

    fn from_bytes(slice: &mut [F]) -> &mut Self {
        slice.borrow_mut()
    }
}

fn fill_main_cols(record: &MainRecord, cols: &mut MainCols<F>, is_first_proof: bool) {
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.is_first_idx = F::from_bool(is_first_proof);
    cols.is_first = F::ONE;
    cols.is_dummy = F::from_bool(record.is_dummy);
    cols.tidx = F::from_usize(record.tidx);
    let claim_basis: [F; D_EF] = record
        .claim
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
    cols.claim_in = claim_basis;
    cols.claim_out = claim_basis;
}
