use core::borrow::BorrowMut;

use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::air::MainCols;
use crate::tracegen::RowMajorChip;

#[derive(Clone, Debug, Default)]
pub struct MainRecord {
    pub is_present: bool,
    pub proof_idx: usize,
    pub idx: usize,
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
    Fill: FnMut(&MainRecord, &mut C, bool, bool),
{
    let width = C::width();
    let dense_records = dense_main_records(records);
    let num_rows = dense_records.len().max(1);
    let height = if let Some(height) = required_height {
        if height < num_rows {
            return None;
        }
        height
    } else {
        num_rows.next_power_of_two().max(1)
    };
    let mut trace = vec![F::ZERO; height * width];

    let mut prev_proof_idx = usize::MAX;
    let mut prev_idx = usize::MAX;
    for (row_idx, record) in dense_records.iter().enumerate() {
        let offset = row_idx * width;
        let cols_slice = &mut trace[offset..offset + width];
        let cols = C::from_bytes(cols_slice);
        let is_new_proof_idx = prev_proof_idx != record.proof_idx;
        let is_new_idx = is_new_proof_idx || prev_idx != record.idx;
        fill(record, cols, is_new_proof_idx, is_new_idx);
        prev_proof_idx = record.proof_idx;
        prev_idx = record.idx;
    }

    Some(RowMajorMatrix::new(trace, width))
}

fn dense_main_records(records: &[MainRecord]) -> Vec<MainRecord> {
    if records.is_empty() {
        return vec![MainRecord::default()];
    }

    let mut dense = Vec::new();
    let mut record_idx = 0;
    while record_idx < records.len() {
        let proof_idx = records[record_idx].proof_idx;
        let proof_start = record_idx;
        while record_idx < records.len() && records[record_idx].proof_idx == proof_idx {
            record_idx += 1;
        }
        let proof_records = &records[proof_start..record_idx];
        let max_idx = proof_records.last().map(|record| record.idx).unwrap_or(0);
        let mut proof_record_idx = 0;
        for idx in 0..=max_idx {
            if proof_record_idx < proof_records.len() && proof_records[proof_record_idx].idx == idx
            {
                dense.push(proof_records[proof_record_idx].clone());
                proof_record_idx += 1;
            } else {
                dense.push(MainRecord {
                    proof_idx,
                    idx,
                    ..Default::default()
                });
            }
        }
    }
    dense
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

fn fill_main_cols(record: &MainRecord, cols: &mut MainCols<F>, is_first_idx: bool, is_first: bool) {
    cols.is_enabled = F::ONE;
    cols.is_present = F::from_bool(record.is_present);
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.is_first_idx = F::from_bool(is_first_idx);
    cols.is_first = F::from_bool(is_first);
    cols.tidx = F::from_usize(record.tidx);
    let claim_basis: [F; D_EF] = record
        .claim
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
    cols.claim_in = claim_basis;
    cols.claim_out = claim_basis;
}
