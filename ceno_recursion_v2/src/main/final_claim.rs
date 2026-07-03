use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::utils::ext_field_add;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{system::MainFinalClaimRecord, tracegen::RowMajorChip};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainFinalClaimCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub is_first_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub contribution: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
    pub expected: [T; D_EF],
}

pub struct MainFinalClaimAir;

impl<F: Field> BaseAir<F> for MainFinalClaimAir {
    fn width(&self) -> usize {
        MainFinalClaimCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainFinalClaimAir {}
impl<F: Field> PartitionedBaseAir<F> for MainFinalClaimAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainFinalClaimAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &MainFinalClaimCols<AB::Var> = (*local_row).borrow();
        let next: &MainFinalClaimCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder
            .when_transition()
            .when_ne(local.is_enabled, AB::Expr::ONE)
            .assert_zero(next.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_first_idx);
        builder.assert_bool(local.is_last);

        let computed_is_last = local.is_enabled - next.is_enabled + next.is_first;
        builder
            .when(local.is_enabled)
            .assert_eq(local.is_last, computed_is_last);

        let acc_out = ext_field_add(local.acc_in, local.contribution);
        assert_array_eq(&mut builder.when(local.is_enabled), local.acc_out, acc_out);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            [AB::Expr::ZERO; D_EF],
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.acc_out,
            local.expected,
        );

        let is_transition = next.is_enabled - next.is_first;
        assert_array_eq(&mut builder.when(is_transition), local.acc_out, next.acc_in);
    }
}

pub struct MainFinalClaimTraceGenerator;

impl RowMajorChip<F> for MainFinalClaimTraceGenerator {
    type Ctx<'a> = &'a [MainFinalClaimRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainFinalClaimCols::<F>::width();
        let num_valid_rows = records.len().max(1);
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

        let mut prev_proof_idx = usize::MAX;
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainFinalClaimCols<F> = row.borrow_mut();
            let is_first_idx = prev_proof_idx != record.proof_idx;
            let is_last = records
                .get(row_idx + 1)
                .is_none_or(|next| next.proof_idx != record.proof_idx);

            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.is_first_idx = F::from_bool(is_first_idx);
            cols.is_first = F::from_bool(is_first_idx);
            cols.is_last = F::from_bool(is_last);
            cols.contribution = record
                .contribution
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.acc_in = record
                .acc_in
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.acc_out = record
                .acc_out
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.expected = record
                .expected
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();

            prev_proof_idx = record.proof_idx;
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
