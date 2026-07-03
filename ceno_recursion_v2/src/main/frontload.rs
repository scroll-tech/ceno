use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::utils::{ext_field_add, ext_field_multiply};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        MainContributionBus, MainContributionMessage, MainEvalBus, MainEvalMessage,
        MainGlobalPointBus, MainGlobalPointMessage,
    },
    system::MainFrontloadTermRecord,
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainFrontloadTermCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub term_idx: T,
    pub step_idx: T,
    pub is_first_step: T,
    pub is_last_step: T,
    pub is_last_chip_step: T,
    pub eval_idx: T,
    pub has_eval_factor: T,
    pub global_round_idx: T,
    pub has_global_factor: T,
    pub factor: [T; D_EF],
    pub term_acc_in: [T; D_EF],
    pub term_acc_out: [T; D_EF],
    pub chip_acc_in: [T; D_EF],
    pub chip_acc_out: [T; D_EF],
}

pub struct MainFrontloadTermAir {
    pub eval_bus: MainEvalBus,
    pub global_point_bus: MainGlobalPointBus,
    pub contribution_bus: MainContributionBus,
}

impl<F: Field> BaseAir<F> for MainFrontloadTermAir {
    fn width(&self) -> usize {
        MainFrontloadTermCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainFrontloadTermAir {}
impl<F: Field> PartitionedBaseAir<F> for MainFrontloadTermAir {}

impl<AB> Air<AB> for MainFrontloadTermAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &MainFrontloadTermCols<AB::Var> = (*local_row).borrow();
        let next: &MainFrontloadTermCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first_step);
        builder.assert_bool(local.is_last_step);
        builder.assert_bool(local.is_last_chip_step);
        builder.assert_bool(local.has_eval_factor);
        builder.assert_bool(local.has_global_factor);
        builder
            .when_transition()
            .when_ne(local.is_enabled, AB::Expr::ONE)
            .assert_zero(next.is_enabled);

        let term_acc_out = ext_field_multiply(local.term_acc_in, local.factor);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.term_acc_out,
            term_acc_out,
        );

        let chip_acc_with_term = ext_field_add(local.chip_acc_in, local.term_acc_out);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last_step),
            local.chip_acc_out,
            chip_acc_with_term,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * (AB::Expr::ONE - local.is_last_step)),
            local.chip_acc_out,
            local.chip_acc_in.map(Into::into),
        );

        let continues_same_term = next.is_enabled
            * (AB::Expr::ONE - next.is_first_step)
            * (AB::Expr::ONE - local.is_last_step);
        assert_array_eq(
            &mut builder.when(continues_same_term),
            local.term_acc_out,
            next.term_acc_in,
        );

        let continues_same_chip = next.is_enabled * (AB::Expr::ONE - next.is_last_chip_step);
        let _ = continues_same_chip;
        let next_same_chip = next.is_enabled * (AB::Expr::ONE - local.is_last_chip_step);
        assert_array_eq(
            &mut builder.when(next_same_chip),
            local.chip_acc_out,
            next.chip_acc_in,
        );

        self.eval_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEvalMessage {
                idx: local.idx.into(),
                eval_idx: local.eval_idx.into(),
                value: local.factor.map(Into::into),
            },
            local.is_enabled * local.has_eval_factor,
        );
        self.global_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainGlobalPointMessage {
                round_idx: local.global_round_idx.into(),
                value: local.factor.map(Into::into),
            },
            local.is_enabled * local.has_global_factor,
        );
        self.contribution_bus.send(
            builder,
            local.proof_idx,
            MainContributionMessage {
                idx: local.idx.into(),
                contribution: local.chip_acc_out.map(Into::into),
            },
            local.is_enabled * local.is_last_chip_step,
        );
    }
}

pub struct MainFrontloadTermTraceGenerator;

impl RowMajorChip<F> for MainFrontloadTermTraceGenerator {
    type Ctx<'a> = &'a [MainFrontloadTermRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainFrontloadTermCols::<F>::width();
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
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainFrontloadTermCols<F> = row.borrow_mut();
            let is_last_chip_step = records
                .get(row_idx + 1)
                .is_none_or(|next| next.proof_idx != record.proof_idx || next.idx != record.idx);

            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.step_idx = F::from_usize(record.step_idx);
            cols.is_first_step = F::from_bool(record.is_first_step);
            cols.is_last_step = F::from_bool(record.is_last_step);
            cols.is_last_chip_step = F::from_bool(is_last_chip_step);
            cols.eval_idx = F::from_usize(record.eval_idx);
            cols.has_eval_factor = F::from_bool(record.has_eval_factor);
            cols.global_round_idx = F::from_usize(record.global_round_idx);
            cols.has_global_factor = F::from_bool(record.has_global_factor);
            cols.factor = record
                .factor
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.term_acc_in = record
                .term_acc_in
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.term_acc_out = record
                .term_acc_out
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.chip_acc_in = record
                .chip_acc_in
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.chip_acc_out = record
                .chip_acc_out
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}
