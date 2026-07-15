use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::utils::{
    ext_field_add, ext_field_multiply, ext_field_multiply_scalar, ext_field_subtract,
    scalar_subtract_ext_field,
};
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
    pub row_idx: T,
    pub node_idx: T,
    pub eval_idx: T,
    pub has_eval_factor: T,
    pub instance_idx: T,
    pub challenge_idx: T,
    pub global_round_idx: T,
    pub has_global_factor: T,
    pub is_wit: T,
    pub is_const: T,
    pub is_instance: T,
    pub is_challenge: T,
    pub is_add: T,
    pub is_sub: T,
    pub is_neg: T,
    pub is_mul: T,
    pub is_fold: T,
    pub is_tail: T,
    pub constraint_idx: T,
    pub alpha: [T; D_EF],
    pub arg0: [T; D_EF],
    pub arg1: [T; D_EF],
    pub value: [T; D_EF],
    pub chip_acc_in: [T; D_EF],
    pub chip_acc_out: [T; D_EF],
    pub is_last_chip_step: T,
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
        builder.assert_bool(local.has_eval_factor);
        builder.assert_bool(local.has_global_factor);
        builder.assert_bool(local.is_wit);
        builder.assert_bool(local.is_const);
        builder.assert_bool(local.is_instance);
        builder.assert_bool(local.is_challenge);
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(local.is_neg);
        builder.assert_bool(local.is_mul);
        builder.assert_bool(local.is_fold);
        builder.assert_bool(local.is_tail);
        builder.assert_bool(local.is_last_chip_step);
        builder
            .when_transition()
            .when_ne(local.is_enabled, AB::Expr::ONE)
            .assert_zero(next.is_enabled);

        let selector_sum = local.is_wit
            + local.is_const
            + local.is_instance
            + local.is_challenge
            + local.is_add
            + local.is_sub
            + local.is_neg
            + local.is_mul
            + local.is_fold
            + local.is_tail;
        builder
            .when(local.is_enabled)
            .assert_one(selector_sum.clone());

        let add_value = ext_field_add(local.arg0, local.arg1);
        let sub_value = ext_field_subtract(local.arg0, local.arg1);
        let neg_value = scalar_subtract_ext_field(AB::Expr::ZERO, local.arg0);
        let mul_value = ext_field_multiply(local.arg0, local.arg1);
        let fold_value = ext_field_add(
            local.chip_acc_in,
            ext_field_multiply(local.alpha, local.arg0),
        );
        let tail_value = ext_field_multiply(local.arg1, local.arg0);

        let mut expected = [AB::Expr::ZERO; D_EF];
        for (sel, value) in [
            (local.is_wit, local.arg0.map(Into::into)),
            (local.is_const, local.arg0.map(Into::into)),
            (local.is_instance, local.arg0.map(Into::into)),
            (local.is_challenge, local.arg0.map(Into::into)),
            (local.is_add, add_value),
            (local.is_sub, sub_value),
            (local.is_neg, neg_value),
            (local.is_mul, mul_value),
            (local.is_fold, fold_value),
            (local.is_tail, tail_value),
        ] {
            expected = ext_field_add(expected, ext_field_multiply_scalar(value, sel));
        }
        assert_array_eq(&mut builder.when(local.is_enabled), local.value, expected);

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_fold),
            local.chip_acc_out,
            local.value.map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_tail),
            local.chip_acc_out,
            local.value.map(Into::into),
        );
        let is_expr_node = selector_sum - local.is_fold - local.is_tail;
        assert_array_eq(
            &mut builder.when(local.is_enabled * is_expr_node),
            local.chip_acc_out,
            local.chip_acc_in.map(Into::into),
        );

        self.eval_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEvalMessage {
                idx: local.idx.into(),
                eval_idx: local.eval_idx.into(),
                value: local.arg0.map(Into::into),
            },
            local.is_enabled * local.has_eval_factor,
        );
        self.global_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainGlobalPointMessage {
                round_idx: local.global_round_idx.into(),
                value: local.arg0.map(Into::into),
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

            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.row_idx = F::from_usize(record.row_idx);
            cols.node_idx = F::from_usize(record.node_idx);
            cols.eval_idx = F::from_usize(record.eval_idx);
            cols.has_eval_factor = F::from_bool(record.has_eval_factor);
            cols.instance_idx = F::from_usize(record.instance_idx);
            cols.challenge_idx = F::from_usize(record.challenge_idx);
            cols.global_round_idx = F::from_usize(record.global_round_idx);
            cols.has_global_factor = F::from_bool(record.has_global_factor);
            cols.is_wit = F::from_bool(record.is_wit);
            cols.is_const = F::from_bool(record.is_const);
            cols.is_instance = F::from_bool(record.is_instance);
            cols.is_challenge = F::from_bool(record.is_challenge);
            cols.is_add = F::from_bool(record.is_add);
            cols.is_sub = F::from_bool(record.is_sub);
            cols.is_neg = F::from_bool(record.is_neg);
            cols.is_mul = F::from_bool(record.is_mul);
            cols.is_fold = F::from_bool(record.is_fold);
            cols.is_tail = F::from_bool(record.is_tail);
            cols.constraint_idx = F::from_usize(record.constraint_idx);
            cols.alpha = record
                .alpha
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.arg0 = record
                .arg0
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.arg1 = record
                .arg1
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.value = record
                .value
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
            cols.is_last_chip_step = F::from_bool(record.is_last_chip_step);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}
