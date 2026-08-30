use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::{SubAir, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::{
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::ext_field_multiply,
};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        MainAlphaPowBus, MainAlphaPowMessage, MainContributionBus, MainContributionMessage,
        MainEvalBus, MainEvalMessage, MainExpressionCountBus, MainExpressionCountMessage,
        MainInitialClaimBus, MainInitialClaimMessage, MainMatrixCorrectionShapeBus,
        MainMatrixCorrectionShapeMessage, MatrixReductionValueBus, MatrixReductionValueMessage,
        TranscriptBus, TranscriptBusMessage,
    },
    system::{MainAlphaPowRecord, MainMatrixCorrectionRecord, MainProofValueRecord},
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainProofValueCols<T> {
    is_enabled: T,
    proof_idx: T,
    claimed_sum: [T; D_EF],
    main_out_evals_len: T,
}

pub struct MainProofValueAir {
    pub initial_claim_bus: MainInitialClaimBus,
}

impl<F: Field> BaseAir<F> for MainProofValueAir {
    fn width(&self) -> usize {
        MainProofValueCols::<F>::width()
    }
}
impl<F: Field> BaseAirWithPublicValues<F> for MainProofValueAir {}
impl<F: Field> PartitionedBaseAir<F> for MainProofValueAir {}
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainProofValueAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0).expect("row");
        let local: &MainProofValueCols<AB::Var> = (*row).borrow();
        builder.assert_bool(local.is_enabled);
        builder
            .when(local.is_enabled)
            .assert_zero(local.main_out_evals_len);
        self.initial_claim_bus.send(
            builder,
            local.proof_idx,
            MainInitialClaimMessage {
                claimed_sum: local.claimed_sum.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainAlphaPowCols<T> {
    is_enabled: T,
    proof_idx: T,
    air_idx: T,
    alpha_idx: T,
    num_exprs: T,
    alpha_tidx: T,
    is_first: T,
    is_last: T,
    is_first_air: T,
    is_last_air: T,
    lookup_count: T,
    alpha: [T; D_EF],
    value: [T; D_EF],
}

pub struct MainAlphaPowAir {
    pub transcript_bus: TranscriptBus,
    pub expression_count_bus: MainExpressionCountBus,
    pub alpha_pow_bus: MainAlphaPowBus,
}

impl<F: Field> BaseAir<F> for MainAlphaPowAir {
    fn width(&self) -> usize {
        MainAlphaPowCols::<F>::width()
    }
}
impl<F: Field> BaseAirWithPublicValues<F> for MainAlphaPowAir {}
impl<F: Field> PartitionedBaseAir<F> for MainAlphaPowAir {}
impl<AB> Air<AB> for MainAlphaPowAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("row");
        let next_row = main.row_slice(1).expect("next row");
        let local: &MainAlphaPowCols<AB::Var> = (*local_row).borrow();
        let next: &MainAlphaPowCols<AB::Var> = (*next_row).borrow();
        for flag in [
            local.is_enabled,
            local.is_first,
            local.is_last,
            local.is_first_air,
            local.is_last_air,
        ] {
            builder.assert_bool(flag);
        }
        NestedForLoopSubAir::<1> {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx],
                    is_first: [local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx],
                    is_first: [next.is_first],
                }
                .map_into(),
            ),
        );
        let computed_is_last = local.is_enabled - next.is_enabled + next.is_first;
        builder
            .when(local.is_enabled)
            .assert_eq(local.is_last, computed_is_last);
        let computed_is_last_air = local.is_enabled - next.is_enabled + next.is_first_air;
        builder
            .when(local.is_enabled)
            .assert_eq(local.is_last_air, computed_is_last_air);
        builder.when(local.is_first).assert_one(local.is_first_air);
        builder
            .when(local.is_first_air)
            .assert_zero(local.alpha_idx);
        builder
            .when(local.is_last_air)
            .assert_eq(local.alpha_idx + AB::Expr::ONE, local.num_exprs);
        let one = [
            AB::Expr::ONE,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ];
        assert_array_eq(&mut builder.when(local.is_first), local.value, one);
        for limb in 0..D_EF {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: local.alpha_tidx + AB::Expr::from_usize(limb),
                    value: local.alpha[limb].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled * local.is_first,
            );
        }
        self.expression_count_bus.receive(
            builder,
            local.proof_idx,
            MainExpressionCountMessage {
                air_idx: local.air_idx.into(),
                num_exprs: local.num_exprs.into(),
            },
            local.is_enabled * local.is_first_air,
        );
        self.alpha_pow_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            MainAlphaPowMessage {
                air_idx: local.air_idx.into(),
                alpha_idx: local.alpha_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
        let transition = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder.when(transition.clone()).assert_one(next.is_enabled);
        builder
            .when(transition.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when(transition.clone())
            .assert_eq(next.alpha_tidx, local.alpha_tidx);
        assert_array_eq(
            &mut builder.when(transition.clone()),
            local.alpha,
            next.alpha,
        );
        let next_value = ext_field_multiply(local.value, local.alpha);
        assert_array_eq(
            &mut builder.when(transition.clone()),
            next.value,
            next_value,
        );
        builder
            .when(transition.clone() * (AB::Expr::ONE - next.is_first_air))
            .assert_eq(next.air_idx, local.air_idx);
        builder
            .when(transition.clone() * (AB::Expr::ONE - next.is_first_air))
            .assert_eq(next.alpha_idx, local.alpha_idx + AB::Expr::ONE);
        builder
            .when(transition.clone() * next.is_first_air)
            .assert_one(local.is_last_air);
        builder
            .when(transition * (AB::Expr::ONE - next.is_first_air))
            .assert_zero(local.is_last_air);
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainMatrixCorrectionCols<T> {
    is_enabled: T,
    proof_idx: T,
    idx: T,
    air_idx: T,
    correction_idx: T,
    alpha_idx: T,
    eval_idx: T,
    matrix_kind: T,
    matrix_idx: T,
    matrix_tidx: T,
    claim: [T; D_EF],
    alpha_pow: [T; D_EF],
    selector_eval: [T; D_EF],
    contribution: [T; D_EF],
}

pub struct MainMatrixCorrectionAir {
    pub shape_bus: MainMatrixCorrectionShapeBus,
    pub alpha_pow_bus: MainAlphaPowBus,
    pub matrix_value_bus: MatrixReductionValueBus,
    pub eval_bus: MainEvalBus,
    pub contribution_bus: MainContributionBus,
}

impl<F: Field> BaseAir<F> for MainMatrixCorrectionAir {
    fn width(&self) -> usize {
        MainMatrixCorrectionCols::<F>::width()
    }
}
impl<F: Field> BaseAirWithPublicValues<F> for MainMatrixCorrectionAir {}
impl<F: Field> PartitionedBaseAir<F> for MainMatrixCorrectionAir {}
impl<AB> Air<AB> for MainMatrixCorrectionAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0).expect("row");
        let local: &MainMatrixCorrectionCols<AB::Var> = (*row).borrow();
        builder.assert_bool(local.is_enabled);
        self.shape_bus.receive(
            builder,
            local.proof_idx,
            MainMatrixCorrectionShapeMessage {
                air_idx: local.air_idx.into(),
                correction_idx: local.correction_idx.into(),
                alpha_idx: local.alpha_idx.into(),
                eval_idx: local.eval_idx.into(),
                matrix_kind: local.matrix_kind.into(),
                matrix_idx: local.matrix_idx.into(),
            },
            local.is_enabled,
        );
        self.alpha_pow_bus.lookup_key(
            builder,
            local.proof_idx,
            MainAlphaPowMessage {
                air_idx: local.air_idx.into(),
                alpha_idx: local.alpha_idx.into(),
                value: local.alpha_pow.map(Into::into),
            },
            local.is_enabled,
        );
        self.matrix_value_bus.lookup_key(
            builder,
            local.proof_idx,
            MatrixReductionValueMessage {
                air_idx: local.air_idx.into(),
                kind: local.matrix_kind.into(),
                idx: local.matrix_idx.into(),
                tidx: local.matrix_tidx.into(),
                value: local.claim.map(Into::into),
            },
            local.is_enabled,
        );
        self.eval_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEvalMessage {
                idx: local.idx.into(),
                eval_idx: local.eval_idx.into(),
                value: local.selector_eval.map(Into::into),
            },
            local.is_enabled,
        );
        let expected = ext_field_multiply(
            ext_field_multiply(local.alpha_pow, local.claim),
            local.selector_eval,
        )
        .map(|value| -value);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.contribution,
            expected,
        );
        self.contribution_bus.send(
            builder,
            local.proof_idx,
            MainContributionMessage {
                idx: local.idx.into(),
                contribution: local.contribution.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

fn trace_height(len: usize, required: Option<usize>) -> Option<usize> {
    let valid = len.max(1);
    required.map_or_else(
        || Some(valid.next_power_of_two()),
        |h| (h >= valid).then_some(h),
    )
}

pub struct MainProofValueTraceGenerator;
impl RowMajorChip<F> for MainProofValueTraceGenerator {
    type Ctx<'a> = &'a [MainProofValueRecord];
    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let w = MainProofValueCols::<F>::width();
        let h = trace_height(records.len(), required)?;
        let mut trace = vec![F::ZERO; h * w];
        for (row, record) in trace.chunks_exact_mut(w).zip(records.iter()) {
            let cols: &mut MainProofValueCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.claimed_sum = record
                .claimed_sum
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.main_out_evals_len = F::from_usize(record.main_out_evals_len);
        }
        Some(RowMajorMatrix::new(trace, w))
    }
}

pub struct MainAlphaPowTraceGenerator;
impl RowMajorChip<F> for MainAlphaPowTraceGenerator {
    type Ctx<'a> = &'a [MainAlphaPowRecord];
    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let w = MainAlphaPowCols::<F>::width();
        let h = trace_height(records.len(), required)?;
        let mut trace = vec![F::ZERO; h * w];
        for (row_idx, (row, record)) in trace.chunks_exact_mut(w).zip(records.iter()).enumerate() {
            let cols: &mut MainAlphaPowCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.air_idx = F::from_usize(record.air_idx);
            cols.alpha_idx = F::from_usize(record.alpha_idx);
            cols.num_exprs = F::from_usize(record.num_exprs);
            cols.alpha_tidx = F::from_usize(record.alpha_tidx);
            cols.is_first =
                F::from_bool(row_idx == 0 || records[row_idx - 1].proof_idx != record.proof_idx);
            cols.is_last = F::from_bool(
                records
                    .get(row_idx + 1)
                    .is_none_or(|next| next.proof_idx != record.proof_idx),
            );
            cols.is_first_air = F::from_bool(record.alpha_idx == 0);
            cols.is_last_air = F::from_bool(record.alpha_idx + 1 == record.num_exprs);
            cols.lookup_count = F::from_usize(record.lookup_count);
            cols.alpha = record
                .alpha
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.value = record
                .value
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
        }
        Some(RowMajorMatrix::new(trace, w))
    }
}

pub struct MainMatrixCorrectionTraceGenerator;
impl RowMajorChip<F> for MainMatrixCorrectionTraceGenerator {
    type Ctx<'a> = &'a [MainMatrixCorrectionRecord];
    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let w = MainMatrixCorrectionCols::<F>::width();
        let h = trace_height(records.len(), required)?;
        let mut trace = vec![F::ZERO; h * w];
        for (row, record) in trace.chunks_exact_mut(w).zip(records.iter()) {
            let cols: &mut MainMatrixCorrectionCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.air_idx = F::from_usize(record.air_idx);
            cols.correction_idx = F::from_usize(record.correction_idx);
            cols.alpha_idx = F::from_usize(record.alpha_idx);
            cols.eval_idx = F::from_usize(record.eval_idx);
            cols.matrix_kind = F::from_usize(record.matrix_kind);
            cols.matrix_idx = F::from_usize(record.matrix_idx);
            cols.matrix_tidx = F::from_usize(record.matrix_tidx);
            cols.claim = record
                .claim
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.alpha_pow = record
                .alpha_pow
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.selector_eval = record
                .selector_eval
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.contribution = record
                .contribution
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
        }
        Some(RowMajorMatrix::new(trace, w))
    }
}
