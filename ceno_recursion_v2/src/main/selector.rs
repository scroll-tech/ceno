use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        AirPresenceBus, AirPresenceBusMessage, MainEvalBus, MainEvalMessage, MainGlobalPointBus,
        MainGlobalPointMessage, MainSelectorResultBus, MainSelectorResultMessage,
        MainSelectorShapeBus, MainSelectorShapeMessage, MainSelectorSparseIndexShapeBus,
        MainSelectorSparseIndexShapeMessage,
    },
    system::{MainSelectorEvalRecord, MainSelectorKind, RecursionField},
    tracegen::RowMajorChip,
};

pub const MAX_SELECTOR_POINT_VARS: usize = 32;
pub const MAX_SELECTOR_SPARSE_INDICES: usize = 256;

const STEP_SHAPE: usize = 0;
const STEP_EQ_PRODUCT: usize = 1;
const STEP_SPARSE_INDEX: usize = 2;
const STEP_ACCUMULATE: usize = 3;
const STEP_FINAL: usize = 4;
const STEP_MULTIPLY: usize = 5;
const STEP_QUARK: usize = 6;

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainSelectorFormulaCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub air_idx: T,
    pub selector_idx: T,
    pub eval_idx: T,
    pub kind: T,
    pub is_whole: T,
    pub is_prefix: T,
    pub is_ordered_sparse: T,
    pub is_quark_binary_tree_less_than: T,
    pub ctx_offset: T,
    pub ctx_num_instances: T,
    pub ctx_num_vars: T,
    pub ordered_sparse_num_vars: T,
    pub num_sparse_indices: T,
    pub step_kind: T,
    pub step_idx: T,
    pub is_shape_step: T,
    pub is_eq_product_step: T,
    pub is_sparse_index_step: T,
    pub is_accumulate_step: T,
    pub is_final_step: T,
    pub is_multiply_step: T,
    pub is_quark_step: T,
    pub is_first_quark_step: T,
    pub is_last_quark_step: T,
    pub carry_accumulator: T,
    pub round_idx: T,
    pub sparse_pos: T,
    pub sparse_index: T,
    pub sparse_index_bits_value: T,
    pub point_active: T,
    pub lhs_point: [T; D_EF],
    pub rhs_point: [T; D_EF],
    pub factor: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
    pub value: [T; D_EF],
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainSelectorEvalCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub eval_idx: T,
    pub value: [T; D_EF],
}

pub struct MainSelectorFormulaAir {
    pub global_point_bus: MainGlobalPointBus,
    pub air_presence_bus: AirPresenceBus,
    pub selector_result_bus: MainSelectorResultBus,
    pub selector_shape_bus: MainSelectorShapeBus,
    pub selector_sparse_index_shape_bus: MainSelectorSparseIndexShapeBus,
}

impl<F: Field> BaseAir<F> for MainSelectorFormulaAir {
    fn width(&self) -> usize {
        MainSelectorFormulaCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainSelectorFormulaAir {}
impl<F: Field> PartitionedBaseAir<F> for MainSelectorFormulaAir {}

impl<AB> Air<AB> for MainSelectorFormulaAir
where
    AB: AirBuilder + InteractionBuilder,
    AB::Expr: Clone,
    AB::Var: Clone,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("main row exists"),
        );
        let local: &MainSelectorFormulaCols<AB::Var> = (*local_row).borrow();
        let next: &MainSelectorFormulaCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_whole);
        builder.assert_bool(local.is_prefix);
        builder.assert_bool(local.is_ordered_sparse);
        builder.assert_bool(local.is_quark_binary_tree_less_than);
        builder.assert_bool(local.is_shape_step);
        builder.assert_bool(local.is_eq_product_step);
        builder.assert_bool(local.is_sparse_index_step);
        builder.assert_bool(local.is_accumulate_step);
        builder.assert_bool(local.is_final_step);
        builder.assert_bool(local.is_multiply_step);
        builder.assert_bool(local.is_quark_step);
        builder.assert_bool(local.is_first_quark_step);
        builder.assert_bool(local.is_last_quark_step);
        builder.assert_bool(local.carry_accumulator);
        builder.assert_bool(local.point_active);
        builder
            .when_transition()
            .when_ne(local.is_enabled, AB::Expr::ONE)
            .assert_zero(next.is_enabled);
        builder.when(local.is_enabled).assert_one(
            local.is_whole
                + local.is_prefix
                + local.is_ordered_sparse
                + local.is_quark_binary_tree_less_than,
        );
        builder.when(local.is_enabled).assert_one(
            local.is_shape_step
                + local.is_eq_product_step
                + local.is_sparse_index_step
                + local.is_accumulate_step
                + local.is_final_step
                + local.is_multiply_step
                + local.is_quark_step,
        );
        builder.when(local.is_enabled).assert_eq(
            local.kind,
            local.is_prefix
                + local.is_ordered_sparse * AB::Expr::from_usize(2)
                + local.is_quark_binary_tree_less_than * AB::Expr::from_usize(3),
        );
        builder.when(local.is_enabled).assert_eq(
            local.step_kind,
            local.is_eq_product_step * AB::Expr::from_usize(STEP_EQ_PRODUCT)
                + local.is_sparse_index_step * AB::Expr::from_usize(STEP_SPARSE_INDEX)
                + local.is_accumulate_step * AB::Expr::from_usize(STEP_ACCUMULATE)
                + local.is_final_step * AB::Expr::from_usize(STEP_FINAL)
                + local.is_multiply_step * AB::Expr::from_usize(STEP_MULTIPLY)
                + local.is_quark_step * AB::Expr::from_usize(STEP_QUARK),
        );
        builder
            .when(local.carry_accumulator)
            .assert_one(local.is_enabled);
        builder.when(local.carry_accumulator).assert_one(
            local.is_eq_product_step
                + local.is_accumulate_step
                + local.is_multiply_step
                + local.is_quark_step,
        );
        builder
            .when(local.is_first_quark_step)
            .assert_one(local.is_quark_step);
        builder
            .when(local.is_last_quark_step)
            .assert_one(local.is_quark_step);

        self.selector_shape_bus.receive(
            builder,
            local.proof_idx,
            MainSelectorShapeMessage {
                air_idx: local.air_idx.into(),
                selector_idx: local.selector_idx.into(),
                kind: local.kind.into(),
                eval_idx: local.eval_idx.into(),
                ctx_offset: local.ctx_offset.into(),
                ctx_num_instances: local.ctx_num_instances.into(),
                ctx_num_vars: local.ctx_num_vars.into(),
                ordered_sparse_num_vars: local.ordered_sparse_num_vars.into(),
                num_sparse_indices: local.num_sparse_indices.into(),
            },
            local.is_enabled * local.is_shape_step,
        );
        self.air_presence_bus.lookup_key(
            builder,
            local.proof_idx,
            AirPresenceBusMessage {
                air_idx: local.air_idx.into(),
                is_present: AB::Expr::ONE,
            },
            local.is_enabled * local.is_shape_step,
        );
        self.selector_sparse_index_shape_bus.receive(
            builder,
            local.proof_idx,
            MainSelectorSparseIndexShapeMessage {
                air_idx: local.air_idx.into(),
                selector_idx: local.selector_idx.into(),
                sparse_pos: local.sparse_pos.into(),
                sparse_index: local.sparse_index.into(),
            },
            local.is_enabled * local.is_sparse_index_step,
        );
        builder
            .when(local.is_enabled * local.is_sparse_index_step)
            .assert_eq(local.sparse_index_bits_value, local.sparse_index);

        self.global_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainGlobalPointMessage {
                round_idx: local.round_idx.into(),
                value: local.lhs_point.map(Into::into),
            },
            local.is_enabled
                * (local.is_eq_product_step * local.point_active + local.is_quark_step),
        );
        let expected_factor = eq_factor::<AB>(local.rhs_point.clone(), local.lhs_point.clone());
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_eq_product_step * local.point_active),
            local.factor,
            expected_factor,
        );
        assert_array_eq(
            &mut builder.when(
                local.is_enabled * local.is_eq_product_step * (AB::Expr::ONE - local.point_active),
            ),
            local.factor,
            ext_one::<AB::Expr>(),
        );
        let product = ext_mul::<AB::Expr>(
            local.acc_in.clone().map(Into::into),
            local.factor.clone().map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_eq_product_step),
            local.acc_out,
            product,
        );
        let sum = ext_add::<AB::Expr>(
            local.acc_in.clone().map(Into::into),
            local.factor.clone().map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_accumulate_step),
            local.acc_out,
            sum,
        );
        let multiply_product = ext_mul::<AB::Expr>(
            local.acc_in.clone().map(Into::into),
            local.factor.clone().map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_multiply_step),
            local.acc_out,
            multiply_product,
        );
        builder
            .when(local.is_enabled * local.is_quark_step)
            .assert_eq(
                local.sparse_index,
                local.sparse_index_bits_value * AB::Expr::from_usize(2) + local.point_active,
            );
        builder
            .when(local.is_enabled * local.is_first_quark_step)
            .assert_zero(local.step_idx);
        builder
            .when(local.is_enabled * local.is_first_quark_step)
            .assert_zero(local.round_idx);
        builder
            .when(local.is_enabled * local.is_first_quark_step)
            .assert_zero(
                local.sparse_index_bits_value * (local.sparse_index_bits_value - AB::Expr::ONE),
            );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_quark_step),
            local.acc_in,
            [AB::Expr::ZERO; D_EF],
        );
        builder
            .when(local.is_enabled * local.is_last_quark_step)
            .assert_eq(local.sparse_index, local.ctx_num_instances);
        let quark_zero_factor = ext_mul::<AB::Expr>(
            ext_one_minus(local.rhs_point.clone().map(Into::into)),
            ext_one_minus(local.lhs_point.clone().map(Into::into)),
        );
        let quark_one_factor = ext_mul::<AB::Expr>(
            local.rhs_point.clone().map(Into::into),
            local.lhs_point.clone().map(Into::into),
        );
        let quark_lhs =
            ext_mul::<AB::Expr>(quark_zero_factor, local.factor.clone().map(Into::into));
        let quark_rhs = ext_mul::<AB::Expr>(quark_one_factor, local.acc_in.clone().map(Into::into));
        let quark_out = ext_add::<AB::Expr>(quark_lhs, quark_rhs);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_quark_step),
            local.acc_out,
            quark_out,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_final_step),
            local.acc_out,
            local.value.clone().map(Into::into),
        );
        let same_selector_continuation =
            local.is_enabled * next.is_enabled * (AB::Expr::ONE - next.is_shape_step);
        builder
            .when_transition()
            .when(same_selector_continuation.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(same_selector_continuation.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when_transition()
            .when(same_selector_continuation.clone())
            .assert_eq(next.air_idx, local.air_idx);
        builder
            .when_transition()
            .when(same_selector_continuation.clone())
            .assert_eq(next.selector_idx, local.selector_idx);
        builder
            .when_transition()
            .when(same_selector_continuation.clone())
            .assert_eq(next.eval_idx, local.eval_idx);
        builder
            .when_transition()
            .when(same_selector_continuation.clone())
            .assert_eq(next.kind, local.kind);
        assert_array_eq(
            &mut builder.when_transition().when(local.carry_accumulator),
            local.acc_out,
            next.acc_in,
        );
        builder
            .when_transition()
            .when(local.is_eq_product_step * next.is_eq_product_step)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_eq_product_step * next.is_final_step * local.is_whole)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_accumulate_step * next.is_accumulate_step)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_accumulate_step * next.is_multiply_step)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_accumulate_step * next.is_final_step)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_multiply_step * next.is_final_step)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_quark_step * next.is_quark_step)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_quark_step * next.is_quark_step)
            .assert_eq(next.step_idx, local.step_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(local.is_quark_step * next.is_quark_step)
            .assert_eq(next.round_idx, local.round_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(local.is_quark_step * next.is_quark_step)
            .assert_eq(
                next.sparse_index,
                local.sparse_index * AB::Expr::from_usize(2) - next.point_active,
            );
        builder
            .when_transition()
            .when(local.is_quark_step * next.is_final_step)
            .assert_one(local.carry_accumulator);
        builder
            .when_transition()
            .when(local.is_enabled * local.is_final_step)
            .assert_zero(next.is_enabled * (AB::Expr::ONE - next.is_shape_step));

        self.selector_result_bus.send(
            builder,
            local.proof_idx,
            MainSelectorResultMessage {
                idx: local.idx.into(),
                eval_idx: local.eval_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.is_final_step,
        );
    }
}

pub struct MainSelectorEvalAir {
    pub eval_bus: MainEvalBus,
    pub selector_result_bus: MainSelectorResultBus,
}

impl<F: Field> BaseAir<F> for MainSelectorEvalAir {
    fn width(&self) -> usize {
        MainSelectorEvalCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainSelectorEvalAir {}
impl<F: Field> PartitionedBaseAir<F> for MainSelectorEvalAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainSelectorEvalAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &MainSelectorEvalCols<AB::Var> = (*local_row).borrow();

        builder.assert_bool(local.is_enabled);
        self.selector_result_bus.receive(
            builder,
            local.proof_idx,
            MainSelectorResultMessage {
                idx: local.idx.into(),
                eval_idx: local.eval_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled,
        );
        self.eval_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEvalMessage {
                idx: local.idx.into(),
                eval_idx: local.eval_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

fn ext_one<FA: PrimeCharacteristicRing>() -> [FA; D_EF] {
    [FA::ONE, FA::ZERO, FA::ZERO, FA::ZERO]
}

fn ext_add<FA: PrimeCharacteristicRing>(x: [FA; D_EF], y: [FA; D_EF]) -> [FA; D_EF] {
    let [x0, x1, x2, x3] = x;
    let [y0, y1, y2, y3] = y;
    [x0 + y0, x1 + y1, x2 + y2, x3 + y3]
}

fn ext_one_minus<FA: PrimeCharacteristicRing>(x: [FA; D_EF]) -> [FA; D_EF] {
    let [x0, x1, x2, x3] = x;
    [FA::ONE - x0, -x1, -x2, -x3]
}

fn ext_mul<FA>(x: [FA; D_EF], y: [FA; D_EF]) -> [FA; D_EF]
where
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let [x0, x1, x2, x3] = x;
    let [y0, y1, y2, y3] = y;
    let w = FA::from_prime_subfield(FA::PrimeSubfield::W);
    let z0_beta_terms = x1.clone() * y3.clone() + x2.clone() * y2.clone() + x3.clone() * y1.clone();
    let z1_beta_terms = x2.clone() * y3.clone() + x3.clone() * y2.clone();
    let z2_beta_terms = x3.clone() * y3.clone();
    [
        x0.clone() * y0.clone() + z0_beta_terms * w.clone(),
        x0.clone() * y1.clone() + x1.clone() * y0.clone() + z1_beta_terms * w.clone(),
        x0.clone() * y2.clone()
            + x1.clone() * y1.clone()
            + x2.clone() * y0.clone()
            + z2_beta_terms * w,
        x0 * y3 + x1 * y2 + x2 * y1 + x3 * y0,
    ]
}

fn eq_factor<AB>(out: [AB::Var; D_EF], input: [AB::Var; D_EF]) -> [AB::Expr; D_EF]
where
    AB: AirBuilder,
    AB::Expr: Clone,
    AB::Var: Clone,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let out_expr = out.map(Into::into);
    let input_expr = input.map(Into::into);
    let same_one: [AB::Expr; D_EF] = ext_mul(out_expr.clone(), input_expr.clone());
    let same_zero: [AB::Expr; D_EF] = ext_mul(ext_one_minus(out_expr), ext_one_minus(input_expr));
    ext_add::<AB::Expr>(same_one, same_zero)
}

pub struct MainSelectorFormulaTraceGenerator;
pub struct MainSelectorEvalTraceGenerator;

impl RowMajorChip<F> for MainSelectorFormulaTraceGenerator {
    type Ctx<'a> = &'a [MainSelectorEvalRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let rows = build_formula_rows(records);
        generate_selector_trace(&rows, required_height, fill_formula_cols)
    }
}

impl RowMajorChip<F> for MainSelectorEvalTraceGenerator {
    type Ctx<'a> = &'a [MainSelectorEvalRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        generate_selector_trace(records, required_height, fill_eval_cols)
    }
}

fn generate_selector_trace<C, R, Fill>(
    records: &[R],
    required_height: Option<usize>,
    mut fill: Fill,
) -> Option<RowMajorMatrix<F>>
where
    C: SelectorColumnAccess<F>,
    Fill: FnMut(&R, &mut C),
{
    let width = C::width();
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
        fill(record, C::from_bytes(row));
    }
    Some(RowMajorMatrix::new(trace, width))
}

trait SelectorColumnAccess<F>: Sized {
    fn width() -> usize;
    fn from_bytes(slice: &mut [F]) -> &mut Self;
}

impl SelectorColumnAccess<F> for MainSelectorFormulaCols<F> {
    fn width() -> usize {
        MainSelectorFormulaCols::<F>::width()
    }

    fn from_bytes(slice: &mut [F]) -> &mut Self {
        slice.borrow_mut()
    }
}

impl SelectorColumnAccess<F> for MainSelectorEvalCols<F> {
    fn width() -> usize {
        MainSelectorEvalCols::<F>::width()
    }

    fn from_bytes(slice: &mut [F]) -> &mut Self {
        slice.borrow_mut()
    }
}

fn fill_eval_cols(record: &MainSelectorEvalRecord, cols: &mut MainSelectorEvalCols<F>) {
    cols.is_enabled = F::from_bool(record.has_eval);
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.eval_idx = F::from_usize(record.eval_idx);
    cols.value = record
        .value
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
}

#[derive(Clone)]
struct FormulaRow<'a> {
    record: &'a MainSelectorEvalRecord,
    step_kind: usize,
    step_idx: usize,
    round_idx: usize,
    sparse_pos: usize,
    sparse_index: usize,
    sparse_index_bits_value: usize,
    quark_is_first: bool,
    quark_is_last: bool,
    point_active: bool,
    lhs_point: RecursionField,
    rhs_point: RecursionField,
    factor: RecursionField,
    acc_in: RecursionField,
    acc_out: RecursionField,
}

fn build_formula_rows(records: &[MainSelectorEvalRecord]) -> Vec<FormulaRow<'_>> {
    if records.is_empty() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for record in records {
        let one = RecursionField::ONE;
        let zero = RecursionField::ZERO;
        rows.push(FormulaRow {
            record,
            step_kind: STEP_SHAPE,
            step_idx: 0,
            round_idx: 0,
            sparse_pos: 0,
            sparse_index: 0,
            sparse_index_bits_value: 0,
            quark_is_first: false,
            quark_is_last: false,
            point_active: false,
            lhs_point: zero,
            rhs_point: zero,
            factor: one,
            acc_in: zero,
            acc_out: zero,
        });

        for (sparse_pos, sparse_index) in record.sparse_indices.iter().copied().enumerate() {
            rows.push(FormulaRow {
                record,
                step_kind: STEP_SPARSE_INDEX,
                step_idx: sparse_pos,
                round_idx: 0,
                sparse_pos,
                sparse_index,
                sparse_index_bits_value: sparse_index,
                quark_is_first: false,
                quark_is_last: false,
                point_active: false,
                lhs_point: zero,
                rhs_point: zero,
                factor: one,
                acc_in: zero,
                acc_out: zero,
            });
        }

        if !record.has_eval {
            continue;
        }

        let computed_value = match record.kind {
            MainSelectorKind::Whole => {
                let acc =
                    push_eq_product_rows(&mut rows, record, 0, record.ctx_num_vars, one, true);
                acc
            }
            MainSelectorKind::Prefix => {
                let _ = push_eq_product_rows(&mut rows, record, 0, record.ctx_num_vars, one, true);
                let end = record.ctx_offset + record.ctx_num_instances;
                let end_eval = if end == 0 {
                    zero
                } else {
                    native_eq_lte(end - 1, &record.out_point, &record.in_point)
                };
                let start_eval = if record.ctx_offset == 0 {
                    zero
                } else {
                    native_eq_lte(record.ctx_offset - 1, &record.out_point, &record.in_point)
                };
                let value = end_eval - start_eval;
                rows.push(accumulate_row(record, 0, end_eval, -start_eval, value));
                value
            }
            MainSelectorKind::OrderedSparse => {
                let _ = push_eq_product_rows(&mut rows, record, 0, record.ctx_num_vars, one, true);
                let subgroup_vars = record.ordered_sparse_num_vars;
                let out_subgroup_eq = native_eq_vec(&record.out_point[..subgroup_vars]);
                let in_subgroup_eq = native_eq_vec(&record.in_point[..subgroup_vars]);
                let mut subgroup_acc = zero;
                for (sparse_pos, sparse_index) in record.sparse_indices.iter().copied().enumerate()
                {
                    let term = out_subgroup_eq[sparse_index] * in_subgroup_eq[sparse_index];
                    let acc_in = subgroup_acc;
                    subgroup_acc += term;
                    rows.push(accumulate_row(
                        record,
                        sparse_pos,
                        acc_in,
                        term,
                        subgroup_acc,
                    ));
                }
                let tail_eval = native_eq_lte(
                    record.ctx_num_instances - 1,
                    &record.out_point[subgroup_vars..],
                    &record.in_point[subgroup_vars..],
                );
                let value = subgroup_acc * tail_eval;
                rows.push(multiply_row(
                    record,
                    record.sparse_indices.len(),
                    subgroup_acc,
                    tail_eval,
                    value,
                ));
                value
            }
            MainSelectorKind::QuarkBinaryTreeLessThan => push_quark_rows(&mut rows, record),
        };
        rows.push(FormulaRow {
            record,
            step_kind: STEP_FINAL,
            step_idx: 0,
            round_idx: 0,
            sparse_pos: 0,
            sparse_index: 0,
            sparse_index_bits_value: 0,
            quark_is_first: false,
            quark_is_last: false,
            point_active: false,
            lhs_point: zero,
            rhs_point: zero,
            factor: one,
            acc_in: computed_value,
            acc_out: computed_value,
        });
    }
    rows
}

fn accumulate_row(
    record: &MainSelectorEvalRecord,
    step_idx: usize,
    acc_in: RecursionField,
    factor: RecursionField,
    acc_out: RecursionField,
) -> FormulaRow<'_> {
    FormulaRow {
        record,
        step_kind: STEP_ACCUMULATE,
        step_idx,
        round_idx: 0,
        sparse_pos: step_idx,
        sparse_index: 0,
        sparse_index_bits_value: 0,
        quark_is_first: false,
        quark_is_last: false,
        point_active: false,
        lhs_point: RecursionField::ZERO,
        rhs_point: RecursionField::ZERO,
        factor,
        acc_in,
        acc_out,
    }
}

fn multiply_row(
    record: &MainSelectorEvalRecord,
    step_idx: usize,
    acc_in: RecursionField,
    factor: RecursionField,
    acc_out: RecursionField,
) -> FormulaRow<'_> {
    FormulaRow {
        record,
        step_kind: STEP_MULTIPLY,
        step_idx,
        round_idx: 0,
        sparse_pos: step_idx,
        sparse_index: 0,
        sparse_index_bits_value: 0,
        quark_is_first: false,
        quark_is_last: false,
        point_active: false,
        lhs_point: RecursionField::ZERO,
        rhs_point: RecursionField::ZERO,
        factor,
        acc_in,
        acc_out,
    }
}

fn push_quark_rows<'a>(
    rows: &mut Vec<FormulaRow<'a>>,
    record: &'a MainSelectorEvalRecord,
) -> RecursionField {
    assert!(record.ctx_num_instances > 0);
    assert!(!record.out_point.is_empty());
    assert_eq!(record.out_point.len(), record.in_point.len());

    let mut layer_ns = (0..record.out_point.len())
        .scan(record.ctx_num_instances, |n_instance, _| {
            let current = *n_instance;
            *n_instance = (*n_instance).div_ceil(2);
            Some(current)
        })
        .collect::<Vec<_>>();
    layer_ns.reverse();

    let zero = RecursionField::ZERO;
    let one = RecursionField::ONE;
    let mut acc = zero;
    for (i, layer_n) in layer_ns.iter().copied().enumerate() {
        let prefix_count = layer_n / 2;
        let parity = layer_n % 2;
        let lhs = record.in_point[i];
        let rhs = record.out_point[i];
        let factor = if prefix_count == 0 {
            zero
        } else if i == 0 {
            one
        } else {
            native_eq_lte(
                prefix_count - 1,
                &record.out_point[..i],
                &record.in_point[..i],
            )
        };
        let zero_factor = (one - rhs) * (one - lhs);
        let one_factor = rhs * lhs;
        let acc_in = acc;
        acc = zero_factor * factor + one_factor * acc;
        rows.push(FormulaRow {
            record,
            step_kind: STEP_QUARK,
            step_idx: i,
            round_idx: i,
            sparse_pos: 0,
            sparse_index: layer_n,
            sparse_index_bits_value: prefix_count,
            quark_is_first: i == 0,
            quark_is_last: i + 1 == layer_ns.len(),
            point_active: parity == 1,
            lhs_point: lhs,
            rhs_point: rhs,
            factor,
            acc_in,
            acc_out: acc,
        });
    }
    acc
}

fn push_eq_product_rows<'a>(
    rows: &mut Vec<FormulaRow<'a>>,
    record: &'a MainSelectorEvalRecord,
    start_round_idx: usize,
    len: usize,
    mut acc: RecursionField,
    point_active: bool,
) -> RecursionField {
    let zero = RecursionField::ZERO;
    for i in 0..len.min(MAX_SELECTOR_POINT_VARS) {
        let point_idx = start_round_idx + i;
        let lhs = record.in_point.get(point_idx).copied().unwrap_or(zero);
        let rhs = record.out_point.get(point_idx).copied().unwrap_or(zero);
        let factor = native_eq_factor(rhs, lhs);
        let acc_in = acc;
        acc *= factor;
        rows.push(FormulaRow {
            record,
            step_kind: STEP_EQ_PRODUCT,
            step_idx: point_idx,
            round_idx: point_idx,
            sparse_pos: 0,
            sparse_index: 0,
            sparse_index_bits_value: 0,
            quark_is_first: false,
            quark_is_last: false,
            point_active,
            lhs_point: lhs,
            rhs_point: rhs,
            factor,
            acc_in,
            acc_out: acc,
        });
    }
    acc
}

fn fill_formula_cols(row: &FormulaRow<'_>, cols: &mut MainSelectorFormulaCols<F>) {
    let record = row.record;
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.air_idx = F::from_usize(record.air_idx);
    cols.selector_idx = F::from_usize(record.selector_idx);
    cols.eval_idx = F::from_usize(record.eval_idx);
    cols.kind = F::from_usize(selector_kind_code(record.kind));
    cols.is_whole = F::from_bool(record.kind == MainSelectorKind::Whole);
    cols.is_prefix = F::from_bool(record.kind == MainSelectorKind::Prefix);
    cols.is_ordered_sparse = F::from_bool(record.kind == MainSelectorKind::OrderedSparse);
    cols.is_quark_binary_tree_less_than =
        F::from_bool(record.kind == MainSelectorKind::QuarkBinaryTreeLessThan);
    cols.ctx_offset = F::from_usize(record.ctx_offset);
    cols.ctx_num_instances = F::from_usize(record.ctx_num_instances);
    cols.ctx_num_vars = F::from_usize(record.ctx_num_vars);
    cols.ordered_sparse_num_vars = F::from_usize(record.ordered_sparse_num_vars);
    cols.num_sparse_indices = F::from_usize(record.sparse_indices.len());
    cols.step_kind = F::from_usize(row.step_kind);
    cols.step_idx = F::from_usize(row.step_idx);
    cols.is_shape_step = F::from_bool(row.step_kind == STEP_SHAPE);
    cols.is_eq_product_step = F::from_bool(row.step_kind == STEP_EQ_PRODUCT);
    cols.is_sparse_index_step = F::from_bool(row.step_kind == STEP_SPARSE_INDEX);
    cols.is_accumulate_step = F::from_bool(row.step_kind == STEP_ACCUMULATE);
    cols.is_final_step = F::from_bool(row.step_kind == STEP_FINAL);
    cols.is_multiply_step = F::from_bool(row.step_kind == STEP_MULTIPLY);
    cols.is_quark_step = F::from_bool(row.step_kind == STEP_QUARK);
    cols.is_first_quark_step = F::from_bool(row.quark_is_first);
    cols.is_last_quark_step = F::from_bool(row.quark_is_last);
    cols.carry_accumulator = F::from_bool(match row.step_kind {
        STEP_EQ_PRODUCT => {
            row.record.kind == MainSelectorKind::Whole || row.step_idx + 1 < row.record.ctx_num_vars
        }
        STEP_ACCUMULATE | STEP_MULTIPLY | STEP_QUARK => true,
        _ => false,
    });
    cols.round_idx = F::from_usize(row.round_idx);
    cols.sparse_pos = F::from_usize(row.sparse_pos);
    cols.sparse_index = F::from_usize(row.sparse_index);
    cols.sparse_index_bits_value = F::from_usize(row.sparse_index_bits_value);
    cols.point_active = F::from_bool(row.point_active);
    cols.lhs_point = row
        .lhs_point
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
    cols.rhs_point = row
        .rhs_point
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
    cols.factor = row.factor.as_basis_coefficients_slice().try_into().unwrap();
    cols.acc_in = row.acc_in.as_basis_coefficients_slice().try_into().unwrap();
    cols.acc_out = row
        .acc_out
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
    cols.value = record
        .value
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
}

fn selector_kind_code(kind: MainSelectorKind) -> usize {
    match kind {
        MainSelectorKind::Whole => 0,
        MainSelectorKind::Prefix => 1,
        MainSelectorKind::OrderedSparse => 2,
        MainSelectorKind::QuarkBinaryTreeLessThan => 3,
    }
}

fn native_eq_factor(out: RecursionField, input: RecursionField) -> RecursionField {
    out * input + (RecursionField::ONE - out) * (RecursionField::ONE - input)
}

fn native_eq_vec(point: &[RecursionField]) -> Vec<RecursionField> {
    let mut eq = vec![RecursionField::ONE];
    for &value in point.iter().rev() {
        let mut next = Vec::with_capacity(eq.len() * 2);
        for prev in eq {
            next.push(prev * (RecursionField::ONE - value));
            next.push(prev * value);
        }
        eq = next;
    }
    eq
}

fn native_eq_lte(
    max_idx: usize,
    out_point: &[RecursionField],
    in_point: &[RecursionField],
) -> RecursionField {
    assert!(out_point.len() >= in_point.len());
    let mut running_product = Vec::with_capacity(in_point.len() + 1);
    running_product.push(RecursionField::ONE);
    for i in 0..in_point.len() {
        running_product.push(running_product[i] * native_eq_factor(out_point[i], in_point[i]));
    }

    let mut running_product2 = vec![RecursionField::ZERO; in_point.len() + 1];
    running_product2[in_point.len()] = RecursionField::ONE;
    for i in (0..in_point.len()).rev() {
        let bit = if ((max_idx >> i) & 1) == 1 {
            RecursionField::ONE
        } else {
            RecursionField::ZERO
        };
        running_product2[i] = running_product2[i + 1]
            * (out_point[i] * in_point[i] * bit
                + (RecursionField::ONE - out_point[i])
                    * (RecursionField::ONE - in_point[i])
                    * (RecursionField::ONE - bit));
    }

    let mut ans = running_product[in_point.len()];
    for i in 0..in_point.len() {
        if ((max_idx >> i) & 1) == 0 {
            ans -= running_product[i] * running_product2[i + 1] * out_point[i] * in_point[i];
        }
    }
    for value in out_point.iter().skip(in_point.len()) {
        ans *= RecursionField::ONE - *value;
    }
    ans
}

#[cfg(test)]
mod tests {
    use super::*;
    use gkr_iop::selector::{SelectorContext, SelectorType};
    use multilinear_extensions::{
        Expression, StructuralWitIn, StructuralWitInType, ToExpr, WitnessId,
    };

    fn structural_expr(wit_id: WitnessId) -> Expression<RecursionField> {
        StructuralWitIn {
            id: wit_id,
            witin_type: StructuralWitInType::Empty,
        }
        .expr()
    }

    fn point(values: &[usize]) -> Vec<RecursionField> {
        values
            .iter()
            .map(|&value| RecursionField::from_usize(value))
            .collect()
    }

    fn record(
        kind: MainSelectorKind,
        ctx: &SelectorContext,
        ordered_sparse_num_vars: usize,
        sparse_indices: Vec<usize>,
        out_point: Vec<RecursionField>,
        in_point: Vec<RecursionField>,
        value: RecursionField,
    ) -> MainSelectorEvalRecord {
        MainSelectorEvalRecord {
            proof_idx: 0,
            idx: 7,
            air_idx: 11,
            selector_idx: 13,
            has_eval: true,
            eval_idx: 17,
            kind,
            ctx_offset: ctx.offset,
            ctx_num_instances: ctx.num_instances,
            ctx_num_vars: ctx.num_vars,
            ordered_sparse_num_vars,
            sparse_indices,
            in_point,
            out_point,
            value,
        }
    }

    fn formula_final_value(record: &MainSelectorEvalRecord) -> RecursionField {
        build_formula_rows(core::slice::from_ref(record))
            .into_iter()
            .find(|row| row.step_kind == STEP_FINAL)
            .map(|row| row.acc_out)
            .expect("active selector has final row")
    }

    fn assert_matches_native(
        selector: SelectorType<RecursionField>,
        kind: MainSelectorKind,
        ctx: SelectorContext,
        ordered_sparse_num_vars: usize,
        sparse_indices: Vec<usize>,
        out_point: Vec<RecursionField>,
        in_point: Vec<RecursionField>,
    ) {
        let (expected, _) = selector.evaluate(&out_point, &in_point, &ctx).unwrap();
        let record = record(
            kind,
            &ctx,
            ordered_sparse_num_vars,
            sparse_indices,
            out_point,
            in_point,
            expected,
        );
        assert_eq!(formula_final_value(&record), expected);
    }

    #[test]
    fn selector_formula_rows_match_native_whole() {
        let ctx = SelectorContext::new(0, 8, 3);
        assert_matches_native(
            SelectorType::Whole(structural_expr(0)),
            MainSelectorKind::Whole,
            ctx,
            0,
            Vec::new(),
            point(&[2, 3, 4]),
            point(&[5, 6, 7]),
        );
    }

    #[test]
    fn selector_formula_rows_match_native_prefix() {
        let ctx = SelectorContext::new(2, 5, 3);
        assert_matches_native(
            SelectorType::Prefix(structural_expr(0)),
            MainSelectorKind::Prefix,
            ctx,
            0,
            Vec::new(),
            point(&[2, 3, 4]),
            point(&[5, 6, 7]),
        );
    }

    #[test]
    fn selector_formula_rows_match_native_ordered_sparse() {
        let ctx = SelectorContext::new(0, 3, 4);
        let sparse_indices = vec![0, 2, 3];
        assert_matches_native(
            SelectorType::OrderedSparse {
                num_vars: 2,
                indices: sparse_indices.clone(),
                expression: structural_expr(0),
            },
            MainSelectorKind::OrderedSparse,
            ctx,
            2,
            sparse_indices,
            point(&[2, 3, 4, 5]),
            point(&[6, 7, 8, 9]),
        );
    }

    #[test]
    fn selector_formula_rows_match_native_quark_binary_tree_less_than() {
        let ctx = SelectorContext::new(0, 5, 3);
        assert_matches_native(
            SelectorType::QuarkBinaryTreeLessThan(structural_expr(0)),
            MainSelectorKind::QuarkBinaryTreeLessThan,
            ctx,
            0,
            Vec::new(),
            point(&[2, 3, 4]),
            point(&[5, 6, 7]),
        );
    }

    #[test]
    fn inactive_selector_rows_do_not_emit_final_result() {
        let mut record = MainSelectorEvalRecord {
            proof_idx: 0,
            idx: 7,
            air_idx: 11,
            selector_idx: 13,
            has_eval: false,
            eval_idx: 17,
            kind: MainSelectorKind::OrderedSparse,
            ctx_offset: 0,
            ctx_num_instances: 3,
            ctx_num_vars: 4,
            ordered_sparse_num_vars: 2,
            sparse_indices: vec![0, 2],
            in_point: Vec::new(),
            out_point: Vec::new(),
            value: RecursionField::ZERO,
        };
        let rows = build_formula_rows(core::slice::from_ref(&record));
        assert!(rows.iter().any(|row| row.step_kind == STEP_SHAPE));
        assert_eq!(
            rows.iter()
                .filter(|row| row.step_kind == STEP_SPARSE_INDEX)
                .count(),
            2
        );
        assert!(rows.iter().all(|row| row.step_kind != STEP_FINAL));

        record.has_eval = true;
        record.in_point = point(&[1, 2, 3, 4]);
        record.out_point = point(&[5, 6, 7, 8]);
        let rows = build_formula_rows(core::slice::from_ref(&record));
        assert!(rows.iter().any(|row| row.step_kind == STEP_FINAL));
    }
}
