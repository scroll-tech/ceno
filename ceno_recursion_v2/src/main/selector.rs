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
        MainSelectorSparseIndexShapeMessage, TowerMainPointBus, TowerMainPointMessage,
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
    pub tower_point_bus: TowerMainPointBus,
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
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &MainSelectorFormulaCols<AB::Var> = (*local_row).borrow();

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
        builder.assert_bool(local.point_active);
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
                + local.is_final_step,
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
                + local.is_final_step * AB::Expr::from_usize(STEP_FINAL),
        );

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
            local.is_enabled * local.is_eq_product_step * local.point_active,
        );
        self.tower_point_bus.receive(
            builder,
            local.proof_idx,
            TowerMainPointMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                value: local.rhs_point.map(Into::into),
            },
            local.is_enabled * local.is_eq_product_step * local.point_active,
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
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_final_step),
            local.acc_out,
            local.value.clone().map(Into::into),
        );

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
    cols.is_enabled = F::ONE;
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
            point_active: false,
            lhs_point: zero,
            rhs_point: zero,
            factor: one,
            acc_in: zero,
            acc_out: zero,
        });

        let mut acc = one;
        for i in 0..record.ctx_num_vars.min(MAX_SELECTOR_POINT_VARS) {
            let lhs = record.in_point.get(i).copied().unwrap_or(zero);
            let rhs = record.out_point.get(i).copied().unwrap_or(zero);
            let factor = native_eq_factor(rhs, lhs);
            let acc_in = acc;
            acc *= factor;
            rows.push(FormulaRow {
                record,
                step_kind: STEP_EQ_PRODUCT,
                step_idx: i,
                round_idx: i,
                sparse_pos: 0,
                sparse_index: 0,
                sparse_index_bits_value: 0,
                point_active: true,
                lhs_point: lhs,
                rhs_point: rhs,
                factor,
                acc_in,
                acc_out: acc,
            });
        }

        for (sparse_pos, sparse_index) in record.sparse_indices.iter().copied().enumerate() {
            rows.push(FormulaRow {
                record,
                step_kind: STEP_SPARSE_INDEX,
                step_idx: sparse_pos,
                round_idx: 0,
                sparse_pos,
                sparse_index,
                sparse_index_bits_value: sparse_index,
                point_active: false,
                lhs_point: zero,
                rhs_point: zero,
                factor: one,
                acc_in: zero,
                acc_out: zero,
            });
        }

        rows.push(FormulaRow {
            record,
            step_kind: STEP_ACCUMULATE,
            step_idx: 0,
            round_idx: 0,
            sparse_pos: 0,
            sparse_index: 0,
            sparse_index_bits_value: 0,
            point_active: false,
            lhs_point: zero,
            rhs_point: zero,
            factor: record.value,
            acc_in: zero,
            acc_out: record.value,
        });
        rows.push(FormulaRow {
            record,
            step_kind: STEP_FINAL,
            step_idx: 0,
            round_idx: 0,
            sparse_pos: 0,
            sparse_index: 0,
            sparse_index_bits_value: 0,
            point_active: false,
            lhs_point: zero,
            rhs_point: zero,
            factor: one,
            acc_in: record.value,
            acc_out: record.value,
        });
    }
    rows
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
