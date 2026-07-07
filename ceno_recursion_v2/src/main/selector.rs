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
        AirPresenceBus, AirPresenceBusMessage, EccRtBus, EccRtMessage, ForkedTranscriptBus,
        ForkedTranscriptBusMessage, MainEvalBus, MainEvalMessage, MainGlobalPointBus,
        MainGlobalPointMessage, MainSelectorPointBus, MainSelectorPointMessage,
        MainSelectorResultBus, MainSelectorResultMessage, MainSelectorShapeBus,
        MainSelectorShapeMessage, MainSelectorSparseIndexShapeBus,
        MainSelectorSparseIndexShapeMessage, TowerMainPointBus, TowerMainPointMessage,
    },
    system::{
        MainSelectorEvalRecord, MainSelectorKind, MainSelectorPointDeriveKind,
        MainSelectorPointRecord, MainSelectorPointSourceKind, RecursionField,
    },
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
const STEP_EQ_LTE: usize = 7;

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainSelectorFormulaCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub tower_idx: T,
    pub air_idx: T,
    pub selector_idx: T,
    pub eval_idx: T,
    pub kind: T,
    pub source_kind: T,
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
    pub is_eq_lte_step: T,
    pub is_first_eq_lte_step: T,
    pub is_last_eq_lte_step: T,
    pub eq_lte_output_to_value: T,
    pub eq_lte_output_to_acc_in: T,
    pub eq_lte_output_to_factor: T,
    pub eq_lte_output_to_neg_factor: T,
    pub eq_lte_value_is_zero: T,
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
    pub aux: [T; D_EF],
    pub aux2: [T; D_EF],
    pub aux3: [T; D_EF],
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

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainSelectorPointCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub tower_idx: T,
    pub air_idx: T,
    pub selector_idx: T,
    pub round_idx: T,
    pub source_kind: T,
    pub is_tower_main: T,
    pub is_rotation_left: T,
    pub is_rotation_right: T,
    pub is_rotation_origin: T,
    pub is_ecc_xy: T,
    pub is_ecc_slope: T,
    pub is_ecc_x3y3: T,
    pub lookup_count: T,
    pub fork_id: T,
    pub has_transcript: T,
    pub transcript_tidx: T,
    pub has_ecc_rt: T,
    pub has_source: T,
    pub source_selector_idx: T,
    pub source_source_kind: T,
    pub source_round_idx: T,
    pub source_value: [T; D_EF],
    pub derive_identity: T,
    pub derive_one_minus: T,
    pub derive_zero: T,
    pub derive_one: T,
    pub value: [T; D_EF],
}

pub struct MainSelectorFormulaAir {
    pub global_point_bus: MainGlobalPointBus,
    pub selector_point_bus: MainSelectorPointBus,
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
        builder.assert_bool(local.is_eq_lte_step);
        builder.assert_bool(local.is_first_eq_lte_step);
        builder.assert_bool(local.is_last_eq_lte_step);
        builder.assert_bool(local.eq_lte_output_to_value);
        builder.assert_bool(local.eq_lte_output_to_acc_in);
        builder.assert_bool(local.eq_lte_output_to_factor);
        builder.assert_bool(local.eq_lte_output_to_neg_factor);
        builder.assert_bool(local.eq_lte_value_is_zero);
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
                + local.is_quark_step
                + local.is_eq_lte_step,
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
                + local.is_quark_step * AB::Expr::from_usize(STEP_QUARK)
                + local.is_eq_lte_step * AB::Expr::from_usize(STEP_EQ_LTE),
        );
        builder
            .when(local.carry_accumulator)
            .assert_one(local.is_enabled);
        builder
            .when(local.is_eq_lte_step)
            .assert_one(local.is_enabled);
        builder.when(local.carry_accumulator).assert_one(
            local.is_eq_product_step
                + local.is_accumulate_step
                + local.is_multiply_step
                + local.is_quark_step,
        );
        builder
            .when(local.is_first_eq_lte_step)
            .assert_one(local.is_eq_lte_step);
        builder
            .when(local.is_last_eq_lte_step)
            .assert_one(local.is_eq_lte_step);
        builder.when(local.is_eq_lte_step).assert_one(
            local.eq_lte_output_to_value
                + local.eq_lte_output_to_acc_in
                + local.eq_lte_output_to_factor
                + local.eq_lte_output_to_neg_factor
                + (AB::Expr::ONE - local.is_last_eq_lte_step),
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
                point_source: local.source_kind.into(),
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
                * (local.is_eq_product_step * local.point_active
                    + local.is_quark_step
                    + local.is_eq_lte_step),
        );
        self.selector_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainSelectorPointMessage {
                idx: local.idx.into(),
                air_idx: local.air_idx.into(),
                selector_idx: local.selector_idx.into(),
                source_kind: local.source_kind.into(),
                round_idx: local.round_idx.into(),
                value: local.rhs_point.map(Into::into),
            },
            local.is_enabled
                * (local.is_eq_product_step * local.point_active
                    + local.is_quark_step
                    + local.is_eq_lte_step),
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
        let ordered_sparse_tail_len = local.ctx_num_vars - local.ordered_sparse_num_vars;
        let ordered_sparse_tail_is_zero = local.aux[0];
        let ordered_sparse_tail_inverse = local.aux2[0];
        builder
            .when(local.is_enabled * local.is_multiply_step * local.is_ordered_sparse)
            .assert_zero(
                ordered_sparse_tail_is_zero * (ordered_sparse_tail_is_zero - AB::Expr::ONE),
            );
        builder
            .when(local.is_enabled * local.is_multiply_step * local.is_ordered_sparse)
            .assert_zero(ordered_sparse_tail_is_zero * ordered_sparse_tail_len.clone());
        builder
            .when(local.is_enabled * local.is_multiply_step * local.is_ordered_sparse)
            .assert_eq(
                ordered_sparse_tail_len * ordered_sparse_tail_inverse,
                AB::Expr::ONE - ordered_sparse_tail_is_zero,
            );
        assert_array_eq(
            &mut builder.when(
                local.is_enabled
                    * local.is_multiply_step
                    * local.is_ordered_sparse
                    * ordered_sparse_tail_is_zero,
            ),
            local.factor,
            ext_one::<AB::Expr>(),
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
        let quark_prefix_is_zero = local.aux[0];
        let quark_prefix_inverse = local.aux2[0];
        builder
            .when(local.is_enabled * local.is_quark_step)
            .assert_zero(quark_prefix_is_zero * (quark_prefix_is_zero - AB::Expr::ONE));
        builder
            .when(local.is_enabled * local.is_quark_step)
            .assert_zero(quark_prefix_is_zero * local.sparse_index_bits_value);
        builder
            .when(local.is_enabled * local.is_quark_step)
            .assert_eq(
                local.sparse_index_bits_value * quark_prefix_inverse,
                AB::Expr::ONE - quark_prefix_is_zero,
            );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_quark_step * quark_prefix_is_zero),
            local.factor,
            [AB::Expr::ZERO; D_EF],
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_quark_step),
            local.acc_in,
            [AB::Expr::ZERO; D_EF],
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_quark_step),
            local.factor,
            [
                local.sparse_index_bits_value.into(),
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
            ],
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
        builder
            .when(local.is_eq_lte_step)
            .assert_zero(local.point_active * (local.point_active - AB::Expr::ONE));
        builder.when(local.is_eq_lte_step).assert_eq(
            local.sparse_index,
            local.sparse_index_bits_value * AB::Expr::from_usize(2) + local.point_active,
        );
        builder
            .when(local.is_first_eq_lte_step)
            .assert_zero(local.step_idx);
        builder
            .when(local.is_first_eq_lte_step)
            .assert_zero(local.sparse_index_bits_value);
        assert_array_eq(
            &mut builder.when(local.is_first_eq_lte_step),
            local.acc_in,
            ext_one::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_first_eq_lte_step),
            local.aux,
            [AB::Expr::ZERO; D_EF],
        );
        assert_array_eq(
            &mut builder.when(local.eq_lte_value_is_zero),
            local.value,
            [AB::Expr::ZERO; D_EF],
        );
        builder
            .when(local.is_last_eq_lte_step)
            .assert_eq(local.sparse_index, local.sparse_pos);
        let eq_lte_same_one = ext_mul::<AB::Expr>(
            local.rhs_point.clone().map(Into::into),
            local.lhs_point.clone().map(Into::into),
        );
        let eq_lte_same_zero = ext_mul::<AB::Expr>(
            ext_one_minus(local.rhs_point.clone().map(Into::into)),
            ext_one_minus(local.lhs_point.clone().map(Into::into)),
        );
        let eq_lte_any = ext_add::<AB::Expr>(eq_lte_same_one.clone(), eq_lte_same_zero.clone());
        let eq_lte_equal_choice = ext_add::<AB::Expr>(
            ext_mul_scalar::<AB::Expr>(eq_lte_same_one, local.point_active.into()),
            ext_mul_scalar::<AB::Expr>(
                eq_lte_same_zero.clone(),
                AB::Expr::ONE - local.point_active,
            ),
        );
        assert_array_eq(
            &mut builder.when(local.is_eq_lte_step),
            local.aux3,
            eq_lte_equal_choice,
        );
        let eq_lte_prefix_out = ext_mul::<AB::Expr>(
            local.acc_in.clone().map(Into::into),
            local.aux3.clone().map(Into::into),
        );
        let eq_lte_less_from_prior =
            ext_mul::<AB::Expr>(local.aux.clone().map(Into::into), eq_lte_any);
        let eq_lte_less_from_equal_prefix_unmasked =
            ext_mul::<AB::Expr>(local.acc_in.clone().map(Into::into), eq_lte_same_zero);
        assert_array_eq(
            &mut builder.when(local.is_eq_lte_step),
            local.aux2,
            eq_lte_less_from_equal_prefix_unmasked,
        );
        let eq_lte_less_from_equal_prefix =
            ext_mul_scalar::<AB::Expr>(local.aux2.clone().map(Into::into), local.point_active);
        let eq_lte_less_out =
            ext_add::<AB::Expr>(eq_lte_less_from_prior, eq_lte_less_from_equal_prefix);
        assert_array_eq(
            &mut builder.when(local.is_eq_lte_step),
            local.factor,
            eq_lte_less_out.clone(),
        );
        assert_array_eq(
            &mut builder.when(local.is_eq_lte_step * (AB::Expr::ONE - local.is_last_eq_lte_step)),
            local.acc_out,
            eq_lte_prefix_out.clone(),
        );
        assert_array_eq(
            &mut builder.when(local.is_last_eq_lte_step),
            local.acc_out,
            ext_add::<AB::Expr>(eq_lte_prefix_out, eq_lte_less_out),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_final_step),
            local.acc_out,
            local.value.clone().map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_final_step),
            local.acc_in,
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
            .when(local.is_eq_lte_step * next.is_eq_lte_step)
            .assert_eq(next.step_idx, local.step_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(local.is_eq_lte_step * next.is_eq_lte_step)
            .assert_eq(next.sparse_pos, local.sparse_pos);
        builder
            .when_transition()
            .when(local.is_eq_lte_step * next.is_eq_lte_step)
            .assert_eq(next.sparse_index_bits_value, local.sparse_index);
        builder
            .when_transition()
            .when(local.is_eq_lte_step * next.is_eq_lte_step)
            .assert_eq(next.round_idx + AB::Expr::ONE, local.round_idx);
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * next.is_eq_lte_step),
            local.acc_out,
            next.acc_in,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * next.is_eq_lte_step),
            local.factor,
            next.aux,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * next.is_eq_lte_step),
            local.value,
            next.value,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * local.eq_lte_output_to_value),
            local.acc_out,
            next.value,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * local.eq_lte_output_to_acc_in),
            local.acc_out,
            next.acc_in,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * local.eq_lte_output_to_factor),
            local.value,
            next.acc_in,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * local.eq_lte_output_to_factor),
            local.acc_out,
            next.factor,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * local.eq_lte_output_to_neg_factor),
            local.value,
            next.acc_in,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_eq_lte_step * local.eq_lte_output_to_neg_factor),
            local.acc_out.map(|value| -value.into()),
            next.factor,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_accumulate_step * next.is_eq_lte_step * local.is_ordered_sparse),
            local.acc_out,
            next.value,
        );
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_quark_step * next.is_eq_lte_step),
            local.acc_out,
            next.value,
        );
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

pub struct MainSelectorPointAir {
    pub selector_point_bus: MainSelectorPointBus,
    pub tower_point_bus: TowerMainPointBus,
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub ecc_rt_bus: EccRtBus,
}

impl<F: Field> BaseAir<F> for MainSelectorPointAir {
    fn width(&self) -> usize {
        MainSelectorPointCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainSelectorPointAir {}
impl<F: Field> PartitionedBaseAir<F> for MainSelectorPointAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainSelectorPointAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &MainSelectorPointCols<AB::Var> = (*local_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_tower_main);
        builder.assert_bool(local.is_rotation_left);
        builder.assert_bool(local.is_rotation_right);
        builder.assert_bool(local.is_rotation_origin);
        builder.assert_bool(local.is_ecc_xy);
        builder.assert_bool(local.is_ecc_slope);
        builder.assert_bool(local.is_ecc_x3y3);
        builder.assert_bool(local.has_transcript);
        builder.assert_bool(local.has_ecc_rt);
        builder.assert_bool(local.has_source);
        builder.assert_bool(local.derive_identity);
        builder.assert_bool(local.derive_one_minus);
        builder.assert_bool(local.derive_zero);
        builder.assert_bool(local.derive_one);
        builder.when(local.is_enabled).assert_one(
            local.is_tower_main
                + local.is_rotation_left
                + local.is_rotation_right
                + local.is_rotation_origin
                + local.is_ecc_xy
                + local.is_ecc_slope
                + local.is_ecc_x3y3,
        );
        builder.when(local.is_enabled).assert_eq(
            local.source_kind,
            local.is_rotation_left * AB::Expr::from_usize(1)
                + local.is_rotation_right * AB::Expr::from_usize(2)
                + local.is_rotation_origin * AB::Expr::from_usize(3)
                + local.is_ecc_xy * AB::Expr::from_usize(4)
                + local.is_ecc_slope * AB::Expr::from_usize(5)
                + local.is_ecc_x3y3 * AB::Expr::from_usize(6),
        );
        builder
            .when(local.has_transcript)
            .assert_one(local.is_rotation_origin + local.is_ecc_xy);
        builder.when(local.has_ecc_rt).assert_one(local.is_ecc_x3y3);
        builder.when(local.has_source).assert_one(
            local.is_rotation_left
                + local.is_rotation_right
                + local.is_ecc_xy
                + local.is_ecc_slope
                + local.is_ecc_x3y3,
        );
        builder
            .when(local.is_tower_main + local.is_rotation_origin)
            .assert_zero(local.has_source);
        builder.when(local.has_ecc_rt).assert_zero(local.has_source);
        builder
            .when(
                local.is_tower_main
                    + local.is_rotation_left
                    + local.is_rotation_right
                    + local.is_ecc_slope
                    + local.is_ecc_x3y3,
            )
            .assert_zero(local.has_transcript);
        builder
            .when(
                local.is_tower_main
                    + local.is_rotation_left
                    + local.is_rotation_right
                    + local.is_rotation_origin
                    + local.is_ecc_xy
                    + local.is_ecc_slope,
            )
            .assert_zero(local.has_ecc_rt);
        builder.when(local.is_enabled).assert_one(
            local.derive_identity + local.derive_one_minus + local.derive_zero + local.derive_one,
        );
        self.tower_point_bus.lookup_key(
            builder,
            local.proof_idx,
            TowerMainPointMessage {
                idx: local.tower_idx.into(),
                round_idx: local.round_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.is_tower_main,
        );
        self.selector_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainSelectorPointMessage {
                idx: local.idx.into(),
                air_idx: local.air_idx.into(),
                selector_idx: local.source_selector_idx.into(),
                source_kind: local.source_source_kind.into(),
                round_idx: local.source_round_idx.into(),
                value: local.source_value.map(Into::into),
            },
            local.is_enabled * local.has_source,
        );
        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.transcript_tidx + AB::Expr::from_usize(i),
                    value: local.value[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled * local.has_transcript,
            );
        }
        self.ecc_rt_bus.lookup_key(
            builder,
            local.proof_idx,
            EccRtMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.has_ecc_rt,
        );
        for i in 0..D_EF {
            let expected = local.derive_identity * local.source_value[i]
                + local.derive_one_minus * (AB::Expr::ONE - local.source_value[i])
                + local.derive_one;
            builder
                .when(local.is_enabled * (local.has_source + local.derive_zero + local.derive_one))
                .assert_eq(local.value[i], expected);
        }
        self.selector_point_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            MainSelectorPointMessage {
                idx: local.idx.into(),
                air_idx: local.air_idx.into(),
                selector_idx: local.selector_idx.into(),
                source_kind: local.source_kind.into(),
                round_idx: local.round_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
    }
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

fn ext_mul_scalar<FA>(x: [FA; D_EF], y: impl Into<FA>) -> [FA; D_EF]
where
    FA: PrimeCharacteristicRing,
{
    let [x0, x1, x2, x3] = x;
    let y = y.into();
    [x0 * y.clone(), x1 * y.clone(), x2 * y.clone(), x3 * y]
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
pub struct MainSelectorPointTraceGenerator;

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

impl RowMajorChip<F> for MainSelectorPointTraceGenerator {
    type Ctx<'a> = &'a [MainSelectorPointRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        generate_selector_trace(records, required_height, fill_point_cols)
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

impl SelectorColumnAccess<F> for MainSelectorPointCols<F> {
    fn width() -> usize {
        MainSelectorPointCols::<F>::width()
    }

    fn from_bytes(slice: &mut [F]) -> &mut Self {
        slice.borrow_mut()
    }
}

fn fill_point_cols(record: &MainSelectorPointRecord, cols: &mut MainSelectorPointCols<F>) {
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.tower_idx = F::from_usize(record.tower_idx);
    cols.air_idx = F::from_usize(record.air_idx);
    cols.selector_idx = F::from_usize(record.selector_idx);
    cols.round_idx = F::from_usize(record.round_idx);
    cols.source_kind = F::from_usize(selector_point_source_code(record.source_kind));
    cols.is_tower_main = F::from_bool(record.source_kind == MainSelectorPointSourceKind::TowerMain);
    cols.is_rotation_left =
        F::from_bool(record.source_kind == MainSelectorPointSourceKind::RotationLeft);
    cols.is_rotation_right =
        F::from_bool(record.source_kind == MainSelectorPointSourceKind::RotationRight);
    cols.is_rotation_origin =
        F::from_bool(record.source_kind == MainSelectorPointSourceKind::RotationOrigin);
    cols.is_ecc_xy = F::from_bool(record.source_kind == MainSelectorPointSourceKind::EccXY);
    cols.is_ecc_slope = F::from_bool(record.source_kind == MainSelectorPointSourceKind::EccSlope);
    cols.is_ecc_x3y3 = F::from_bool(record.source_kind == MainSelectorPointSourceKind::EccX3Y3);
    cols.lookup_count = F::from_usize(record.lookup_count);
    cols.fork_id = F::from_usize(record.fork_id);
    cols.has_transcript = F::from_bool(record.has_transcript);
    cols.transcript_tidx = F::from_usize(record.transcript_tidx);
    cols.has_ecc_rt = F::from_bool(record.has_ecc_rt);
    cols.has_source = F::from_bool(record.has_source);
    cols.source_selector_idx = F::from_usize(record.source_selector_idx);
    cols.source_source_kind = F::from_usize(selector_point_source_code(record.source_source_kind));
    cols.source_round_idx = F::from_usize(record.source_round_idx);
    cols.source_value = record
        .source_value
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
    cols.derive_identity =
        F::from_bool(record.derive_kind == MainSelectorPointDeriveKind::Identity);
    cols.derive_one_minus =
        F::from_bool(record.derive_kind == MainSelectorPointDeriveKind::OneMinus);
    cols.derive_zero = F::from_bool(record.derive_kind == MainSelectorPointDeriveKind::Zero);
    cols.derive_one = F::from_bool(record.derive_kind == MainSelectorPointDeriveKind::One);
    cols.value = record
        .value
        .as_basis_coefficients_slice()
        .try_into()
        .unwrap();
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
    eq_lte_is_first: bool,
    eq_lte_is_last: bool,
    eq_lte_output_to_value: bool,
    eq_lte_output_to_acc_in: bool,
    eq_lte_output_to_factor: bool,
    eq_lte_output_to_neg_factor: bool,
    eq_lte_value_is_zero: bool,
    quark_is_first: bool,
    quark_is_last: bool,
    point_active: bool,
    lhs_point: RecursionField,
    rhs_point: RecursionField,
    factor: RecursionField,
    acc_in: RecursionField,
    acc_out: RecursionField,
    aux: RecursionField,
    aux2: RecursionField,
    aux3: RecursionField,
    value: RecursionField,
}

#[derive(Clone, Copy)]
enum EqLteOutput {
    ToValue,
    ToAccIn,
    ToFactor,
    ToNegFactor,
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
            eq_lte_is_first: false,
            eq_lte_is_last: false,
            eq_lte_output_to_value: false,
            eq_lte_output_to_acc_in: false,
            eq_lte_output_to_factor: false,
            eq_lte_output_to_neg_factor: false,
            eq_lte_value_is_zero: false,
            quark_is_first: false,
            quark_is_last: false,
            point_active: false,
            lhs_point: zero,
            rhs_point: zero,
            factor: one,
            acc_in: zero,
            acc_out: zero,
            aux: zero,
            aux2: zero,
            aux3: zero,
            value: record.value,
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
                eq_lte_is_first: false,
                eq_lte_is_last: false,
                eq_lte_output_to_value: false,
                eq_lte_output_to_acc_in: false,
                eq_lte_output_to_factor: false,
                eq_lte_output_to_neg_factor: false,
                eq_lte_value_is_zero: false,
                quark_is_first: false,
                quark_is_last: false,
                point_active: false,
                lhs_point: zero,
                rhs_point: zero,
                factor: one,
                acc_in: zero,
                acc_out: zero,
                aux: zero,
                aux2: zero,
                aux3: zero,
                value: record.value,
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
                if record.ctx_offset == 0 {
                    let _ = push_eq_lte_rows(
                        &mut rows,
                        record,
                        0,
                        record.ctx_num_vars,
                        end - 1,
                        zero,
                        true,
                        EqLteOutput::ToAccIn,
                    );
                } else {
                    let _ = push_eq_lte_rows(
                        &mut rows,
                        record,
                        0,
                        record.ctx_num_vars,
                        end - 1,
                        zero,
                        true,
                        EqLteOutput::ToValue,
                    );
                    let _ = push_eq_lte_rows(
                        &mut rows,
                        record,
                        0,
                        record.ctx_num_vars,
                        record.ctx_offset - 1,
                        end_eval,
                        false,
                        EqLteOutput::ToNegFactor,
                    );
                }
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
                let _ = push_eq_lte_rows(
                    &mut rows,
                    record,
                    subgroup_vars,
                    record.ctx_num_vars - subgroup_vars,
                    record.ctx_num_instances - 1,
                    subgroup_acc,
                    record.sparse_indices.is_empty(),
                    EqLteOutput::ToFactor,
                );
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
            eq_lte_is_first: false,
            eq_lte_is_last: false,
            eq_lte_output_to_value: false,
            eq_lte_output_to_acc_in: false,
            eq_lte_output_to_factor: false,
            eq_lte_output_to_neg_factor: false,
            eq_lte_value_is_zero: false,
            quark_is_first: false,
            quark_is_last: false,
            point_active: false,
            lhs_point: zero,
            rhs_point: zero,
            factor: one,
            acc_in: computed_value,
            acc_out: computed_value,
            aux: zero,
            aux2: zero,
            aux3: zero,
            value: record.value,
        });
    }
    rows
}

pub(crate) fn selector_formula_global_point_lookups(
    records: &[MainSelectorEvalRecord],
) -> Vec<(usize, usize)> {
    build_formula_rows(records)
        .into_iter()
        .filter(|row| {
            row.record.has_eval
                && ((row.step_kind == STEP_EQ_PRODUCT && row.point_active)
                    || row.step_kind == STEP_QUARK
                    || row.step_kind == STEP_EQ_LTE)
        })
        .map(|row| (row.record.proof_idx, row.round_idx))
        .collect()
}

pub(crate) fn selector_formula_point_lookup_counts(
    records: &[MainSelectorEvalRecord],
) -> std::collections::BTreeMap<(usize, usize, usize, usize, usize), usize> {
    let mut counts = std::collections::BTreeMap::new();
    for row in build_formula_rows(records).into_iter().filter(|row| {
        row.record.has_eval
            && ((row.step_kind == STEP_EQ_PRODUCT && row.point_active)
                || row.step_kind == STEP_QUARK
                || row.step_kind == STEP_EQ_LTE)
    }) {
        *counts
            .entry((
                row.record.proof_idx,
                row.record.idx,
                row.record.air_idx,
                row.record.selector_idx,
                row.round_idx,
            ))
            .or_default() += 1;
    }
    counts
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
        eq_lte_is_first: false,
        eq_lte_is_last: false,
        eq_lte_output_to_value: false,
        eq_lte_output_to_acc_in: false,
        eq_lte_output_to_factor: false,
        eq_lte_output_to_neg_factor: false,
        eq_lte_value_is_zero: false,
        quark_is_first: false,
        quark_is_last: false,
        point_active: false,
        lhs_point: RecursionField::ZERO,
        rhs_point: RecursionField::ZERO,
        factor,
        acc_in,
        acc_out,
        aux: RecursionField::ZERO,
        aux2: RecursionField::ZERO,
        aux3: RecursionField::ZERO,
        value: record.value,
    }
}

fn multiply_row(
    record: &MainSelectorEvalRecord,
    step_idx: usize,
    acc_in: RecursionField,
    factor: RecursionField,
    acc_out: RecursionField,
) -> FormulaRow<'_> {
    let ordered_sparse_tail_len = record
        .ctx_num_vars
        .saturating_sub(record.ordered_sparse_num_vars);
    FormulaRow {
        record,
        step_kind: STEP_MULTIPLY,
        step_idx,
        round_idx: 0,
        sparse_pos: step_idx,
        sparse_index: 0,
        sparse_index_bits_value: 0,
        eq_lte_is_first: false,
        eq_lte_is_last: false,
        eq_lte_output_to_value: false,
        eq_lte_output_to_acc_in: false,
        eq_lte_output_to_factor: false,
        eq_lte_output_to_neg_factor: false,
        eq_lte_value_is_zero: false,
        quark_is_first: false,
        quark_is_last: false,
        point_active: false,
        lhs_point: RecursionField::ZERO,
        rhs_point: RecursionField::ZERO,
        factor,
        acc_in,
        acc_out,
        aux: RecursionField::from_usize(usize::from(
            record.kind == MainSelectorKind::OrderedSparse && ordered_sparse_tail_len == 0,
        )),
        aux2: if record.kind == MainSelectorKind::OrderedSparse && ordered_sparse_tail_len != 0 {
            RecursionField::from_usize(ordered_sparse_tail_len).inverse()
        } else {
            RecursionField::ZERO
        },
        aux3: RecursionField::ZERO,
        value: record.value,
    }
}

fn push_eq_lte_rows<'a>(
    rows: &mut Vec<FormulaRow<'a>>,
    record: &'a MainSelectorEvalRecord,
    point_offset: usize,
    len: usize,
    max_idx: usize,
    carried_value: RecursionField,
    carried_value_is_zero: bool,
    output: EqLteOutput,
) -> RecursionField {
    if len == 0 {
        return RecursionField::ONE;
    }

    let zero = RecursionField::ZERO;
    let one = RecursionField::ONE;
    let mut eq_prefix = one;
    let mut less_sum = zero;
    let mut bound_prefix = 0usize;
    let mut output_value = one;
    for (step_idx, bit_idx) in (0..len).rev().enumerate() {
        let bit = (max_idx >> bit_idx) & 1;
        let lhs = record.in_point[point_offset + bit_idx];
        let rhs = record.out_point[point_offset + bit_idx];
        let same_one = rhs * lhs;
        let same_zero = (one - rhs) * (one - lhs);
        let any = same_one + same_zero;
        let equal_choice = if bit == 1 { same_one } else { same_zero };
        let less_from_equal_prefix = if bit == 1 {
            eq_prefix * same_zero
        } else {
            zero
        };
        let less_from_equal_prefix_unmasked = eq_prefix * same_zero;
        let next_less_sum = less_sum * any + less_from_equal_prefix;
        let next_eq_prefix = eq_prefix * equal_choice;
        let is_last = step_idx + 1 == len;
        output_value = next_eq_prefix + next_less_sum;
        bound_prefix = bound_prefix * 2 + bit;
        rows.push(FormulaRow {
            record,
            step_kind: STEP_EQ_LTE,
            step_idx,
            round_idx: point_offset + bit_idx,
            sparse_pos: max_idx,
            sparse_index: bound_prefix,
            sparse_index_bits_value: (bound_prefix - bit) / 2,
            eq_lte_is_first: step_idx == 0,
            eq_lte_is_last: is_last,
            eq_lte_output_to_value: is_last && matches!(output, EqLteOutput::ToValue),
            eq_lte_output_to_acc_in: is_last && matches!(output, EqLteOutput::ToAccIn),
            eq_lte_output_to_factor: is_last && matches!(output, EqLteOutput::ToFactor),
            eq_lte_output_to_neg_factor: is_last && matches!(output, EqLteOutput::ToNegFactor),
            eq_lte_value_is_zero: step_idx == 0 && carried_value_is_zero,
            quark_is_first: false,
            quark_is_last: false,
            point_active: bit == 1,
            lhs_point: lhs,
            rhs_point: rhs,
            factor: next_less_sum,
            acc_in: eq_prefix,
            acc_out: if is_last {
                output_value
            } else {
                next_eq_prefix
            },
            aux: less_sum,
            aux2: less_from_equal_prefix_unmasked,
            aux3: equal_choice,
            value: carried_value,
        });
        eq_prefix = next_eq_prefix;
        less_sum = next_less_sum;
    }
    output_value
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
        let mut factor = if prefix_count == 0 {
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
        if prefix_count > 0 && i > 0 {
            factor = push_eq_lte_rows(
                rows,
                record,
                0,
                i,
                prefix_count - 1,
                acc,
                false,
                EqLteOutput::ToFactor,
            );
        }
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
            eq_lte_is_first: false,
            eq_lte_is_last: false,
            eq_lte_output_to_value: false,
            eq_lte_output_to_acc_in: false,
            eq_lte_output_to_factor: false,
            eq_lte_output_to_neg_factor: false,
            eq_lte_value_is_zero: false,
            quark_is_first: i == 0,
            quark_is_last: i + 1 == layer_ns.len(),
            point_active: parity == 1,
            lhs_point: lhs,
            rhs_point: rhs,
            factor,
            acc_in,
            acc_out: acc,
            aux: RecursionField::from_usize(usize::from(prefix_count == 0)),
            aux2: if prefix_count == 0 {
                zero
            } else {
                RecursionField::from_usize(prefix_count).inverse()
            },
            aux3: zero,
            value: record.value,
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
            eq_lte_is_first: false,
            eq_lte_is_last: false,
            eq_lte_output_to_value: false,
            eq_lte_output_to_acc_in: false,
            eq_lte_output_to_factor: false,
            eq_lte_output_to_neg_factor: false,
            eq_lte_value_is_zero: false,
            quark_is_first: false,
            quark_is_last: false,
            point_active,
            lhs_point: lhs,
            rhs_point: rhs,
            factor,
            acc_in,
            acc_out: acc,
            aux: zero,
            aux2: zero,
            aux3: zero,
            value: record.value,
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
    cols.source_kind = F::from_usize(selector_point_source_code(record.point_source));
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
    cols.is_eq_lte_step = F::from_bool(row.step_kind == STEP_EQ_LTE);
    cols.is_first_eq_lte_step = F::from_bool(row.eq_lte_is_first);
    cols.is_last_eq_lte_step = F::from_bool(row.eq_lte_is_last);
    cols.eq_lte_output_to_value = F::from_bool(row.eq_lte_output_to_value);
    cols.eq_lte_output_to_acc_in = F::from_bool(row.eq_lte_output_to_acc_in);
    cols.eq_lte_output_to_factor = F::from_bool(row.eq_lte_output_to_factor);
    cols.eq_lte_output_to_neg_factor = F::from_bool(row.eq_lte_output_to_neg_factor);
    cols.eq_lte_value_is_zero = F::from_bool(row.eq_lte_value_is_zero);
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
    cols.aux = row.aux.as_basis_coefficients_slice().try_into().unwrap();
    cols.aux2 = row.aux2.as_basis_coefficients_slice().try_into().unwrap();
    cols.aux3 = row.aux3.as_basis_coefficients_slice().try_into().unwrap();
    cols.value = row.value.as_basis_coefficients_slice().try_into().unwrap();
}

fn selector_kind_code(kind: MainSelectorKind) -> usize {
    match kind {
        MainSelectorKind::Whole => 0,
        MainSelectorKind::Prefix => 1,
        MainSelectorKind::OrderedSparse => 2,
        MainSelectorKind::QuarkBinaryTreeLessThan => 3,
    }
}

pub(crate) fn selector_point_source_code(kind: MainSelectorPointSourceKind) -> usize {
    match kind {
        MainSelectorPointSourceKind::TowerMain => 0,
        MainSelectorPointSourceKind::RotationLeft => 1,
        MainSelectorPointSourceKind::RotationRight => 2,
        MainSelectorPointSourceKind::RotationOrigin => 3,
        MainSelectorPointSourceKind::EccXY => 4,
        MainSelectorPointSourceKind::EccSlope => 5,
        MainSelectorPointSourceKind::EccX3Y3 => 6,
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
            tower_idx: 7,
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
            point_source: MainSelectorPointSourceKind::TowerMain,
            value,
            ..Default::default()
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
            tower_idx: 7,
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
            point_source: MainSelectorPointSourceKind::TowerMain,
            value: RecursionField::ZERO,
            ..Default::default()
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
