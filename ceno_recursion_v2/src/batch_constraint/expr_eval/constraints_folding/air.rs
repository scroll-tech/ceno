use std::borrow::Borrow;

use openvm_circuit_primitives::{SubAir, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    batch_constraint::bus::{
        ConstraintsFoldingBus, ConstraintsFoldingMessage, EqNOuterBus, EqNOuterMessage,
        ExpressionClaimBus, ExpressionClaimMessage,
    },
    bus::{NLiftBus, NLiftMessage, TranscriptBus},
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{ext_field_add, ext_field_multiply, ext_field_multiply_scalar},
};

#[derive(AlignedBorrow, Copy, Clone)]
#[repr(C)]
pub struct ConstraintsFoldingCols<T> {
    pub is_valid: T,
    pub is_first: T,
    pub proof_idx: T,

    pub air_idx: T,
    pub sort_idx: T,
    pub constraint_idx: T,
    pub n_lift: T,

    pub lambda_tidx: T,
    pub lambda: [T; D_EF],

    pub value: [T; D_EF],
    pub cur_sum: [T; D_EF],
    pub eq_n: [T; D_EF],

    pub is_first_in_air: T,
}

pub struct ConstraintsFoldingAir {
    pub transcript_bus: TranscriptBus,
    pub constraint_bus: ConstraintsFoldingBus,
    pub expression_claim_bus: ExpressionClaimBus,
    pub eq_n_outer_bus: EqNOuterBus,
    pub n_lift_bus: NLiftBus,
}

impl<F> BaseAirWithPublicValues<F> for ConstraintsFoldingAir {}
impl<F> PartitionedBaseAir<F> for ConstraintsFoldingAir {}

impl<F> BaseAir<F> for ConstraintsFoldingAir {
    fn width(&self) -> usize {
        ConstraintsFoldingCols::<F>::width()
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ConstraintsFoldingAir
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
    /* debug block: Step 1 placeholder - all constraints deferred pending trace implementation */
    #[allow(unused_variables)]
    let _ = &builder;
    }
}
