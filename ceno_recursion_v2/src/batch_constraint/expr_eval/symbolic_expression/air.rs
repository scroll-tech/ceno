use core::array;
use std::borrow::Borrow;

use openvm_circuit_primitives::{encoder::Encoder, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, air_builders::PartitionedAirBuilder,
    interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::EnumIter;

use crate::{
    batch_constraint::bus::{
        ConstraintsFoldingBus, ConstraintsFoldingMessage, InteractionsFoldingBus,
        InteractionsFoldingMessage, SymbolicExpressionBus, SymbolicExpressionMessage,
    },
    bus::{
        AirPresenceBus, AirPresenceBusMessage, AirShapeBus, AirShapeBusMessage, ColumnClaimsBus,
        ColumnClaimsMessage, HyperdimBus, HyperdimBusMessage, PublicValuesBus,
        PublicValuesBusMessage, SelHypercubeBus, SelHypercubeBusMessage, SelUniBus,
        SelUniBusMessage,
    },
    proof_shape::bus::AirShapeProperty,
    utils::{
        base_to_ext, ext_field_add, ext_field_multiply, ext_field_multiply_scalar,
        ext_field_subtract, scalar_subtract_ext_field,
    },
};

pub const NUM_FLAGS: usize = 5;
pub const ENCODER_MAX_DEGREE: u32 = 2;

#[derive(Debug, Clone, Copy, EnumIter, EnumCount)]
pub enum NodeKind {
    WitIn = 0,
    StructuralWitIn = 1,
    Fixed = 2,
    Instance = 3,
    SelIsFirst = 4,
    SelIsLast = 5,
    SelIsTransition = 6,
    Constant = 7,
    Add = 8,
    Sub = 9,
    Neg = 10,
    Mul = 11,
    InteractionMult = 12,
    InteractionMsgComp = 13,
    InteractionBusIndex = 14,
}

impl Default for NodeKind {
    fn default() -> Self {
        NodeKind::WitIn
    }
}

#[derive(AlignedBorrow, Copy, Clone)]
#[repr(C)]
pub struct CachedSymbolicExpressionColumns<T> {
    pub flags: [T; NUM_FLAGS],
    pub air_idx: T,
    pub node_or_interaction_idx: T,
    pub attrs: [T; 3],
    pub fanout: T,
    pub is_constraint: T,
    pub constraint_idx: T,
}

#[derive(AlignedBorrow, Copy, Clone)]
#[repr(C)]
pub struct SingleMainSymbolicExpressionColumns<T> {
    /// 0 = absent proof, 1 = proof present but air absent, 2 = proof+air present.
    pub slot_state: T,
    pub args: [T; 2 * D_EF],
    pub sort_idx: T,
    pub n_abs: T,
    pub is_n_neg: T,
}

pub struct SymbolicExpressionAir {
    pub expr_bus: SymbolicExpressionBus,
    pub hyperdim_bus: HyperdimBus,
    pub air_shape_bus: AirShapeBus,
    pub air_presence_bus: AirPresenceBus,
    pub column_claims_bus: ColumnClaimsBus,
    pub interactions_folding_bus: InteractionsFoldingBus,
    pub constraints_folding_bus: ConstraintsFoldingBus,
    pub public_values_bus: PublicValuesBus,
    pub sel_hypercube_bus: SelHypercubeBus,
    pub sel_uni_bus: SelUniBus,

    pub cnt_proofs: usize,
}

impl<F: Field> BaseAirWithPublicValues<F> for SymbolicExpressionAir {}

impl<F: Field> PartitionedBaseAir<F> for SymbolicExpressionAir {
    fn cached_main_widths(&self) -> Vec<usize> {
        vec![CachedSymbolicExpressionColumns::<F>::width()]
    }

    fn common_main_width(&self) -> usize {
        SingleMainSymbolicExpressionColumns::<F>::width() * self.cnt_proofs
    }
}

impl<F: Field> BaseAir<F> for SymbolicExpressionAir {
    fn width(&self) -> usize {
        CachedSymbolicExpressionColumns::<F>::width()
            + SingleMainSymbolicExpressionColumns::<F>::width() * self.cnt_proofs
    }
}

impl<AB: PartitionedAirBuilder + InteractionBuilder + AirBuilderWithPublicValues> Air<AB>
    for SymbolicExpressionAir
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
    /* debug block: Step 1 placeholder - all constraints deferred pending trace implementation */
    #[allow(unused_variables)]
    let _ = &builder;
    }
}
