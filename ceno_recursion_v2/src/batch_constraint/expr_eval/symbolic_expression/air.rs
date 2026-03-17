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

pub const NUM_FLAGS: usize = 4;
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
        let cached_local = builder.cached_mains()[0]
            .row_slice(0)
            .expect("cached window should have a row")
            .to_vec();
        let main_local = builder
            .common_main()
            .row_slice(0)
            .expect("main window should have a row")
            .to_vec();
        let main_next = builder
            .common_main()
            .row_slice(1)
            .expect("main window should have two rows")
            .to_vec();

        let cached_cols: &CachedSymbolicExpressionColumns<AB::Var> =
            cached_local.as_slice().borrow();
        let main_cols: Vec<&SingleMainSymbolicExpressionColumns<AB::Var>> = main_local
            .chunks(SingleMainSymbolicExpressionColumns::<AB::Var>::width())
            .map(|chunk| chunk.borrow())
            .collect();
        let next_main_cols: Vec<&SingleMainSymbolicExpressionColumns<AB::Var>> = main_next
            .chunks(SingleMainSymbolicExpressionColumns::<AB::Var>::width())
            .map(|chunk| chunk.borrow())
            .collect();

        let enc = Encoder::new(NodeKind::COUNT, ENCODER_MAX_DEGREE, true);
        let flags = cached_cols.flags;
        let is_valid_row = enc.is_valid::<AB>(&flags);

        let is_arg0_node_idx = enc.contains_flag::<AB>(
            &flags,
            &[
                NodeKind::Add,
                NodeKind::Sub,
                NodeKind::Mul,
                NodeKind::Neg,
                NodeKind::InteractionMult,
                NodeKind::InteractionMsgComp,
                NodeKind::WitIn,
                NodeKind::StructuralWitIn,
                NodeKind::Fixed,
                NodeKind::Instance,
            ]
            .map(|x| x as usize),
        );
        let is_arg1_node_idx = enc.contains_flag::<AB>(
            &flags,
            &[
                NodeKind::Add,
                NodeKind::Sub,
                NodeKind::Mul,
                NodeKind::InteractionMsgComp,
            ]
            .map(|x| x as usize),
        );

        for (proof_idx, (&cols, &next_cols)) in main_cols.iter().zip(&next_main_cols).enumerate() {
            let proof_idx = AB::F::from_usize(proof_idx);

            let slot_state: AB::Expr = cols.slot_state.into();
            let next_slot_state: AB::Expr = next_cols.slot_state.into();
            let proof_present = slot_state.clone()
                * (AB::Expr::from_u8(3) - slot_state.clone())
                * AB::F::TWO.inverse();
            let next_proof_present = next_slot_state.clone()
                * (AB::Expr::from_u8(3) - next_slot_state)
                * AB::F::TWO.inverse();
            let air_present =
                slot_state.clone() * (slot_state.clone() - AB::Expr::ONE) * AB::F::TWO.inverse();

            let arg_ef0: [AB::Var; D_EF] = cols.args[..D_EF].try_into().unwrap();
            let arg_ef1: [AB::Var; D_EF] = cols.args[D_EF..2 * D_EF].try_into().unwrap();

            builder.assert_tern(cols.slot_state);
            builder
                .when(cols.is_n_neg)
                .assert_eq(cols.slot_state, AB::Expr::TWO);
            builder
                .when(air_present.clone())
                .assert_one(is_valid_row.clone());
            builder
                .when_transition()
                .assert_eq(proof_present.clone(), next_proof_present);

            let mut value = [AB::Expr::ZERO; D_EF];
            for node_kind in NodeKind::iter() {
                let sel = enc.get_flag_expr::<AB>(node_kind as usize, &flags);
                let expr = match node_kind {
                    NodeKind::Add => ext_field_add::<AB::Expr>(arg_ef0, arg_ef1),
                    NodeKind::Sub => ext_field_subtract::<AB::Expr>(arg_ef0, arg_ef1),
                    NodeKind::Neg => scalar_subtract_ext_field::<AB::Expr>(AB::Expr::ZERO, arg_ef0),
                    NodeKind::Mul => ext_field_multiply::<AB::Expr>(arg_ef0, arg_ef1),
                    NodeKind::Constant => base_to_ext(cached_cols.attrs[0]),
                    NodeKind::Instance => base_to_ext(cols.args[0]),
                    NodeKind::SelIsFirst => ext_field_multiply(arg_ef0, arg_ef1),
                    NodeKind::SelIsLast => ext_field_multiply(arg_ef0, arg_ef1),
                    NodeKind::SelIsTransition => scalar_subtract_ext_field(
                        AB::Expr::ONE,
                        ext_field_multiply(arg_ef0, arg_ef1),
                    ),
                    NodeKind::WitIn
                    | NodeKind::StructuralWitIn
                    | NodeKind::Fixed
                    | NodeKind::InteractionMult
                    | NodeKind::InteractionMsgComp => arg_ef0.map(Into::into),
                    NodeKind::InteractionBusIndex => {
                        base_to_ext(cached_cols.attrs[0] + AB::Expr::ONE)
                    }
                };
                value = ext_field_add::<AB::Expr>(
                    value,
                    ext_field_multiply_scalar::<AB::Expr>(expr, sel),
                );
            }

            self.expr_bus.add_key_with_lookups(
                builder,
                proof_idx,
                SymbolicExpressionMessage {
                    air_idx: cached_cols.air_idx.into(),
                    node_idx: cached_cols.node_or_interaction_idx.into(),
                    value: value.clone(),
                },
                air_present.clone() * cached_cols.fanout,
            );
            self.expr_bus.lookup_key(
                builder,
                proof_idx,
                SymbolicExpressionMessage {
                    air_idx: cached_cols.air_idx,
                    node_idx: cached_cols.attrs[0],
                    value: arg_ef0,
                },
                air_present.clone() * is_arg0_node_idx.clone(),
            );
            self.expr_bus.lookup_key(
                builder,
                proof_idx,
                SymbolicExpressionMessage {
                    air_idx: cached_cols.air_idx,
                    node_idx: cached_cols.attrs[1],
                    value: arg_ef1,
                },
                air_present.clone() * is_arg1_node_idx.clone(),
            );

            let is_var = enc.contains_flag::<AB>(
                &flags,
                &[NodeKind::WitIn, NodeKind::StructuralWitIn, NodeKind::Fixed].map(|x| x as usize),
            );
            self.column_claims_bus.receive(
                builder,
                proof_idx,
                ColumnClaimsMessage {
                    sort_idx: cols.sort_idx.into(),
                    part_idx: cached_cols.attrs[1].into(),
                    col_idx: cached_cols.attrs[0].into(),
                    claim: array::from_fn(|i| cols.args[i].into()),
                    is_rot: cached_cols.attrs[2].into(),
                },
                is_var * air_present.clone(),
            );
            self.public_values_bus.receive(
                builder,
                proof_idx,
                PublicValuesBusMessage {
                    air_idx: cached_cols.air_idx,
                    pv_idx: cached_cols.attrs[0],
                    value: cols.args[0],
                },
                enc.get_flag_expr::<AB>(NodeKind::Instance as usize, &flags) * air_present.clone(),
            );
            self.air_shape_bus.lookup_key(
                builder,
                proof_idx,
                AirShapeBusMessage {
                    sort_idx: cols.sort_idx.into(),
                    property_idx: AirShapeProperty::AirId.to_field(),
                    value: cached_cols.air_idx.into(),
                },
                air_present.clone(),
            );
            self.air_presence_bus.lookup_key(
                builder,
                proof_idx,
                AirPresenceBusMessage {
                    air_idx: cached_cols.air_idx.into(),
                    is_present: air_present.clone(),
                },
                proof_present * is_valid_row.clone(),
            );
            self.hyperdim_bus.lookup_key(
                builder,
                proof_idx,
                HyperdimBusMessage {
                    sort_idx: cols.sort_idx,
                    n_abs: cols.n_abs,
                    n_sign_bit: cols.is_n_neg,
                },
                air_present.clone(),
            );

            let is_sel = enc.contains_flag::<AB>(
                &flags,
                &[
                    NodeKind::SelIsFirst,
                    NodeKind::SelIsLast,
                    NodeKind::SelIsTransition,
                ]
                .map(|x| x as usize),
            );
            let is_first = enc.get_flag_expr::<AB>(NodeKind::SelIsFirst as usize, &flags);
            self.sel_uni_bus.lookup_key(
                builder,
                proof_idx,
                SelUniBusMessage {
                    n: AB::Expr::NEG_ONE * cols.n_abs * cols.is_n_neg,
                    is_first: is_first.clone(),
                    value: arg_ef0.map(Into::into),
                },
                air_present.clone() * is_sel.clone(),
            );
            self.sel_hypercube_bus.lookup_key(
                builder,
                proof_idx,
                SelHypercubeBusMessage {
                    n: cols.n_abs.into(),
                    is_first: is_first.clone(),
                    value: arg_ef1.map(Into::into),
                },
                is_sel.clone() * (air_present.clone() - cols.is_n_neg),
            );
            assert_array_eq(
                &mut builder.when(is_sel.clone() * cols.is_n_neg),
                arg_ef1,
                [
                    AB::Expr::ONE,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ],
            );

            let is_mult = enc.get_flag_expr::<AB>(NodeKind::InteractionMult as usize, &flags);
            let is_bus_index =
                enc.get_flag_expr::<AB>(NodeKind::InteractionBusIndex as usize, &flags);
            let is_interaction = enc.contains_flag::<AB>(
                &flags,
                &[NodeKind::InteractionMult, NodeKind::InteractionMsgComp].map(|x| x as usize),
            );
            self.interactions_folding_bus.send(
                builder,
                proof_idx,
                InteractionsFoldingMessage {
                    air_idx: cached_cols.air_idx.into(),
                    interaction_idx: cached_cols.node_or_interaction_idx.into(),
                    is_mult,
                    idx_in_message: cached_cols.attrs[1].into(),
                    value: value.clone(),
                },
                is_interaction * air_present.clone(),
            );
            self.interactions_folding_bus.send(
                builder,
                proof_idx,
                InteractionsFoldingMessage {
                    air_idx: cached_cols.air_idx.into(),
                    interaction_idx: cached_cols.node_or_interaction_idx.into(),
                    is_mult: AB::Expr::ZERO,
                    idx_in_message: AB::Expr::NEG_ONE,
                    value: value.clone(),
                },
                is_bus_index * air_present.clone(),
            );
            self.constraints_folding_bus.send(
                builder,
                proof_idx,
                ConstraintsFoldingMessage {
                    air_idx: cached_cols.air_idx.into(),
                    constraint_idx: cached_cols.constraint_idx.into(),
                    value: value.clone(),
                },
                cached_cols.is_constraint * air_present,
            );
        }
    }
}
