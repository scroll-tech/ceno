use core::borrow::Borrow;

use openvm_circuit_primitives::{SubAir, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::gkr::bus::{
    GkrProdInitClaimBus, GkrProdInitClaimMessage, GkrProdInitLayerMessage,
    GkrProdLayerChallengeMessage, GkrProdReadClaimBus, GkrProdReadClaimInputBus,
    GkrProdReadInitClaimBus, GkrProdReadInitClaimInputBus, GkrProdSumClaimMessage,
    GkrProdWriteClaimBus, GkrProdWriteClaimInputBus, GkrProdWriteInitClaimBus,
    GkrProdWriteInitClaimInputBus,
};
use recursion_circuit::{
    bus::TranscriptBus,
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{assert_zeros, ext_field_add, ext_field_multiply, ext_field_subtract},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct GkrProdSumCheckClaimCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub is_first_air_idx: T,
    pub is_first_layer: T,
    pub is_first: T,
    pub is_dummy: T,

    pub layer_idx: T,
    pub index_id: T,
    pub tidx: T,

    pub lambda: [T; D_EF],
    pub mu: [T; D_EF],
    pub p_xi_0: [T; D_EF],
    pub p_xi_1: [T; D_EF],
    pub p_xi: [T; D_EF],
    pub pow_lambda: [T; D_EF],
    pub acc_sum: [T; D_EF],
    pub num_prod_count: T,
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct GkrProdInitSumCheckClaimCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub is_first_air_idx: T,
    pub is_first_layer: T,
    pub is_first: T,
    pub is_dummy: T,

    pub layer_idx: T,
    pub index_id: T,
    pub tidx: T,

    pub p_xi_0: [T; D_EF],
    pub p_xi_1: [T; D_EF],
    pub acc_sum: [T; D_EF],
    pub num_prod_count: T,
}

pub struct GkrProdSumCheckClaimAir<IB, OB> {
    pub transcript_bus: TranscriptBus,
    pub prod_claim_input_bus: IB,
    pub prod_claim_bus: OB,
}

pub struct GkrProdInitSumCheckClaimAir<IB, OB> {
    pub transcript_bus: TranscriptBus,
    pub prod_init_claim_input_bus: IB,
    pub prod_init_claim_bus: OB,
}

pub type GkrProdReadSumCheckClaimAir =
    GkrProdSumCheckClaimAir<GkrProdReadClaimInputBus, GkrProdReadClaimBus>;
pub type GkrProdWriteSumCheckClaimAir =
    GkrProdSumCheckClaimAir<GkrProdWriteClaimInputBus, GkrProdWriteClaimBus>;
pub type GkrProdReadInitSumCheckClaimAir =
    GkrProdInitSumCheckClaimAir<GkrProdReadInitClaimInputBus, GkrProdReadInitClaimBus>;
pub type GkrProdWriteInitSumCheckClaimAir =
    GkrProdInitSumCheckClaimAir<GkrProdWriteInitClaimInputBus, GkrProdWriteInitClaimBus>;

impl<F: Field, IB, OB> BaseAir<F> for GkrProdSumCheckClaimAir<IB, OB> {
    fn width(&self) -> usize {
        GkrProdSumCheckClaimCols::<F>::width()
    }
}

impl<F: Field, IB, OB> BaseAirWithPublicValues<F> for GkrProdSumCheckClaimAir<IB, OB> {}
impl<F: Field, IB, OB> PartitionedBaseAir<F> for GkrProdSumCheckClaimAir<IB, OB> {}

impl<F: Field, IB, OB> BaseAir<F> for GkrProdInitSumCheckClaimAir<IB, OB> {
    fn width(&self) -> usize {
        GkrProdInitSumCheckClaimCols::<F>::width()
    }
}

impl<F: Field, IB, OB> BaseAirWithPublicValues<F> for GkrProdInitSumCheckClaimAir<IB, OB> {}
impl<F: Field, IB, OB> PartitionedBaseAir<F> for GkrProdInitSumCheckClaimAir<IB, OB> {}

impl<IB, OB> GkrProdSumCheckClaimAir<IB, OB> {
    fn eval_core<AB, Recv, Send>(
        &self,
        builder: &mut AB,
        mut recv_challenge: Recv,
        mut send_claim: Send,
    ) where
        AB: AirBuilder + InteractionBuilder,
        <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
        Recv: FnMut(
            &IB,
            &mut AB,
            AB::Var,
            GkrProdLayerChallengeMessage<AB::Expr>,
            AB::Expr,
        ),
        Send: FnMut(&OB, &mut AB, AB::Var, GkrProdSumClaimMessage<AB::Expr>, AB::Expr),
    {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &GkrProdSumCheckClaimCols<AB::Var> = (*local_row).borrow();
        let next: &GkrProdSumCheckClaimCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_dummy);
        builder.assert_bool(local.is_first_air_idx);
        builder.assert_bool(local.is_first_layer);

        type LoopSubAir = NestedForLoopSubAir<3>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.idx, local.layer_idx],
                    is_first: [local.is_first_air_idx, local.is_first_layer, local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.idx, next.layer_idx],
                    is_first: [next.is_first_air_idx, next.is_first_layer, next.is_first],
                }
                .map_into(),
            ),
        );

        let is_transition = LoopSubAir::local_is_transition(next.is_enabled, next.is_first);
        let is_last_layer_row =
            LoopSubAir::local_is_last(local.is_enabled, next.is_enabled, next.is_first);
        let is_not_dummy = local.is_enabled * (AB::Expr::ONE - local.is_dummy);
        let stay_in_layer = AB::Expr::ONE - is_transition.clone();

        builder
            .when(local.is_first)
            .assert_zero(local.layer_idx.clone());
        builder
            .when(is_transition.clone())
            .assert_eq(next.layer_idx, local.layer_idx + AB::Expr::ONE);

        builder
            .when(local.is_first_layer)
            .assert_zero(local.index_id.clone());
        builder
            .when(local.is_enabled * next.is_enabled * next.is_first_layer)
            .assert_zero(next.index_id.clone());
        builder
            .when(is_not_dummy.clone() * stay_in_layer.clone())
            .assert_eq(next.index_id, local.index_id + AB::Expr::ONE);
        builder
            .when(is_last_layer_row.clone() * is_not_dummy.clone())
            .assert_eq(local.index_id + AB::Expr::ONE, local.num_prod_count.clone());

        assert_zeros(
            &mut builder.when(local.is_first * is_not_dummy.clone()),
            local.acc_sum.map(Into::into),
        );
        builder
            .when(local.is_first * is_not_dummy.clone())
            .assert_eq(local.pow_lambda[0], AB::Expr::ONE);
        for limb in local.pow_lambda.iter().copied().skip(1) {
            builder
                .when(local.is_first * is_not_dummy.clone())
                .assert_zero(limb);
        }

        let delta = ext_field_subtract::<AB::Expr>(local.p_xi_1, local.p_xi_0);
        let expected_p_xi =
            ext_field_add::<AB::Expr>(local.p_xi_0, ext_field_multiply(delta, local.mu));
        assert_array_eq(builder, local.p_xi, expected_p_xi);

        let pow_lambda = local.pow_lambda.map(Into::into);
        let contribution = ext_field_multiply::<AB::Expr>(local.p_xi, pow_lambda.clone());
        let acc_sum_with_cur = ext_field_add::<AB::Expr>(local.acc_sum, contribution);
        let acc_sum_export = acc_sum_with_cur.clone();

        assert_array_eq(
            &mut builder.when(stay_in_layer.clone()),
            next.acc_sum,
            acc_sum_with_cur,
        );

        let pow_lambda_next = ext_field_multiply::<AB::Expr>(pow_lambda, local.lambda.map(Into::into));
        assert_array_eq(
            &mut builder.when(stay_in_layer),
            next.pow_lambda,
            pow_lambda_next,
        );

        recv_challenge(
            &self.prod_claim_input_bus,
            builder,
            local.proof_idx,
            GkrProdLayerChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: local.tidx.into(),
                lambda: local.lambda.map(Into::into),
                mu: local.mu.map(Into::into),
            },
            local.is_first_layer * is_not_dummy.clone(),
        );

        send_claim(
            &self.prod_claim_bus,
            builder,
            local.proof_idx,
            GkrProdSumClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                claim: acc_sum_export.map(Into::into),
                num_prod_count: local.num_prod_count.into(),
            },
            is_last_layer_row * is_not_dummy.clone(),
        );

        let mut tidx = local.tidx.into();
        self.transcript_bus.observe_ext(
            builder,
            local.proof_idx,
            tidx.clone(),
            local.p_xi_0,
            local.is_enabled * is_not_dummy.clone(),
        );
        tidx += AB::Expr::from_usize(D_EF);
        self.transcript_bus.observe_ext(
            builder,
            local.proof_idx,
            tidx,
            local.p_xi_1,
            local.is_enabled * is_not_dummy,
        );
    }
}

impl<IB, OB> GkrProdInitSumCheckClaimAir<IB, OB> {
    fn eval_core<AB, Recv, Send>(
        &self,
        builder: &mut AB,
        mut recv_init: Recv,
        mut send_init: Send,
    ) where
        AB: AirBuilder + InteractionBuilder,
        <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
        Recv: FnMut(&IB, &mut AB, AB::Var, GkrProdInitLayerMessage<AB::Expr>, AB::Expr),
        Send: FnMut(
            &OB,
            &mut AB,
            AB::Var,
            GkrProdInitClaimMessage<AB::Expr>,
            AB::Expr,
        ),
    {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &GkrProdInitSumCheckClaimCols<AB::Var> = (*local_row).borrow();
        let next: &GkrProdInitSumCheckClaimCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_dummy);
        builder.assert_bool(local.is_first_air_idx);
        builder.assert_bool(local.is_first_layer);

        type LoopSubAir = NestedForLoopSubAir<3>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.idx, local.layer_idx],
                    is_first: [local.is_first_air_idx, local.is_first_layer, local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.idx, next.layer_idx],
                    is_first: [next.is_first_air_idx, next.is_first_layer, next.is_first],
                }
                .map_into(),
            ),
        );

        let is_transition = LoopSubAir::local_is_transition(next.is_enabled, next.is_first);
        let is_last_layer_row =
            LoopSubAir::local_is_last(local.is_enabled, next.is_enabled, next.is_first);
        let is_not_dummy = local.is_enabled * (AB::Expr::ONE - local.is_dummy);
        let stay_in_layer = AB::Expr::ONE - is_transition.clone();

        builder
            .when(local.is_first)
            .assert_zero(local.layer_idx.clone());
        builder
            .when(is_transition.clone())
            .assert_eq(next.layer_idx, local.layer_idx + AB::Expr::ONE);

        builder
            .when(local.is_first_layer)
            .assert_zero(local.index_id.clone());
        builder
            .when(local.is_enabled * next.is_enabled * next.is_first_layer)
            .assert_zero(next.index_id.clone());
        builder
            .when(is_not_dummy.clone() * stay_in_layer.clone())
            .assert_eq(next.index_id, local.index_id + AB::Expr::ONE);
        builder
            .when(is_last_layer_row.clone() * is_not_dummy.clone())
            .assert_eq(local.index_id + AB::Expr::ONE, local.num_prod_count.clone());

        assert_zeros(
            &mut builder.when(local.is_first * is_not_dummy.clone()),
            local.acc_sum.map(Into::into),
        );

        let product = ext_field_multiply::<AB::Expr>(local.p_xi_0, local.p_xi_1);
        let acc_sum_with_cur = ext_field_add::<AB::Expr>(local.acc_sum, product.clone());

        assert_array_eq(
            &mut builder.when(stay_in_layer.clone()),
            next.acc_sum,
            acc_sum_with_cur,
        );

        recv_init(
            &self.prod_init_claim_input_bus,
            builder,
            local.proof_idx,
            GkrProdInitLayerMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: local.tidx.into(),
            },
            local.is_first_layer * is_not_dummy.clone(),
        );

        send_init(
            &self.prod_init_claim_bus,
            builder,
            local.proof_idx,
            GkrProdInitClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                acc_sum: acc_sum_with_cur.map(Into::into),
                num_prod_count: local.num_prod_count.into(),
            },
            is_last_layer_row * is_not_dummy.clone(),
        );

        let mut tidx = local.tidx.into();
        self.transcript_bus.observe_ext(
            builder,
            local.proof_idx,
            tidx.clone(),
            local.p_xi_0,
            local.is_enabled * is_not_dummy.clone(),
        );
        tidx += AB::Expr::from_usize(D_EF);
        self.transcript_bus.observe_ext(
            builder,
            local.proof_idx,
            tidx,
            local.p_xi_1,
            local.is_enabled * is_not_dummy,
        );
    }
}

macro_rules! impl_prod_sum_air {
    ($ty:ty) => {
        impl<AB> Air<AB> for $ty
        where
            AB: AirBuilder + InteractionBuilder,
            <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
        {
            fn eval(&self, builder: &mut AB) {
                self.eval_core(
                    builder,
                    |bus, builder, proof_idx, msg, mult| {
                        bus.receive(builder, proof_idx, msg, mult);
                    },
                    |bus, builder, proof_idx, msg, mult| {
                        bus.send(builder, proof_idx, msg, mult);
                    },
                );
            }
        }
    };
}

impl_prod_sum_air!(GkrProdReadSumCheckClaimAir);
impl_prod_sum_air!(GkrProdWriteSumCheckClaimAir);

macro_rules! impl_prod_init_air {
    ($ty:ty) => {
        impl<AB> Air<AB> for $ty
        where
            AB: AirBuilder + InteractionBuilder,
            <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
        {
            fn eval(&self, builder: &mut AB) {
                self.eval_core(
                    builder,
                    |bus, builder, proof_idx, msg, mult| {
                        bus.receive(builder, proof_idx, msg, mult);
                    },
                    |bus, builder, proof_idx, msg, mult| {
                        bus.send(builder, proof_idx, msg, mult);
                    },
                );
            }
        }
    };
}

impl_prod_init_air!(GkrProdReadInitSumCheckClaimAir);
impl_prod_init_air!(GkrProdWriteInitSumCheckClaimAir);
