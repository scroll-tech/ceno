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

use crate::tower::bus::{
    TowerProdLayerChallengeMessage, TowerProdReadClaimBus, TowerProdReadClaimInputBus,
    TowerProdSumClaimMessage, TowerProdWriteClaimBus, TowerProdWriteClaimInputBus,
};
use recursion_circuit::{
    bus::TranscriptBus,
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{assert_zeros, ext_field_add, ext_field_multiply, ext_field_subtract},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerProdSumCheckClaimCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub is_first_layer: T,
    pub is_first: T,
    pub is_dummy: T,

    pub layer_idx: T,
    pub index_id: T,
    pub tidx: T,

    pub lambda: [T; D_EF],
    pub lambda_prime: [T; D_EF],
    pub mu: [T; D_EF],
    pub p_xi_0: [T; D_EF],
    pub p_xi_1: [T; D_EF],
    pub p_xi: [T; D_EF],
    pub pow_lambda: [T; D_EF],
    pub pow_lambda_prime: [T; D_EF],
    pub acc_sum: [T; D_EF],
    pub acc_sum_prime: [T; D_EF],
    pub num_prod_count: T,
}

pub struct TowerProdSumCheckClaimAir<IB, OB> {
    pub transcript_bus: TranscriptBus,
    pub prod_claim_input_bus: IB,
    pub prod_claim_bus: OB,
}

pub type TowerProdReadSumCheckClaimAir =
    TowerProdSumCheckClaimAir<TowerProdReadClaimInputBus, TowerProdReadClaimBus>;
pub type TowerProdWriteSumCheckClaimAir =
    TowerProdSumCheckClaimAir<TowerProdWriteClaimInputBus, TowerProdWriteClaimBus>;

impl<F: Field, IB: Sync, OB: Sync> BaseAir<F> for TowerProdSumCheckClaimAir<IB, OB> {
    fn width(&self) -> usize {
        TowerProdSumCheckClaimCols::<F>::width()
    }
}

impl<F: Field, IB: Sync, OB: Sync> BaseAirWithPublicValues<F>
    for TowerProdSumCheckClaimAir<IB, OB>
{
}
impl<F: Field, IB: Sync, OB: Sync> PartitionedBaseAir<F> for TowerProdSumCheckClaimAir<IB, OB> {}

impl<IB, OB> TowerProdSumCheckClaimAir<IB, OB> {
    fn eval_core<AB, Recv, Send>(
        &self,
        builder: &mut AB,
        mut recv_challenge: Recv,
        mut send_claim: Send,
    ) where
        AB: AirBuilder + InteractionBuilder,
        <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
        Recv: FnMut(&IB, &mut AB, AB::Var, TowerProdLayerChallengeMessage<AB::Expr>, AB::Expr),
        Send: FnMut(&OB, &mut AB, AB::Var, TowerProdSumClaimMessage<AB::Expr>, AB::Expr),
    {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &TowerProdSumCheckClaimCols<AB::Var> = (*local_row).borrow();
        let next: &TowerProdSumCheckClaimCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_dummy);
        builder.assert_bool(local.is_first_layer);
        builder.assert_bool(local.is_first);

        // Track proof_idx as the single outer loop counter.
        // is_first_layer marks the start of each proof scope.
        type LoopSubAir = NestedForLoopSubAir<1>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx],
                    is_first: [local.is_first_layer],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx],
                    is_first: [next.is_first_layer],
                }
                .map_into(),
            ),
        );

        // When is_first is set, this must be a real enabled row.
        builder
            .when(local.is_first)
            .assert_one(local.is_enabled.clone());
        // After a disabled row, is_first must not be set (padding rows).
        builder
            .when_transition()
            .when_ne(local.is_enabled.clone(), AB::Expr::ONE)
            .assert_zero(next.is_first.clone());

        // is_within_layer: next row continues within the same layer (next.is_first = 0 and enabled)
        let is_within_layer = AB::Expr::from(next.is_enabled) - AB::Expr::from(next.is_first);
        // at_layer_boundary: current row is the last index_id of its layer
        // fires when next is disabled OR next starts a new layer
        let at_layer_boundary = AB::Expr::from(local.is_enabled)
            - AB::Expr::from(next.is_enabled)
            + AB::Expr::from(next.is_first);
        let is_not_dummy = local.is_enabled * (AB::Expr::ONE - local.is_dummy);

        // idx and layer_idx stay fixed within a layer.
        builder
            .when(is_within_layer.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when(is_within_layer.clone())
            .assert_eq(next.layer_idx, local.layer_idx);

        // When the next row starts a later layer within the same record, idx stays fixed
        // and layer_idx increments by 1. If next.layer_idx == 0, this is a new record boundary
        // and the next row is constrained by its own bus input instead.
        builder
            .when(at_layer_boundary.clone() * local.is_enabled * next.is_enabled * next.layer_idx)
            .assert_eq(next.idx, local.idx);
        builder
            .when(at_layer_boundary.clone() * local.is_enabled * next.is_enabled * next.layer_idx)
            .assert_eq(next.layer_idx, local.layer_idx + AB::Expr::ONE);

        // index_id starts at 0 on the first row of each layer
        builder
            .when(local.is_first)
            .assert_zero(local.index_id.clone());
        // index_id also resets to 0 on any is_first row (layer start)
        builder
            .when(local.is_enabled * next.is_enabled * next.is_first)
            .assert_zero(next.index_id.clone());
        // index_id increments within a layer
        builder
            .when(is_not_dummy.clone() * is_within_layer.clone())
            .assert_eq(next.index_id, local.index_id + AB::Expr::ONE);
        // last row of a layer: index_id + 1 == num_prod_count
        builder
            .when(at_layer_boundary.clone() * is_not_dummy.clone())
            .assert_eq(local.index_id + AB::Expr::ONE, local.num_prod_count.clone());
        let is_last_layer_row = at_layer_boundary;

        assert_zeros(
            &mut builder.when(local.is_first * is_not_dummy.clone()),
            local.acc_sum.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(local.is_first * is_not_dummy.clone()),
            local.acc_sum_prime.map(Into::into),
        );
        builder
            .when(local.is_first * is_not_dummy.clone())
            .assert_eq(local.pow_lambda[0], AB::Expr::ONE);
        for limb in local.pow_lambda.iter().copied().skip(1) {
            builder
                .when(local.is_first * is_not_dummy.clone())
                .assert_zero(limb);
        }
        builder
            .when(local.is_first * is_not_dummy.clone())
            .assert_eq(local.pow_lambda_prime[0], AB::Expr::ONE);
        for limb in local.pow_lambda_prime.iter().copied().skip(1) {
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

        let prime_product = ext_field_multiply::<AB::Expr>(local.p_xi_0, local.p_xi_1);
        let pow_lambda_prime = local.pow_lambda_prime.map(Into::into);
        let prime_contribution =
            ext_field_multiply::<AB::Expr>(pow_lambda_prime.clone(), prime_product);
        let acc_sum_prime_with_cur =
            ext_field_add::<AB::Expr>(local.acc_sum_prime, prime_contribution);
        let acc_sum_prime_export = acc_sum_prime_with_cur.clone();

        assert_array_eq(
            &mut builder.when(is_within_layer.clone()),
            next.acc_sum,
            acc_sum_with_cur,
        );
        assert_array_eq(
            &mut builder.when(is_within_layer.clone()),
            next.acc_sum_prime,
            acc_sum_prime_with_cur,
        );

        let lambda = local.lambda.map(Into::into);
        let pow_lambda_next = ext_field_multiply::<AB::Expr>(pow_lambda, lambda.clone());
        assert_array_eq(
            &mut builder.when(is_within_layer.clone()),
            next.pow_lambda,
            pow_lambda_next,
        );
        let lambda_prime = local.lambda_prime.map(Into::into);
        let pow_lambda_prime_next =
            ext_field_multiply::<AB::Expr>(pow_lambda_prime, lambda_prime.clone());
        assert_array_eq(
            &mut builder.when(is_within_layer.clone()),
            next.pow_lambda_prime,
            pow_lambda_prime_next,
        );

        recv_challenge(
            &self.prod_claim_input_bus,
            builder,
            local.proof_idx,
            TowerProdLayerChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: local.tidx.into(),
                lambda,
                lambda_prime: lambda_prime.clone(),
                mu: local.mu.map(Into::into),
            },
            AB::Expr::from(local.is_first) * is_not_dummy.clone(),
        );

        send_claim(
            &self.prod_claim_bus,
            builder,
            local.proof_idx,
            TowerProdSumClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_claim: acc_sum_export.map(Into::into),
                lambda_prime_claim: acc_sum_prime_export.map(Into::into),
                num_prod_count: local.num_prod_count.into(),
            },
            is_last_layer_row * is_not_dummy.clone(),
        );

        let _ = &self.transcript_bus;
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

impl_prod_sum_air!(TowerProdReadSumCheckClaimAir);
impl_prod_sum_air!(TowerProdWriteSumCheckClaimAir);
