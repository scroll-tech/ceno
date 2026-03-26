use core::borrow::Borrow;

use openvm_circuit_primitives::utils::assert_array_eq;
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

        ///////////////////////////////////////////////////////////////////////
        // Structural constraints (replaces NestedForLoopSubAir<2>)
        //
        // The trace has a 3-level nested structure:
        //   proof_idx > idx (chip) > GKR layer (marked by is_first)
        // NestedForLoopSubAir<2> only supports 2 levels and would forbid
        // is_first=1 when idx stays the same. We need is_first at every
        // GKR layer boundary for correct bus send counts, so we write the
        // loop constraints manually.
        ///////////////////////////////////////////////////////////////////////

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);

        // is_enabled monotone decreasing: once disabled, stays disabled
        builder
            .when_transition()
            .when(AB::Expr::ONE - local.is_enabled)
            .assert_zero(next.is_enabled);

        // is_first flags imply is_enabled
        builder
            .when(local.is_first_layer)
            .assert_one(local.is_enabled);
        builder.when(local.is_first).assert_one(local.is_enabled);

        // First trace row: is_first_layer=1 and proof_idx=0 if enabled
        builder
            .when_first_row()
            .when(local.is_enabled)
            .assert_one(local.is_first_layer);
        builder
            .when_first_row()
            .when(local.is_enabled)
            .assert_zero(local.proof_idx);

        // is_first_layer implies is_first and idx=0
        builder
            .when(local.is_first_layer)
            .assert_one(local.is_first);
        builder.when(local.is_first_layer).assert_zero(local.idx);

        // proof_idx transitions: can stay same or increment by 1
        let proof_diff: AB::Expr = next.proof_idx - local.proof_idx;
        builder
            .when_transition()
            .when(next.is_enabled)
            .assert_bool(proof_diff.clone());
        // When proof_idx changes: next.is_first_layer must be 1
        builder
            .when_transition()
            .when(next.is_enabled * proof_diff.clone())
            .assert_one(next.is_first_layer);
        // When proof_idx unchanged: next.is_first_layer must be 0
        builder
            .when_transition()
            .when(next.is_enabled * (AB::Expr::ONE - proof_diff))
            .assert_zero(next.is_first_layer);

        // idx transitions within same proof (non-proof-boundary)
        let idx_diff: AB::Expr = next.idx - local.idx;
        builder
            .when_transition()
            .when(next.is_enabled * (AB::Expr::ONE - next.is_first_layer))
            .assert_bool(idx_diff.clone());
        // When idx changes: next.is_first must be 1
        builder
            .when_transition()
            .when(next.is_enabled * (AB::Expr::ONE - next.is_first_layer) * idx_diff)
            .assert_one(next.is_first);
        // NOTE: We do NOT constrain is_first=0 when idx stays the same.
        // Within the same idx (chip), is_first=1 marks GKR layer boundaries.

        ///////////////////////////////////////////////////////////////////////
        // Derived flags
        ///////////////////////////////////////////////////////////////////////

        // is_within_layer: next row continues the same GKR layer
        let is_within_layer: AB::Expr = next.is_enabled - next.is_first;
        // is_layer_end: current row is the last of its GKR layer
        let is_layer_end: AB::Expr = local.is_enabled - next.is_enabled + next.is_first;
        let is_not_dummy = local.is_enabled * (AB::Expr::ONE - local.is_dummy);

        ///////////////////////////////////////////////////////////////////////
        // layer_idx: GKR layer index, constant within each layer
        ///////////////////////////////////////////////////////////////////////

        // Within the same layer: layer_idx stays constant
        builder
            .when(is_within_layer.clone())
            .assert_eq(next.layer_idx, local.layer_idx);

        ///////////////////////////////////////////////////////////////////////
        // index_id: row counter within each GKR layer
        ///////////////////////////////////////////////////////////////////////

        builder
            .when(local.is_first)
            .assert_zero(local.index_id);
        builder
            .when(local.is_enabled * next.is_enabled * next.is_first_layer)
            .assert_zero(next.index_id);
        builder
            .when(is_within_layer.clone() * is_not_dummy.clone())
            .assert_eq(next.index_id, local.index_id + AB::Expr::ONE);
        builder
            .when(is_layer_end.clone() * is_not_dummy.clone())
            .assert_eq(local.index_id + AB::Expr::ONE, local.num_prod_count);

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
            local.is_first.into(),
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
            is_layer_end,
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

impl_prod_sum_air!(TowerProdReadSumCheckClaimAir);
impl_prod_sum_air!(TowerProdWriteSumCheckClaimAir);
