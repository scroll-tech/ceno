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
    TowerLogupClaimBus, TowerLogupClaimInputBus, TowerLogupClaimMessage,
    TowerLogupLayerChallengeMessage,
};
use recursion_circuit::{
    bus::TranscriptBus,
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{assert_zeros, ext_field_add, ext_field_multiply, ext_field_subtract},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerLogupSumCheckClaimCols<T> {
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
    pub q_xi_0: [T; D_EF],
    pub q_xi_1: [T; D_EF],
    pub p_xi: [T; D_EF],
    pub q_xi: [T; D_EF],

    pub pow_lambda: [T; D_EF],
    pub pow_lambda_prime: [T; D_EF],
    pub acc_sum: [T; D_EF],
    pub acc_p_cross: [T; D_EF],
    pub acc_q_cross: [T; D_EF],
    pub num_logup_count: T,
}

pub struct TowerLogupSumCheckClaimAir {
    pub transcript_bus: TranscriptBus,
    pub logup_claim_input_bus: TowerLogupClaimInputBus,
    pub logup_claim_bus: TowerLogupClaimBus,
}

impl<F: Field> BaseAir<F> for TowerLogupSumCheckClaimAir {
    fn width(&self) -> usize {
        TowerLogupSumCheckClaimCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerLogupSumCheckClaimAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerLogupSumCheckClaimAir {}

impl<AB> Air<AB> for TowerLogupSumCheckClaimAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &TowerLogupSumCheckClaimCols<AB::Var> = (*local_row).borrow();
        let next: &TowerLogupSumCheckClaimCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_dummy);
        builder.assert_bool(local.is_first_layer);

        type LoopSubAir = NestedForLoopSubAir<2>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.idx],
                    is_first: [local.is_first_layer, local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.idx],
                    is_first: [next.is_first_layer, next.is_first],
                }
                .map_into(),
            ),
        );

        let is_transition = LoopSubAir::local_is_transition(next.is_enabled, next.is_first);
        let is_last_layer_row =
            LoopSubAir::local_is_last(local.is_enabled, next.is_enabled, next.is_first);
        let stay_in_layer = AB::Expr::ONE - is_transition.clone();
        let is_not_dummy = local.is_enabled * (AB::Expr::ONE - local.is_dummy);

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
            .assert_eq(
                local.index_id + AB::Expr::ONE,
                local.num_logup_count.clone(),
            );

        assert_zeros(
            &mut builder.when(local.is_first * is_not_dummy.clone()),
            local.acc_sum.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(local.is_first * is_not_dummy.clone()),
            local.acc_p_cross.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(local.is_first * is_not_dummy.clone()),
            local.acc_q_cross.map(Into::into),
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

        let delta_p = ext_field_subtract::<AB::Expr>(local.p_xi_1, local.p_xi_0);
        let expected_p_xi =
            ext_field_add::<AB::Expr>(local.p_xi_0, ext_field_multiply(delta_p, local.mu));
        assert_array_eq(builder, local.p_xi, expected_p_xi);

        let delta_q = ext_field_subtract::<AB::Expr>(local.q_xi_1, local.q_xi_0);
        let expected_q_xi =
            ext_field_add::<AB::Expr>(local.q_xi_0, ext_field_multiply(delta_q, local.mu));
        assert_array_eq(builder, local.q_xi, expected_q_xi);

        let (p_cross_term, q_cross_term) =
            compute_recursive_relations(local.p_xi_0, local.q_xi_0, local.p_xi_1, local.q_xi_1);

        let lambda = local.lambda.map(Into::into);
        let pow_lambda = local.pow_lambda.map(Into::into);
        let combined = ext_field_add::<AB::Expr>(
            local.p_xi,
            ext_field_multiply::<AB::Expr>(lambda.clone(), local.q_xi),
        );
        let contribution = ext_field_multiply::<AB::Expr>(pow_lambda.clone(), combined);
        let acc_sum_with_cur = ext_field_add::<AB::Expr>(local.acc_sum, contribution);
        let acc_sum_export = acc_sum_with_cur.clone();

        assert_array_eq(
            &mut builder.when(stay_in_layer.clone()),
            next.acc_sum,
            acc_sum_with_cur,
        );
        let pow_lambda_next = ext_field_multiply::<AB::Expr>(pow_lambda, lambda.clone());
        assert_array_eq(
            &mut builder.when(stay_in_layer.clone()),
            next.pow_lambda,
            pow_lambda_next,
        );

        let pow_lambda_prime = local.pow_lambda_prime.map(Into::into);
        let lambda_prime = local.lambda_prime.map(Into::into);
        let acc_p_with_cur = ext_field_add::<AB::Expr>(
            local.acc_p_cross,
            ext_field_multiply::<AB::Expr>(pow_lambda_prime.clone(), p_cross_term),
        );
        assert_array_eq(
            &mut builder.when(stay_in_layer.clone()),
            next.acc_p_cross,
            acc_p_with_cur.clone(),
        );
        let scaled_q_term = ext_field_multiply::<AB::Expr>(
            ext_field_multiply::<AB::Expr>(pow_lambda_prime.clone(), lambda_prime.clone()),
            q_cross_term,
        );
        let acc_q_with_cur = ext_field_add::<AB::Expr>(local.acc_q_cross, scaled_q_term);
        assert_array_eq(
            &mut builder.when(stay_in_layer.clone()),
            next.acc_q_cross,
            acc_q_with_cur.clone(),
        );
        let pow_lambda_prime_next =
            ext_field_multiply::<AB::Expr>(pow_lambda_prime, lambda_prime.clone());
        assert_array_eq(
            &mut builder.when(stay_in_layer.clone()),
            next.pow_lambda_prime,
            pow_lambda_prime_next,
        );

        self.logup_claim_input_bus.receive(
            builder,
            local.proof_idx,
            TowerLogupLayerChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: local.tidx.into(),
                lambda: lambda.clone(),
                lambda_prime: lambda_prime.clone(),
                mu: local.mu.map(Into::into),
            },
            local.is_first_layer * is_not_dummy.clone(),
        );

        self.logup_claim_bus.send(
            builder,
            local.proof_idx,
            TowerLogupClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_claim: acc_sum_export.map(Into::into),
                lambda_prime_claim: acc_q_with_cur.map(Into::into),
                num_logup_count: local.num_logup_count.into(),
            },
            is_last_layer_row * is_not_dummy.clone(),
        );

        let mut tidx = local.tidx.into();
        for claim in [local.p_xi_0, local.q_xi_0, local.p_xi_1, local.q_xi_1] {
            self.transcript_bus.observe_ext(
                builder,
                local.proof_idx,
                tidx.clone(),
                claim,
                local.is_enabled * is_not_dummy.clone(),
            );
            tidx += AB::Expr::from_usize(D_EF);
        }
    }
}

fn compute_recursive_relations<F, FA>(
    p_xi_0: [F; D_EF],
    q_xi_0: [F; D_EF],
    p_xi_1: [F; D_EF],
    q_xi_1: [F; D_EF],
) -> ([FA; D_EF], [FA; D_EF])
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let p_cross_term = ext_field_add::<FA>(
        ext_field_multiply::<FA>(p_xi_0, q_xi_1),
        ext_field_multiply::<FA>(p_xi_1, q_xi_0),
    );
    let q_cross_term = ext_field_multiply::<FA>(q_xi_0, q_xi_1);
    (p_cross_term, q_cross_term)
}
