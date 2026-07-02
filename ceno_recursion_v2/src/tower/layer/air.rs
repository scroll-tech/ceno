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

use crate::{
    bus::{ForkedTranscriptBus, ForkedTranscriptBusMessage},
    tower::{
        TOWER_ACTIVITY_LOGUP, TOWER_ACTIVITY_READ, TOWER_ACTIVITY_WRITE, TowerActivityBus,
        TowerAlphaPowBus, TowerAlphaPowMessage, TowerLayerInputBus, TowerLayerOutputBus,
        TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage, TowerSumcheckInputBus,
        TowerSumcheckInputMessage, TowerSumcheckOutputBus, TowerSumcheckOutputMessage,
        bus::{TowerActivityMessage, TowerLayerInputMessage, TowerLayerOutputMessage},
    },
};

use recursion_circuit::{
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{assert_zeros, ext_field_add, ext_field_multiply, ext_field_subtract},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerLayerCols<T> {
    /// Whether the current row is enabled (i.e. not padding)
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub fork_id: T,
    pub is_first_air_idx: T,
    pub is_first: T,

    /// An enabled row which is not involved in any interactions
    /// but should satisfy air constraints
    pub is_dummy: T,

    /// GKR layer index
    pub layer_idx: T,

    /// Transcript index at the start of this layer
    pub tidx: T,

    /// Sampled batching challenge
    pub lambda: [T; D_EF],
    /// Challenge inherited from previous layer
    pub lambda_prime: [T; D_EF],
    /// Reduction point
    pub mu: [T; D_EF],

    pub sumcheck_claim_in: [T; D_EF],
    pub sumcheck_claim_out: [T; D_EF],

    pub read_claim: [T; D_EF],
    pub read_claim_prime: [T; D_EF],
    pub write_claim: [T; D_EF],
    pub write_claim_prime: [T; D_EF],
    pub logup_claim: [T; D_EF],
    pub logup_claim_prime: [T; D_EF],
    pub read_active: T,
    pub write_active: T,
    pub logup_active: T,

    pub read_p0: [T; D_EF],
    pub read_p1: [T; D_EF],
    pub read_p_xi: [T; D_EF],
    pub write_p0: [T; D_EF],
    pub write_p1: [T; D_EF],
    pub write_p_xi: [T; D_EF],
    pub logup_p0: [T; D_EF],
    pub logup_p1: [T; D_EF],
    pub logup_q0: [T; D_EF],
    pub logup_q1: [T; D_EF],
    pub logup_p_xi: [T; D_EF],
    pub logup_q_xi: [T; D_EF],
    pub read_weight: [T; D_EF],
    pub write_weight: [T; D_EF],
    pub logup_p_weight: [T; D_EF],
    pub logup_q_weight: [T; D_EF],

    /// Received from TowerLayerSumcheckAir
    pub eq_at_r_prime: [T; D_EF],

    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    pub q0_claim: [T; D_EF],
}

/// The TowerLayerAir handles layer-to-layer transitions in the GKR protocol
pub struct TowerLayerAir {
    // External buses
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub activity_bus: TowerActivityBus,
    pub alpha_pow_bus: TowerAlphaPowBus,
    // Internal buses
    pub layer_input_bus: TowerLayerInputBus,
    pub layer_output_bus: TowerLayerOutputBus,
    pub sumcheck_input_bus: TowerSumcheckInputBus,
    pub sumcheck_output_bus: TowerSumcheckOutputBus,
    pub sumcheck_challenge_bus: TowerSumcheckChallengeBus,
}

impl<F: Field> BaseAir<F> for TowerLayerAir {
    fn width(&self) -> usize {
        TowerLayerCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerLayerAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerLayerAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for TowerLayerAir
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &TowerLayerCols<AB::Var> = (*local).borrow();
        let next: &TowerLayerCols<AB::Var> = (*next).borrow();

        ///////////////////////////////////////////////////////////////////////
        // Boolean Constraints
        ///////////////////////////////////////////////////////////////////////

        builder.assert_bool(local.is_dummy);
        builder.assert_bool(local.is_first_air_idx);
        builder.assert_bool(local.read_active);
        builder.assert_bool(local.write_active);
        builder.assert_bool(local.logup_active);

        ///////////////////////////////////////////////////////////////////////
        // Proof Index and Loop Constraints
        ///////////////////////////////////////////////////////////////////////

        type LoopSubAir = NestedForLoopSubAir<2>;

        // This subair has the following constraints:
        // 1. Boolean enabled flag
        // 2. Disabled rows are followed by disabled rows
        // 3. Proof index increments by exactly one between enabled rows
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.idx],
                    is_first: [local.is_first_air_idx, local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.idx],
                    is_first: [next.is_first_air_idx, next.is_first],
                }
                .map_into(),
            ),
        );

        let is_transition = LoopSubAir::local_is_transition(next.is_enabled, next.is_first);
        let is_last = LoopSubAir::local_is_last(local.is_enabled, next.is_enabled, next.is_first);
        // Layer index starts from 0
        builder.when(local.is_first).assert_zero(local.layer_idx);
        // Layer index increments by 1
        builder
            .when(is_transition.clone())
            .assert_eq(next.layer_idx, local.layer_idx + AB::Expr::ONE);

        ///////////////////////////////////////////////////////////////////////
        // Dummy Row Constraints
        ///////////////////////////////////////////////////////////////////////

        let is_not_dummy = AB::Expr::ONE - local.is_dummy;
        let enabled_not_dummy = local.is_enabled * is_not_dummy.clone();
        builder
            .when(is_transition.clone())
            .assert_eq(next.is_dummy, local.is_dummy);
        builder
            .when(is_transition.clone())
            .assert_zero(local.is_dummy);
        builder.when(local.is_dummy).assert_one(local.is_first);
        builder.when(local.is_dummy).assert_one(is_last.clone());

        // constrain lambda_prime
        let lambda_prime_one = {
            let mut arr = core::array::from_fn(|_| AB::Expr::ZERO);
            arr[0] = AB::Expr::ONE;
            arr
        };
        assert_array_eq(
            &mut builder.when(local.is_first),
            local.lambda_prime,
            lambda_prime_one,
        );
        // constrain lambda_prime
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.lambda_prime,
            local.lambda,
        );

        ///////////////////////////////////////////////////////////////////////
        // Direct Interleaved Claim Constraints
        ///////////////////////////////////////////////////////////////////////

        let reduce_pair = |p0: [AB::Var; D_EF], p1: [AB::Var; D_EF], mu: [AB::Var; D_EF]| {
            ext_field_add::<AB::Expr>(
                p0,
                ext_field_multiply::<AB::Expr>(ext_field_subtract::<AB::Expr>(p1, p0), mu),
            )
        };

        let read_p_xi = reduce_pair(local.read_p0, local.read_p1, local.mu);
        let write_p_xi = reduce_pair(local.write_p0, local.write_p1, local.mu);
        let logup_p_xi = reduce_pair(local.logup_p0, local.logup_p1, local.mu);
        let logup_q_xi = reduce_pair(local.logup_q0, local.logup_q1, local.mu);
        assert_array_eq(builder, local.read_p_xi, read_p_xi.clone());
        assert_array_eq(builder, local.write_p_xi, write_p_xi.clone());
        assert_array_eq(builder, local.logup_p_xi, logup_p_xi.clone());
        assert_array_eq(builder, local.logup_q_xi, logup_q_xi.clone());

        let read_prime = ext_field_multiply::<AB::Expr>(local.read_p0, local.read_p1);
        let write_prime = ext_field_multiply::<AB::Expr>(local.write_p0, local.write_p1);
        let logup_p_cross = ext_field_add::<AB::Expr>(
            ext_field_multiply::<AB::Expr>(local.logup_p0, local.logup_q1),
            ext_field_multiply::<AB::Expr>(local.logup_p1, local.logup_q0),
        );
        let logup_q_cross = ext_field_multiply::<AB::Expr>(local.logup_q0, local.logup_q1);
        let logup_prime = ext_field_add::<AB::Expr>(
            logup_p_cross.clone(),
            ext_field_multiply::<AB::Expr>(local.lambda_prime, logup_q_cross.clone()),
        );

        assert_array_eq(
            &mut builder.when(local.read_active),
            local.read_claim,
            local.read_p_xi,
        );
        assert_array_eq(
            &mut builder.when(local.read_active),
            local.read_claim_prime,
            read_prime,
        );
        assert_array_eq(
            &mut builder.when(local.write_active),
            local.write_claim,
            local.write_p_xi,
        );
        assert_array_eq(
            &mut builder.when(local.write_active),
            local.write_claim_prime,
            write_prime,
        );
        assert_array_eq(
            &mut builder.when(local.logup_active),
            local.logup_claim,
            ext_field_add::<AB::Expr>(
                local.logup_p_xi,
                ext_field_multiply::<AB::Expr>(local.lambda, local.logup_q_xi),
            ),
        );
        assert_array_eq(
            &mut builder.when(local.logup_active),
            local.logup_claim_prime,
            logup_prime,
        );

        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.read_active),
            local.read_p0.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.read_active),
            local.read_p1.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.read_active),
            local.read_p_xi.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.read_active),
            local.read_claim.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.read_active),
            local.read_claim_prime.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.write_active),
            local.write_p0.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.write_active),
            local.write_p1.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.write_active),
            local.write_p_xi.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.write_active),
            local.write_claim.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.write_active),
            local.write_claim_prime.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_p0.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_p1.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_q0.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_q1.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_p_xi.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_q_xi.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_claim.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_claim_prime.map(Into::into),
        );

        ///////////////////////////////////////////////////////////////////////
        // Inter-Layer Constraints
        ///////////////////////////////////////////////////////////////////////

        let folded_claim = ext_field_add::<AB::Expr>(
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(local.read_weight, local.read_p_xi),
                ext_field_multiply::<AB::Expr>(local.write_weight, local.write_p_xi),
            ),
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(local.logup_p_weight, local.logup_p_xi),
                ext_field_multiply::<AB::Expr>(local.logup_q_weight, local.logup_q_xi),
            ),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.read_active),
            local.read_weight.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.write_active),
            local.write_weight.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_p_weight.map(Into::into),
        );
        assert_zeros(
            &mut builder.when(AB::Expr::ONE - local.logup_active),
            local.logup_q_weight.map(Into::into),
        );

        // Transcript index increment
        use crate::tower::tower_transcript_len::{
            ALPHA_LEN, POST_SUMCHECK_LEN, ROUND_LEN, SUMCHECK_INIT_LEN,
        };
        let tidx_after_sumcheck = local.tidx
            // Sample lambda label+sample on non-root layer
            + (AB::Expr::ONE - local.is_first) * AB::Expr::from_usize(ALPHA_LEN)
            + AB::Expr::from_usize(SUMCHECK_INIT_LEN)
            + (local.layer_idx + AB::Expr::ONE) * AB::Expr::from_usize(ROUND_LEN);
        let tidx_end = tidx_after_sumcheck.clone() + AB::Expr::from_usize(POST_SUMCHECK_LEN);
        builder
            .when(is_transition.clone())
            .assert_eq(next.tidx, tidx_end.clone());

        ///////////////////////////////////////////////////////////////////////
        // Module Interactions
        ///////////////////////////////////////////////////////////////////////

        let is_non_root_layer = local.is_enabled * (AB::Expr::ONE - local.is_first);

        let lookup_enable = local.is_enabled * is_not_dummy.clone();
        self.activity_bus.receive(
            builder,
            local.proof_idx,
            TowerActivityMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                kind: AB::Expr::from_usize(TOWER_ACTIVITY_READ),
                active: local.read_active.into(),
            },
            lookup_enable.clone(),
        );
        self.activity_bus.receive(
            builder,
            local.proof_idx,
            TowerActivityMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                kind: AB::Expr::from_usize(TOWER_ACTIVITY_WRITE),
                active: local.write_active.into(),
            },
            lookup_enable.clone(),
        );
        self.activity_bus.receive(
            builder,
            local.proof_idx,
            TowerActivityMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                kind: AB::Expr::from_usize(TOWER_ACTIVITY_LOGUP),
                active: local.logup_active.into(),
            },
            lookup_enable.clone(),
        );

        self.alpha_pow_bus.receive(
            builder,
            local.proof_idx,
            TowerAlphaPowMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                slot_kind: AB::Expr::from_usize(TOWER_ACTIVITY_READ),
                alpha: local.lambda.map(Into::into),
                weight: local.read_weight.map(Into::into),
            },
            lookup_enable.clone() * local.read_active,
        );
        self.alpha_pow_bus.receive(
            builder,
            local.proof_idx,
            TowerAlphaPowMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                slot_kind: AB::Expr::from_usize(TOWER_ACTIVITY_WRITE),
                alpha: local.lambda.map(Into::into),
                weight: local.write_weight.map(Into::into),
            },
            lookup_enable.clone() * local.write_active,
        );
        self.alpha_pow_bus.receive(
            builder,
            local.proof_idx,
            TowerAlphaPowMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                slot_kind: AB::Expr::from_usize(TOWER_ACTIVITY_LOGUP),
                alpha: local.lambda.map(Into::into),
                weight: local.logup_p_weight.map(Into::into),
            },
            lookup_enable.clone() * local.logup_active,
        );
        self.alpha_pow_bus.receive(
            builder,
            local.proof_idx,
            TowerAlphaPowMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                slot_kind: AB::Expr::from_usize(TOWER_ACTIVITY_LOGUP + 1),
                alpha: local.lambda.map(Into::into),
                weight: local.logup_q_weight.map(Into::into),
            },
            lookup_enable.clone() * local.logup_active,
        );

        // 1. TowerLayerInputBus
        // 1a. Receive GKR layers input
        self.layer_input_bus.receive(
            builder,
            local.proof_idx,
            TowerLayerInputMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                r0_claim: local.r0_claim.map(Into::into),
                w0_claim: local.w0_claim.map(Into::into),
                q0_claim: local.q0_claim.map(Into::into),
            },
            local.is_first * is_not_dummy.clone(),
        );
        // 2. TowerLayerOutputBus
        // 2a. Send GKR input layer claims back
        self.layer_output_bus.send(
            builder,
            local.proof_idx,
            TowerLayerOutputMessage {
                idx: local.idx.into(),
                tidx: tidx_end,
                layer_idx_end: local.layer_idx.into(),
                input_layer_claim: folded_claim.map(Into::into),
                lambda: local.lambda.map(Into::into),
                mu: local.mu.map(Into::into),
            },
            is_last.clone() * is_not_dummy.clone(),
        );
        // 3. TowerSumcheckInputBus
        // 3a. Send claim to sumcheck
        // Native verifier runs sumcheck for every tower round, including root.
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckInputMessage {
                idx: local.idx.into(),
                // TowerLayerSumcheckAir keeps its internal bus layer key 1-based
                // so `layer_idx - 1` can address the previous GKR layer challenge.
                layer_idx: local.layer_idx + AB::Expr::ONE,
                is_last_layer: is_last.clone(),
                tidx: local.tidx
                    + (AB::Expr::ONE - local.is_first) * AB::Expr::from_usize(ALPHA_LEN)
                    + AB::Expr::from_usize(SUMCHECK_INIT_LEN),
                claim: local.sumcheck_claim_in.map(Into::into),
            },
            enabled_not_dummy.clone(),
        );
        // 3. TowerSumcheckOutputBus
        // 3a. Receive sumcheck results
        let weighted_prime_fold = ext_field_add::<AB::Expr>(
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(local.read_weight, local.read_claim_prime),
                ext_field_multiply::<AB::Expr>(local.write_weight, local.write_claim_prime),
            ),
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(local.logup_p_weight, logup_p_cross),
                ext_field_multiply::<AB::Expr>(local.logup_q_weight, logup_q_cross),
            ),
        );
        let expected_sumcheck_claim_out =
            ext_field_multiply::<AB::Expr>(weighted_prime_fold, local.eq_at_r_prime);
        let _ = expected_sumcheck_claim_out;
        // TODO(recursion-v2): re-enable the native tower expected-evaluation
        // equality here once the full tower transcript/replay oracle is wired.
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            TowerSumcheckOutputMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx + AB::Expr::ONE,
                tidx: tidx_after_sumcheck.clone(),
                claim_out: local.sumcheck_claim_out.map(Into::into),
                eq_at_r_prime: local.eq_at_r_prime.map(Into::into),
            },
            enabled_not_dummy.clone(),
        );
        // 4. TowerSumcheckChallengeBus
        // 4a. Send challenge mu
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx + AB::Expr::ONE,
                sumcheck_round: local.layer_idx + AB::Expr::ONE,
                challenge: local.mu.map(Into::into),
            },
            local.is_enabled * (AB::Expr::ONE - is_last) * is_not_dummy.clone(),
        );

        ///////////////////////////////////////////////////////////////////////
        // External Interactions
        ///////////////////////////////////////////////////////////////////////

        // 1. TranscriptBus
        // sample lambda and mu
        // in root & intermediate layer: for next.sumcheck_claim_in
        // in last layer: for send back to GKR input layer
        // 1a. Sample `lambda` — only on non-root layers.
        //     Root layer uses alpha_logup (set in trace), not a transcript sample.
        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(i),
                    value: local.lambda[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                is_non_root_layer.clone()
                    * is_not_dummy.clone()
                    * AB::Expr::from_bool(!crate::system::TOWER_PREFIX_ONLY),
            );
        }
        // 1b. Observe layer claims
        let tidx = tidx_after_sumcheck;
        // 1c. Sample `mu`
        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: tidx.clone() + AB::Expr::from_usize(i),
                    value: local.mu[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled
                    * is_not_dummy.clone()
                    * AB::Expr::from_bool(!crate::system::TOWER_PREFIX_ONLY),
            );
        }
    }
}
