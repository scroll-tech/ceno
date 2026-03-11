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

use crate::gkr::{
    GkrSumcheckChallengeBus, GkrSumcheckChallengeMessage,
    bus::{
        GkrLayerInputBus, GkrLayerInputMessage, GkrLayerOutputBus, GkrLayerOutputMessage,
        GkrLogupClaimBus, GkrLogupClaimInputBus, GkrLogupClaimMessage, GkrLogupInitClaimBus,
        GkrLogupInitClaimInputBus, GkrLogupInitClaimMessage, GkrLogupInitLayerMessage,
        GkrLogupLayerChallengeMessage, GkrProdInitClaimMessage, GkrProdInitLayerMessage,
        GkrProdLayerChallengeMessage, GkrProdReadClaimBus, GkrProdReadClaimInputBus,
        GkrProdReadInitClaimBus, GkrProdReadInitClaimInputBus, GkrProdSumClaimMessage,
        GkrProdWriteClaimBus, GkrProdWriteClaimInputBus, GkrProdWriteInitClaimBus,
        GkrProdWriteInitClaimInputBus, GkrSumcheckInputBus, GkrSumcheckInputMessage,
        GkrSumcheckOutputBus, GkrSumcheckOutputMessage,
    },
};

use recursion_circuit::{
    bus::{TranscriptBus, XiRandomnessBus, XiRandomnessMessage},
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{assert_zeros, ext_field_add},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct GkrLayerCols<T> {
    /// Whether the current row is enabled (i.e. not padding)
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
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
    /// Reduction point
    pub mu: [T; D_EF],

    pub sumcheck_claim_in: [T; D_EF],

    pub read_claim: [T; D_EF],
    pub write_claim: [T; D_EF],
    pub logup_claim: [T; D_EF],
    pub num_prod_count: T,
    pub num_logup_count: T,

    /// Received from GkrLayerSumcheckAir
    pub eq_at_r_prime: [T; D_EF],

    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    pub q0_claim: [T; D_EF],
}

/// The GkrLayerAir handles layer-to-layer transitions in the GKR protocol
pub struct GkrLayerAir {
    // External buses
    pub xi_randomness_bus: XiRandomnessBus,
    pub transcript_bus: TranscriptBus,
    // Internal buses
    pub layer_input_bus: GkrLayerInputBus,
    pub layer_output_bus: GkrLayerOutputBus,
    pub sumcheck_input_bus: GkrSumcheckInputBus,
    pub sumcheck_output_bus: GkrSumcheckOutputBus,
    pub sumcheck_challenge_bus: GkrSumcheckChallengeBus,
    pub prod_read_claim_input_bus: GkrProdReadClaimInputBus,
    pub prod_read_claim_bus: GkrProdReadClaimBus,
    pub prod_write_claim_input_bus: GkrProdWriteClaimInputBus,
    pub prod_write_claim_bus: GkrProdWriteClaimBus,
    pub prod_read_init_claim_input_bus: GkrProdReadInitClaimInputBus,
    pub prod_read_init_claim_bus: GkrProdReadInitClaimBus,
    pub prod_write_init_claim_input_bus: GkrProdWriteInitClaimInputBus,
    pub prod_write_init_claim_bus: GkrProdWriteInitClaimBus,
    pub logup_claim_input_bus: GkrLogupClaimInputBus,
    pub logup_claim_bus: GkrLogupClaimBus,
    pub logup_init_claim_input_bus: GkrLogupInitClaimInputBus,
    pub logup_init_claim_bus: GkrLogupInitClaimBus,
}

impl<F: Field> BaseAir<F> for GkrLayerAir {
    fn width(&self) -> usize {
        GkrLayerCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for GkrLayerAir {}
impl<F: Field> PartitionedBaseAir<F> for GkrLayerAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for GkrLayerAir
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &GkrLayerCols<AB::Var> = (*local).borrow();
        let next: &GkrLayerCols<AB::Var> = (*next).borrow();

        ///////////////////////////////////////////////////////////////////////
        // Boolean Constraints
        ///////////////////////////////////////////////////////////////////////

        builder.assert_bool(local.is_dummy);
        builder.assert_bool(local.is_first_air_idx);

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
        // Root Layer Constraints
        ///////////////////////////////////////////////////////////////////////

        assert_zeros(
            &mut builder.when(local.is_first),
            local.sumcheck_claim_in.map(Into::into),
        );

        ///////////////////////////////////////////////////////////////////////
        // Inter-Layer Constraints
        ///////////////////////////////////////////////////////////////////////

        let read_plus_write =
            ext_field_add::<AB::Expr>(local.read_claim, local.write_claim);
        let folded_claim = ext_field_add::<AB::Expr>(read_plus_write, local.logup_claim);
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.sumcheck_claim_in,
            folded_claim,
        );

        // Transcript index increment
        let tidx_after_sumcheck = local.tidx
            // Sample lambda on non-root layer
            + (AB::Expr::ONE - local.is_first) * AB::Expr::from_usize(D_EF)
            + local.layer_idx * AB::Expr::from_usize(4 * D_EF);
        let tidx_end = tidx_after_sumcheck.clone() + AB::Expr::from_usize(5 * D_EF);
        builder
            .when(is_transition.clone())
            .assert_eq(next.tidx, tidx_end.clone());

        ///////////////////////////////////////////////////////////////////////
        // Module Interactions
        ///////////////////////////////////////////////////////////////////////

        let is_not_dummy = AB::Expr::ONE - local.is_dummy;
        let is_non_root_layer = local.is_enabled * (AB::Expr::ONE - local.is_first);

        let tidx_for_claims = tidx_after_sumcheck.clone();
        let challenge_msg = GkrProdLayerChallengeMessage {
            idx: local.idx.into(),
            layer_idx: local.layer_idx.into(),
            tidx: tidx_for_claims.clone(),
            lambda: local.lambda.map(Into::into),
            mu: local.mu.map(Into::into),
        };
        self.prod_read_claim_input_bus.send(
            builder,
            local.proof_idx,
            challenge_msg.clone(),
            is_not_dummy.clone(),
        );
        self.prod_write_claim_input_bus.send(
            builder,
            local.proof_idx,
            challenge_msg,
            is_not_dummy.clone(),
        );
        self.logup_claim_input_bus.send(
            builder,
            local.proof_idx,
            GkrLogupLayerChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: tidx_for_claims.clone(),
                lambda: local.lambda.map(Into::into),
                mu: local.mu.map(Into::into),
            },
            is_not_dummy.clone(),
        );
        self.prod_read_claim_bus.receive(
            builder,
            local.proof_idx,
            GkrProdSumClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                claim: local.read_claim.map(Into::into),
                num_prod_count: local.num_prod_count.into(),
            },
            is_not_dummy.clone(),
        );
        self.prod_write_claim_bus.receive(
            builder,
            local.proof_idx,
            GkrProdSumClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                claim: local.write_claim.map(Into::into),
                num_prod_count: local.num_prod_count.into(),
            },
            is_not_dummy.clone(),
        );
        self.logup_claim_bus.receive(
            builder,
            local.proof_idx,
            GkrLogupClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                claim: local.logup_claim.map(Into::into),
                num_logup_count: local.num_logup_count.into(),
            },
            is_not_dummy.clone(),
        );

        let is_root_layer = local.is_first;
        let init_msg = GkrProdInitLayerMessage {
            idx: local.idx.into(),
            layer_idx: local.layer_idx.into(),
            tidx: local.tidx.into(),
        };
        self.prod_read_init_claim_input_bus.send(
            builder,
            local.proof_idx,
            init_msg.clone(),
            is_root_layer * is_not_dummy.clone(),
        );
        self.prod_write_init_claim_input_bus.send(
            builder,
            local.proof_idx,
            init_msg,
            is_root_layer * is_not_dummy.clone(),
        );
        self.logup_init_claim_input_bus.send(
            builder,
            local.proof_idx,
            GkrLogupInitLayerMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: local.tidx.into(),
            },
            is_root_layer * is_not_dummy.clone(),
        );
        self.prod_read_init_claim_bus.receive(
            builder,
            local.proof_idx,
            GkrProdInitClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                acc_sum: local.r0_claim.map(Into::into),
                num_prod_count: local.num_prod_count.into(),
            },
            is_root_layer * is_not_dummy.clone(),
        );
        self.prod_write_init_claim_bus.receive(
            builder,
            local.proof_idx,
            GkrProdInitClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                acc_sum: local.w0_claim.map(Into::into),
                num_prod_count: local.num_prod_count.into(),
            },
            is_root_layer * is_not_dummy.clone(),
        );
        self.logup_init_claim_bus.receive(
            builder,
            local.proof_idx,
            GkrLogupInitClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                acc_p_cross: core::array::from_fn(|_| AB::Expr::ZERO),
                acc_q_cross: local.q0_claim.map(Into::into),
                num_logup_count: local.num_logup_count.into(),
            },
            is_root_layer * is_not_dummy.clone(),
        );

        // 1. GkrLayerInputBus
        // 1a. Receive GKR layers input
        self.layer_input_bus.receive(
            builder,
            local.proof_idx,
            GkrLayerInputMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                r0_claim: local.r0_claim.map(Into::into),
                w0_claim: local.w0_claim.map(Into::into),
                q0_claim: local.q0_claim.map(Into::into),
            },
            local.is_first_air_idx * is_not_dummy.clone(),
        );
        // 2. GkrLayerOutputBus
        // 2a. Send GKR input layer claims back
        self.layer_output_bus.send(
            builder,
            local.proof_idx,
            GkrLayerOutputMessage {
                idx: local.idx.into(),
                tidx: tidx_end,
                layer_idx_end: local.layer_idx.into(),
                input_layer_claim: local.sumcheck_claim_in.map(Into::into),
            },
            is_last.clone() * is_not_dummy.clone(),
        );
        // 3. GkrSumcheckInputBus
        // 3a. Send claim to sumcheck
        // only send sumcheck on non root layer
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            GkrSumcheckInputMessage {
                layer_idx: local.layer_idx.into(),
                is_last_layer: is_last.clone(),
                tidx: local.tidx + AB::Expr::from_usize(D_EF),
                claim: local.sumcheck_claim_in.map(Into::into),
            },
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        // 3. GkrSumcheckOutputBus
        // 3a. Receive sumcheck results
        let sumcheck_claim_out = local.sumcheck_claim_in;
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            GkrSumcheckOutputMessage {
                layer_idx: local.layer_idx.into(),
                tidx: tidx_after_sumcheck.clone(),
                claim_out: sumcheck_claim_out.map(Into::into),
                eq_at_r_prime: local.eq_at_r_prime.map(Into::into),
            },
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        // 4. GkrSumcheckChallengeBus
        // 4a. Send challenge mu
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            GkrSumcheckChallengeMessage {
                layer_idx: local.layer_idx.into(),
                sumcheck_round: AB::Expr::ZERO,
                challenge: local.mu.map(Into::into),
            },
            is_transition.clone() * is_not_dummy.clone(),
        );

        ///////////////////////////////////////////////////////////////////////
        // External Interactions
        ///////////////////////////////////////////////////////////////////////

        // 1. TranscriptBus
        // 1a. Sample `lambda`
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            local.tidx,
            local.lambda,
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        // 1b. Observe layer claims
        let tidx = tidx_after_sumcheck;
        // 1c. Sample `mu`
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            tidx,
            local.mu,
            local.is_enabled * is_not_dummy.clone(),
        );

        // 2. XiRandomnessBus
        // 2a. Send shared randomness
        self.xi_randomness_bus.send(
            builder,
            local.proof_idx,
            XiRandomnessMessage {
                idx: AB::Expr::ZERO,
                xi: local.mu.map(Into::into),
            },
            is_last * is_not_dummy.clone(),
        );
    }
}
