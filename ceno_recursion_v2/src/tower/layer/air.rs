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
    bus::{AirShapeBus, AirShapeBusMessage},
    proof_shape::bus::AirShapeProperty,
    tower::{
        TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage,
        bus::{
            TowerLayerInputBus, TowerLayerInputMessage, TowerLayerOutputBus,
            TowerLayerOutputMessage, TowerLogupClaimBus, TowerLogupClaimInputBus,
            TowerLogupClaimMessage, TowerLogupLayerChallengeMessage,
            TowerProdLayerChallengeMessage, TowerProdReadClaimBus, TowerProdReadClaimInputBus,
            TowerProdSumClaimMessage, TowerProdWriteClaimBus, TowerProdWriteClaimInputBus,
            TowerSumcheckInputBus, TowerSumcheckInputMessage, TowerSumcheckOutputBus,
            TowerSumcheckOutputMessage,
        },
    },
    utils::{label_field_len, transcript_receive_label},
};

use recursion_circuit::{
    bus::{TranscriptBus, TranscriptBusMessage},
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::ext_field_add,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerLayerCols<T> {
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
    /// Challenge inherited from previous layer
    pub lambda_prime: [T; D_EF],
    /// Reduction point
    pub mu: [T; D_EF],
    /// Initial point sampled before the tower layer loop.
    pub beta_logup: [T; D_EF],

    pub sumcheck_claim_in: [T; D_EF],

    pub read_claim: [T; D_EF],
    pub read_claim_prime: [T; D_EF],
    pub write_claim: [T; D_EF],
    pub write_claim_prime: [T; D_EF],
    pub logup_claim: [T; D_EF],
    pub logup_claim_prime: [T; D_EF],
    pub num_read_count: T,
    pub num_write_count: T,
    pub num_logup_count: T,
    pub sumcheck_claim_out: [T; D_EF],

    /// Received from TowerLayerSumcheckAir
    pub eq_at_r_prime: [T; D_EF],

    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    pub q0_claim: [T; D_EF],
}

/// The TowerLayerAir handles layer-to-layer transitions in the GKR protocol
pub struct TowerLayerAir {
    // External buses
    pub transcript_bus: TranscriptBus,
    pub air_shape_bus: AirShapeBus,
    // Internal buses
    pub layer_input_bus: TowerLayerInputBus,
    pub layer_output_bus: TowerLayerOutputBus,
    pub sumcheck_input_bus: TowerSumcheckInputBus,
    pub sumcheck_output_bus: TowerSumcheckOutputBus,
    pub sumcheck_challenge_bus: TowerSumcheckChallengeBus,
    pub prod_read_claim_input_bus: TowerProdReadClaimInputBus,
    pub prod_read_claim_bus: TowerProdReadClaimBus,
    pub prod_write_claim_input_bus: TowerProdWriteClaimInputBus,
    pub prod_write_claim_bus: TowerProdWriteClaimBus,
    pub logup_claim_input_bus: TowerLogupClaimInputBus,
    pub logup_claim_bus: TowerLogupClaimBus,
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
        // Inter-Layer Constraints
        ///////////////////////////////////////////////////////////////////////

        let read_plus_write = ext_field_add::<AB::Expr>(local.read_claim, local.write_claim);
        let folded_claim = ext_field_add::<AB::Expr>(read_plus_write, local.logup_claim);
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.sumcheck_claim_in,
            folded_claim.clone(),
        );

        // Transcript index increment
        use crate::tower::tower_transcript_len::{
            ALPHA_LEN, MERGE_LEN, ROUND_LEN, SUMCHECK_INIT_LEN,
        };
        let non_root_layer = AB::Expr::ONE - local.is_first;
        let sumcheck_init_tidx =
            local.tidx + non_root_layer.clone() * AB::Expr::from_usize(ALPHA_LEN);
        let tidx_after_sumcheck = local.tidx
            + non_root_layer.clone() * AB::Expr::from_usize(ALPHA_LEN)
            + AB::Expr::from_usize(SUMCHECK_INIT_LEN)
            + (local.layer_idx + AB::Expr::ONE) * AB::Expr::from_usize(ROUND_LEN);
        let read_count: AB::Expr = local.num_read_count.into();
        let write_count: AB::Expr = local.num_write_count.into();
        let logup_count: AB::Expr = local.num_logup_count.into();
        let read_claim_span = read_count.clone() * AB::Expr::from_usize(2 * D_EF);
        let write_claim_span = write_count.clone() * AB::Expr::from_usize(2 * D_EF);
        let logup_claim_span = logup_count.clone() * AB::Expr::from_usize(4 * D_EF);
        let read_claim_tidx = tidx_after_sumcheck.clone();
        let write_claim_tidx = read_claim_tidx.clone() + read_claim_span;
        let logup_claim_tidx = write_claim_tidx.clone() + write_claim_span;
        let merge_label_tidx = logup_claim_tidx.clone() + logup_claim_span;
        let tidx_end = merge_label_tidx.clone() + AB::Expr::from_usize(MERGE_LEN);
        builder
            .when(is_transition.clone())
            .assert_eq(next.tidx, tidx_end.clone());

        ///////////////////////////////////////////////////////////////////////
        // Module Interactions
        ///////////////////////////////////////////////////////////////////////

        let is_not_dummy = AB::Expr::ONE - local.is_dummy;
        let is_non_root_layer = local.is_enabled * (AB::Expr::ONE - local.is_first);

        let lookup_enable = local.is_enabled * is_not_dummy.clone();
        self.air_shape_bus.lookup_key(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.idx.into(),
                property_idx: AirShapeProperty::NumRead.to_field(),
                value: local.num_read_count.into(),
            },
            lookup_enable.clone(),
        );
        self.air_shape_bus.lookup_key(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.idx.into(),
                property_idx: AirShapeProperty::NumWrite.to_field(),
                value: local.num_write_count.into(),
            },
            lookup_enable.clone(),
        );
        self.air_shape_bus.lookup_key(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.idx.into(),
                property_idx: AirShapeProperty::NumLk.to_field(),
                value: local.num_logup_count.into(),
            },
            lookup_enable.clone(),
        );

        self.prod_read_claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerProdLayerChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: read_claim_tidx,
                lambda: local.lambda.map(Into::into),
                lambda_prime: local.lambda_prime.map(Into::into),
                mu: local.mu.map(Into::into),
                root_prime_claim: local.read_claim_prime.map(Into::into),
            },
            is_not_dummy.clone() * read_count.clone(),
        );
        // TODO separate lambda, lambda_prime for prod-write the relation should be local.lambda^(num_read)
        self.prod_write_claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerProdLayerChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: write_claim_tidx,
                lambda: local.lambda.map(Into::into),
                lambda_prime: local.lambda_prime.map(Into::into),
                mu: local.mu.map(Into::into),
                root_prime_claim: local.write_claim_prime.map(Into::into),
            },
            is_not_dummy.clone() * write_count.clone(),
        );
        // TODO separate lambda, lambda_prime for logup the relation should be local.lambda^(num_read + num_write)
        self.logup_claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerLogupLayerChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: logup_claim_tidx,
                lambda: local.lambda.map(Into::into),
                lambda_prime: local.lambda_prime.map(Into::into),
                mu: local.mu.map(Into::into),
                root_prime_claim: local.logup_claim_prime.map(Into::into),
            },
            is_not_dummy.clone() * logup_count.clone(),
        );
        self.prod_read_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerProdSumClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_claim: local.read_claim.map(Into::into),
                lambda_prime_claim: local.read_claim_prime.map(Into::into),
                num_prod_count: local.num_read_count.into(),
            },
            is_not_dummy.clone() * read_count,
        );
        self.prod_write_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerProdSumClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_claim: local.write_claim.map(Into::into),
                lambda_prime_claim: local.write_claim_prime.map(Into::into),
                num_prod_count: local.num_write_count.into(),
            },
            is_not_dummy.clone() * write_count,
        );
        self.logup_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerLogupClaimMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_claim: local.logup_claim.map(Into::into),
                lambda_prime_claim: local.logup_claim_prime.map(Into::into),
                num_logup_count: local.num_logup_count.into(),
            },
            is_not_dummy.clone() * logup_count,
        );

        let root_layer_mask = local.is_first * is_not_dummy.clone();
        assert_array_eq(
            &mut builder.when(root_layer_mask.clone()),
            local.read_claim_prime,
            local.r0_claim,
        );
        assert_array_eq(
            &mut builder.when(root_layer_mask.clone()),
            local.write_claim_prime,
            local.w0_claim,
        );
        assert_array_eq(
            &mut builder.when(root_layer_mask.clone()),
            local.logup_claim_prime,
            local.q0_claim,
        );

        // 1. TowerLayerInputBus
        // 1a. Receive GKR layers input
        self.layer_input_bus.receive(
            builder,
            local.proof_idx,
            TowerLayerInputMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                beta_logup: local.beta_logup.map(Into::into),
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
        // only send sumcheck on non root layer
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckInputMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                is_last_layer: is_last.clone(),
                tidx: sumcheck_init_tidx.clone() + AB::Expr::from_usize(SUMCHECK_INIT_LEN),
                claim: local.sumcheck_claim_in.map(Into::into),
            },
            local.is_enabled * is_not_dummy.clone(),
        );
        // 3. TowerSumcheckOutputBus
        // 3a. Receive sumcheck results
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            TowerSumcheckOutputMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: tidx_after_sumcheck.clone(),
                claim_out: local.sumcheck_claim_out.map(Into::into),
                eq_at_r_prime: local.eq_at_r_prime.map(Into::into),
            },
            local.is_enabled * is_not_dummy.clone(),
        );
        // 4. TowerSumcheckChallengeBus
        // 4a. Send the root sumcheck's initial point.
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                idx: local.idx.into(),
                layer_idx: AB::Expr::ZERO,
                sumcheck_round: AB::Expr::ZERO,
                challenge: local.beta_logup.map(Into::into),
            },
            root_layer_mask,
        );
        // 4b. Send merge challenge to the final round slot of the next layer.
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                idx: local.idx.into(),
                layer_idx: local.layer_idx + AB::Expr::ONE,
                sumcheck_round: local.layer_idx + AB::Expr::ONE,
                challenge: local.mu.map(Into::into),
            },
            is_transition.clone() * is_not_dummy.clone(),
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
        let combine_label = b"combine subset evals";
        transcript_receive_label(
            &self.transcript_bus,
            builder,
            local.proof_idx,
            local.tidx,
            combine_label,
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            local.tidx + AB::Expr::from_usize(label_field_len(combine_label)),
            local.lambda,
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        let init_enabled = local.is_enabled * is_not_dummy.clone();
        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: sumcheck_init_tidx.clone(),
                value: local.layer_idx + AB::Expr::ONE,
                is_sample: AB::Expr::ZERO,
            },
            init_enabled.clone(),
        );
        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: sumcheck_init_tidx.clone() + AB::Expr::ONE,
                value: AB::Expr::ZERO,
                is_sample: AB::Expr::ZERO,
            },
            init_enabled.clone(),
        );
        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: sumcheck_init_tidx.clone() + AB::Expr::TWO,
                value: AB::Expr::from_u32(3),
                is_sample: AB::Expr::ZERO,
            },
            init_enabled.clone(),
        );
        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: sumcheck_init_tidx + AB::Expr::from_u32(3),
                value: AB::Expr::ZERO,
                is_sample: AB::Expr::ZERO,
            },
            init_enabled,
        );
        // 1b. Observe layer claims in the claim AIRs, then sample the merge challenge.
        let merge_label = b"merge";
        transcript_receive_label(
            &self.transcript_bus,
            builder,
            local.proof_idx,
            merge_label_tidx.clone(),
            merge_label,
            local.is_enabled * is_not_dummy.clone(),
        );
        // 1c. Sample `mu`
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            merge_label_tidx + AB::Expr::from_usize(label_field_len(merge_label)),
            local.mu,
            local.is_enabled * is_not_dummy.clone(),
        );
    }
}
