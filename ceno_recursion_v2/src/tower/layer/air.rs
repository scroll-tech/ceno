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
    bus::AirShapeBus,
    tower::{
        TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage,
        bus::{
            TowerLayerInputBus, TowerLayerInputMessage, TowerLayerOutputBus,
            TowerLayerOutputMessage, TowerLogupClaimBus, TowerLogupClaimInputBus,
            TowerLogupClaimMessage, TowerLogupLayerChallengeMessage, TowerProdLayerInputMessage,
            TowerProdReadClaimBus, TowerProdReadClaimInputBus, TowerProdSumClaimMessage,
            TowerProdWriteClaimBus, TowerProdWriteClaimInputBus, TowerSumcheckInputBus,
            TowerSumcheckInputMessage, TowerSumcheckOutputBus, TowerSumcheckOutputMessage,
        },
    },
};

use recursion_circuit::{
    bus::TranscriptBus,
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{assert_zeros, ext_field_add, ext_field_multiply},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerLayerCols<T> {
    /// Whether the current row is enabled (i.e. not padding)
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub chip_id: T,
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

    pub read_claim: [T; D_EF],
    pub read_claim_prime: [T; D_EF],
    pub write_claim: [T; D_EF],
    pub write_claim_prime: [T; D_EF],
    pub logup_claim: [T; D_EF],
    pub logup_claim_prime: [T; D_EF],
    pub read_eval_claim: [T; D_EF],
    pub write_eval_claim: [T; D_EF],
    pub logup_eval_claim: [T; D_EF],
    pub read_lambda_end: [T; D_EF],
    pub read_lambda_prime_end: [T; D_EF],
    pub write_lambda_end: [T; D_EF],
    pub write_lambda_prime_end: [T; D_EF],
    pub num_read_count: T,
    pub num_write_count: T,
    pub num_logup_count: T,
    pub num_layers: T,

    /// Received from TowerLayerSumcheckAir
    pub eq_at_r_prime: [T; D_EF],

    pub initial_tower_claim: [T; D_EF],
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
        // Root Layer Constraints
        ///////////////////////////////////////////////////////////////////////

        assert_zeros(
            &mut builder.when(local.is_first),
            local.sumcheck_claim_in.map(Into::into),
        );

        ///////////////////////////////////////////////////////////////////////
        // Inter-Layer Constraints
        ///////////////////////////////////////////////////////////////////////

        let read_plus_write = ext_field_add::<AB::Expr>(local.read_claim, local.write_claim);
        let folded_claim = ext_field_add::<AB::Expr>(read_plus_write, local.logup_claim);
        assert_array_eq(
            &mut builder.when(local.is_first),
            folded_claim.clone(),
            local.initial_tower_claim,
        );
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.sumcheck_claim_in,
            folded_claim.clone(),
        );
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.read_eval_claim,
            local.read_claim_prime,
        );
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.write_eval_claim,
            local.write_claim_prime,
        );
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.logup_eval_claim,
            local.logup_claim_prime,
        );

        // Transcript index increment
        use crate::tower::tower_transcript_len::{
            ALPHA_BETA_LEN, ALPHA_LEN, LABEL_COMBINE, LABEL_COMBINE_VALUES, LABEL_MERGE,
            LABEL_MERGE_VALUES, LABEL_PRODUCT_SUM, LABEL_PRODUCT_SUM_VALUES, MERGE_LEN, ROUND_LEN,
            SUMCHECK_INIT_LEN,
        };
        let out_eval_span = (local.num_read_count * AB::Expr::from_usize(2)
            + local.num_write_count * AB::Expr::from_usize(2)
            + local.num_logup_count * AB::Expr::from_usize(4))
            * AB::Expr::from_usize(D_EF);
        let non_root = AB::Expr::ONE - local.is_first;
        let sumcheck_span = AB::Expr::from_usize(SUMCHECK_INIT_LEN)
            + local.layer_idx * AB::Expr::from_usize(ROUND_LEN);
        let tidx_after_sumcheck = local.tidx + non_root.clone() * sumcheck_span.clone();
        let root_span = out_eval_span.clone() + AB::Expr::from_usize(ALPHA_BETA_LEN);
        let non_root_span =
            sumcheck_span + out_eval_span.clone() + AB::Expr::from_usize(MERGE_LEN + ALPHA_LEN);
        let layer_span = local.is_first * root_span + non_root.clone() * non_root_span;
        let tidx_end = local.tidx + layer_span;
        builder
            .when(is_transition.clone())
            .assert_eq(next.tidx, tidx_end.clone());

        ///////////////////////////////////////////////////////////////////////
        // Module Interactions
        ///////////////////////////////////////////////////////////////////////

        let is_not_dummy = AB::Expr::ONE - local.is_dummy;
        let is_non_root_layer = local.is_enabled * (AB::Expr::ONE - local.is_first);

        let active_non_dummy = local.is_enabled * is_not_dummy.clone();
        let tidx_for_claims = tidx_after_sumcheck.clone();
        let prod_eval_span = AB::Expr::from_usize(2 * D_EF);
        let read_tidx = tidx_for_claims.clone();
        let write_tidx = read_tidx.clone() + local.num_read_count * prod_eval_span.clone();
        let logup_tidx = write_tidx.clone() + local.num_write_count * prod_eval_span;
        let read_claim_mult = active_non_dummy.clone() * local.num_read_count;
        let write_claim_mult = active_non_dummy.clone() * local.num_write_count;
        let logup_claim_mult = active_non_dummy.clone() * local.num_logup_count;
        let lambda_one = {
            let mut arr = core::array::from_fn(|_| AB::Expr::ZERO);
            arr[0] = AB::Expr::ONE;
            arr
        };
        self.prod_read_claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerProdLayerInputMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                tidx: read_tidx,
                lambda_next: local.lambda.map(Into::into),
                lambda_cur: local.lambda_prime.map(Into::into),
                mu: local.mu.map(Into::into),
                prod_offset: AB::Expr::ZERO,
                lambda_next_start: lambda_one.clone(),
                lambda_cur_start: lambda_one.clone(),
                num_prod_count: local.num_read_count.into(),
            },
            read_claim_mult.clone(),
        );
        self.prod_write_claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerProdLayerInputMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                tidx: write_tidx,
                lambda_next: local.lambda.map(Into::into),
                lambda_cur: local.lambda_prime.map(Into::into),
                mu: local.mu.map(Into::into),
                prod_offset: local.num_read_count.into(),
                lambda_next_start: local.read_lambda_end.map(Into::into),
                lambda_cur_start: local.read_lambda_prime_end.map(Into::into),
                num_prod_count: local.num_write_count.into(),
            },
            write_claim_mult.clone(),
        );
        self.logup_claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerLogupLayerChallengeMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                tidx: logup_tidx,
                lambda_next: local.lambda.map(Into::into),
                lambda_cur: local.lambda_prime.map(Into::into),
                mu: local.mu.map(Into::into),
                lambda_next_start: local.write_lambda_end.map(Into::into),
                lambda_cur_start: local.write_lambda_prime_end.map(Into::into),
                num_logup_count: local.num_logup_count.into(),
            },
            logup_claim_mult.clone(),
        );
        self.prod_read_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerProdSumClaimMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                lambda_next_claim: local.read_claim.map(Into::into),
                lambda_cur_claim: local.read_claim_prime.map(Into::into),
                lambda_next_end: local.read_lambda_end.map(Into::into),
                lambda_cur_end: local.read_lambda_prime_end.map(Into::into),
            },
            read_claim_mult,
        );
        self.prod_write_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerProdSumClaimMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                lambda_next_claim: local.write_claim.map(Into::into),
                lambda_cur_claim: local.write_claim_prime.map(Into::into),
                lambda_next_end: local.write_lambda_end.map(Into::into),
                lambda_cur_end: local.write_lambda_prime_end.map(Into::into),
            },
            write_claim_mult,
        );
        self.logup_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerLogupClaimMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                lambda_next_claim: local.logup_claim.map(Into::into),
                lambda_cur_claim: local.logup_claim_prime.map(Into::into),
            },
            logup_claim_mult,
        );

        // 1. TowerLayerInputBus
        // 1a. Receive GKR layers input
        self.layer_input_bus.receive(
            builder,
            local.proof_idx,
            TowerLayerInputMessage {
                chip_id: local.chip_id.into(),
                tidx: local.tidx.into(),
                num_layers: local.num_layers.into(),
                num_read_specs: local.num_read_count.into(),
                num_write_specs: local.num_write_count.into(),
                num_logup_specs: local.num_logup_count.into(),
                initial_tower_claim: local.initial_tower_claim.map(Into::into),
            },
            local.is_first * active_non_dummy.clone(),
        );
        // 2. TowerLayerOutputBus
        // 2a. Send GKR input layer claims back
        self.layer_output_bus.send(
            builder,
            local.proof_idx,
            TowerLayerOutputMessage {
                chip_id: local.chip_id.into(),
                tidx: tidx_end,
                layer_idx_end: local.layer_idx.into(),
                input_layer_claim: folded_claim.map(Into::into),
                lambda_next: local.lambda.map(Into::into),
                mu: local.mu.map(Into::into),
            },
            is_last.clone() * active_non_dummy.clone(),
        );
        // 3. TowerSumcheckInputBus
        // 3a. Send claim to sumcheck
        // only send sumcheck on non root layer
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckInputMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                is_last_layer: is_last.clone(),
                tidx: local.tidx + AB::Expr::from_usize(SUMCHECK_INIT_LEN),
                claim: local.sumcheck_claim_in.map(Into::into),
            },
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        // 3. TowerSumcheckOutputBus
        // 3a. Receive sumcheck results
        let prime_fold = ext_field_add::<AB::Expr>(local.read_claim_prime, local.write_claim_prime);
        let sumcheck_claim_out = ext_field_multiply::<AB::Expr>(
            ext_field_add::<AB::Expr>(prime_fold, local.logup_claim_prime),
            local.eq_at_r_prime,
        );
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            TowerSumcheckOutputMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                tidx: tidx_after_sumcheck.clone(),
                claim_out: sumcheck_claim_out.map(Into::into),
                eq_at_r_prime: local.eq_at_r_prime.map(Into::into),
            },
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        // 4. TowerSumcheckChallengeBus
        // 4a. Send challenge mu
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                chip_id: local.chip_id.into(),
                layer_idx: local.layer_idx.into(),
                sumcheck_round: local.layer_idx.into(),
                challenge: local.mu.map(Into::into),
            },
            is_transition.clone() * active_non_dummy,
        );

        ///////////////////////////////////////////////////////////////////////
        // External Interactions
        ///////////////////////////////////////////////////////////////////////

        // 1. TranscriptBus
        let root_lambda_label_tidx = local.tidx + out_eval_span.clone();
        for (i, value) in LABEL_COMBINE_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                root_lambda_label_tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                local.is_enabled * local.is_first * is_not_dummy.clone(),
            );
        }
        let root_lambda_tidx = root_lambda_label_tidx.clone() + AB::Expr::from_usize(LABEL_COMBINE);

        let non_root_init_tidx = local.tidx;
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            non_root_init_tidx,
            local.layer_idx,
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            local.tidx + AB::Expr::ONE,
            AB::Expr::ZERO,
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            local.tidx + AB::Expr::from_usize(2),
            AB::Expr::from_usize(3),
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            local.tidx + AB::Expr::from_usize(3),
            AB::Expr::ZERO,
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );

        let root_mu_label_tidx = root_lambda_tidx.clone() + AB::Expr::from_usize(D_EF);
        for (i, value) in LABEL_PRODUCT_SUM_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                root_mu_label_tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                local.is_enabled * local.is_first * is_not_dummy.clone(),
            );
        }
        let root_mu_tidx = root_mu_label_tidx + AB::Expr::from_usize(LABEL_PRODUCT_SUM);

        let non_root_mu_label_tidx = tidx_after_sumcheck.clone() + out_eval_span;
        for (i, value) in LABEL_MERGE_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                non_root_mu_label_tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                is_non_root_layer.clone() * is_not_dummy.clone(),
            );
        }
        let non_root_mu_tidx = non_root_mu_label_tidx + AB::Expr::from_usize(LABEL_MERGE);

        let non_root_lambda_label_tidx = non_root_mu_tidx.clone() + AB::Expr::from_usize(D_EF);
        for (i, value) in LABEL_COMBINE_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                non_root_lambda_label_tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                is_non_root_layer.clone() * is_not_dummy.clone(),
            );
        }
        let non_root_lambda_tidx = non_root_lambda_label_tidx + AB::Expr::from_usize(LABEL_COMBINE);

        // 1a. Sample `lambda`: root lambda_1 after root out-evals, later
        // rows sample lambda_next after merge.
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            root_lambda_tidx,
            local.lambda,
            local.is_enabled * local.is_first * is_not_dummy.clone(),
        );
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            non_root_lambda_tidx,
            local.lambda,
            is_non_root_layer.clone() * is_not_dummy.clone(),
        );
        // 1b. Sample `mu`: root r_1 after product_sum; later rows after
        // child-claim observations and merge label.
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            root_mu_tidx,
            local.mu,
            local.is_enabled * local.is_first * is_not_dummy.clone(),
        );
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            non_root_mu_tidx,
            local.mu,
            is_non_root_layer * is_not_dummy,
        );
    }
}
