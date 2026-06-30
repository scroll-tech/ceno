use core::borrow::Borrow;

use openvm_circuit_primitives::{
    SubAir,
    is_zero::{IsZeroAuxCols, IsZeroIo, IsZeroSubAir},
    utils::assert_array_eq,
};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::tower::{
    TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage,
    bus::{
        TowerClaimInputBus, TowerClaimLayerInputMessage, TowerClaimOp, TowerLayerInputBus,
        TowerLayerInputMessage, TowerLayerOutputBus, TowerLayerOutputMessage, TowerLogupClaimBus,
        TowerLogupClaimMessage, TowerProdReadClaimBus, TowerProdSumClaimMessage,
        TowerProdWriteClaimBus, TowerSumcheckInputBus, TowerSumcheckInputMessage,
        TowerSumcheckOutputBus, TowerSumcheckOutputMessage,
    },
};

use recursion_circuit::{
    bus::TranscriptBus,
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{ext_field_add, ext_field_multiply},
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerLayerCols<T> {
    /// Whether the current row is enabled (i.e. not padding)
    pub is_enabled: T,
    pub proof_idx: T,
    pub chip_idx: T,
    pub is_first_proof_idx: T,
    pub is_first_chip_idx: T,

    /// Enabled no-op row for chips with less than two layers.
    pub is_noop: T,
    pub is_noop_aux: IsZeroAuxCols<T>,
    pub num_read_count: T,
    pub num_write_count: T,
    pub num_logup_count: T,
    pub num_layers: T,

    /// GKR layer index
    pub layer_idx: T,

    /// Transcript index at the start of this layer
    pub tidx: T,

    /// Sampled batching challenge
    pub lambda_next: [T; D_EF],
    /// Challenge inherited from previous layer
    pub lambda_cur: [T; D_EF],
    /// Reduction point
    pub mu: [T; D_EF],

    /// Current layer sumcheck input claim `C_i(r_i)`.
    pub sumcheck_claim_in: [T; D_EF],

    /// Read/write/LogUp `*_claim_next`: contributions to next-layer claim `C_{i+1}(rho, mu)`.
    /// Read/write/LogUp `*_claim_cur`: contributions to current-layer expected eval `T_i(rho)`.
    pub read_claim_cur: [T; D_EF],
    pub write_claim_cur: [T; D_EF],
    pub logup_claim_cur: [T; D_EF],
    pub read_claim_next: [T; D_EF],
    pub write_claim_next: [T; D_EF],
    pub logup_claim_next: [T; D_EF],

    /// End powers after the read group and after the combined read/write groups.
    pub read_lambda_next_end: [T; D_EF],
    pub read_lambda_cur_end: [T; D_EF],
    pub write_lambda_next_end: [T; D_EF],
    pub write_lambda_cur_end: [T; D_EF],

    /// Received from TowerLayerSumcheckAir
    pub eq_at_r_prime: [T; D_EF],
}

/// The TowerLayerAir handles layer-to-layer transitions in the GKR protocol
pub struct TowerLayerAir {
    // External buses
    pub transcript_bus: TranscriptBus,
    // Internal buses
    pub layer_input_bus: TowerLayerInputBus,
    pub layer_output_bus: TowerLayerOutputBus,
    pub sumcheck_input_bus: TowerSumcheckInputBus,
    pub sumcheck_output_bus: TowerSumcheckOutputBus,
    pub sumcheck_challenge_bus: TowerSumcheckChallengeBus,
    pub claim_input_bus: TowerClaimInputBus,
    pub prod_read_claim_bus: TowerProdReadClaimBus,
    pub prod_write_claim_bus: TowerProdWriteClaimBus,
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
        // tower that has 0 or 1 layer
        ///////////////////////////////////////////////////////////////////////
        let num_layers_expr: AB::Expr = local.num_layers.into();
        let noop_poly = num_layers_expr.clone() * (num_layers_expr.clone() - AB::Expr::ONE);
        IsZeroSubAir.eval(
            builder,
            (
                IsZeroIo::new(noop_poly, local.is_noop.into(), local.is_enabled.into()),
                local.is_noop_aux.inv,
            ),
        );

        ///////////////////////////////////////////////////////////////////////
        // Boolean Constraints
        ///////////////////////////////////////////////////////////////////////

        builder.assert_bool(local.is_first_proof_idx);
        builder.assert_bool(local.is_first_chip_idx);

        ///////////////////////////////////////////////////////////////////////
        // Proof Index and Loop Constraints
        ///////////////////////////////////////////////////////////////////////

        type LoopSubAir = NestedForLoopSubAir<2>;

        // This subair has the following constraints:
        // 1. Boolean enabled flag
        // 2. Disabled rows are followed by disabled rows
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.chip_idx],
                    is_first: [local.is_first_proof_idx, local.is_first_chip_idx],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.chip_idx],
                    is_first: [next.is_first_proof_idx, next.is_first_chip_idx],
                }
                .map_into(),
            ),
        );

        let is_transition =
            LoopSubAir::local_is_transition(next.is_enabled, next.is_first_chip_idx);
        let is_last =
            LoopSubAir::local_is_last(local.is_enabled, next.is_enabled, next.is_first_chip_idx);
        let is_not_noop = AB::Expr::ONE - local.is_noop;
        let active_layer = local.is_enabled * is_not_noop.clone();

        // Layer index is the innermost counter, so it is checked locally.
        builder
            .when(local.is_first_chip_idx * local.is_noop)
            .assert_zero(local.layer_idx);
        builder
            .when(local.is_first_chip_idx * is_not_noop.clone())
            .assert_one(local.layer_idx);
        builder
            .when(is_transition.clone())
            .assert_eq(next.layer_idx, local.layer_idx + AB::Expr::ONE);
        builder
            .when(is_transition.clone())
            .assert_eq(next.num_layers, local.num_layers);
        builder
            .when(is_transition.clone())
            .assert_eq(next.num_read_count, local.num_read_count);
        builder
            .when(is_transition.clone())
            .assert_eq(next.num_write_count, local.num_write_count);
        builder
            .when(is_transition.clone())
            .assert_eq(next.num_logup_count, local.num_logup_count);
        builder
            .when(is_last.clone() * is_not_noop.clone())
            .assert_eq(local.layer_idx + AB::Expr::ONE, local.num_layers);
        builder
            .when(local.is_noop)
            .assert_zero(is_transition.clone());

        // constrain lambda_cur
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.lambda_cur,
            local.lambda_next,
        );

        ///////////////////////////////////////////////////////////////////////
        // Inter-Layer Constraints
        ///////////////////////////////////////////////////////////////////////

        let read_plus_write =
            ext_field_add::<AB::Expr>(local.read_claim_next, local.write_claim_next);
        let folded_claim = ext_field_add::<AB::Expr>(read_plus_write, local.logup_claim_next);
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            next.sumcheck_claim_in,
            folded_claim.clone(),
        );

        ///////////////////////////////////////////////////////////////////////
        // Transcript index increment
        ///////////////////////////////////////////////////////////////////////
        use crate::tower::tower_transcript_len::{
            ALPHA_LEN, LABEL_COMBINE, LABEL_COMBINE_VALUES, LABEL_MERGE, LABEL_MERGE_VALUES,
            MERGE_LEN, ROUND_LEN, SUMCHECK_INIT_LEN,
        };
        let out_eval_span = (local.num_read_count * AB::Expr::from_usize(2)
            + local.num_write_count * AB::Expr::from_usize(2)
            + local.num_logup_count * AB::Expr::from_usize(4))
            * AB::Expr::from_usize(D_EF);
        let sumcheck_span = AB::Expr::from_usize(SUMCHECK_INIT_LEN)
            + local.layer_idx * AB::Expr::from_usize(ROUND_LEN);
        let tidx_after_sumcheck = local.tidx + sumcheck_span.clone();
        let layer_span =
            sumcheck_span + out_eval_span.clone() + AB::Expr::from_usize(MERGE_LEN + ALPHA_LEN);
        let tidx_end = local.tidx + layer_span;
        builder
            .when(is_transition.clone())
            .assert_eq(next.tidx, tidx_end.clone());

        ///////////////////////////////////////////////////////////////////////
        // Module Interactions
        ///////////////////////////////////////////////////////////////////////

        let has_tower = local.is_enabled * (is_not_noop.clone() + local.is_noop * local.num_layers);
        let tidx_for_claims = tidx_after_sumcheck.clone();
        let prod_eval_span = AB::Expr::from_usize(2 * D_EF);
        let read_tidx = tidx_for_claims.clone();
        let write_tidx = read_tidx.clone() + local.num_read_count * prod_eval_span.clone();
        let logup_tidx = write_tidx.clone() + local.num_write_count * prod_eval_span;
        let read_claim_mult = active_layer.clone() * local.num_read_count;
        let write_claim_mult = active_layer.clone() * local.num_write_count;
        let logup_claim_mult = active_layer.clone() * local.num_logup_count;
        let lambda_one = {
            let mut arr = core::array::from_fn(|_| AB::Expr::ZERO);
            arr[0] = AB::Expr::ONE;
            arr
        };

        // 1. Claim buses
        // 1a. Send read/write/logup input to the claim air
        self.claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerClaimLayerInputMessage {
                op: AB::Expr::from_usize(TowerClaimOp::Read.as_usize()),
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: read_tidx,
                lambda_next: local.lambda_next.map(Into::into),
                lambda_cur: local.lambda_cur.map(Into::into),
                mu: local.mu.map(Into::into),
                prod_offset: AB::Expr::ZERO,
                lambda_next_start: lambda_one.clone(),
                lambda_cur_start: lambda_one.clone(),
                num_count: local.num_read_count.into(),
            },
            read_claim_mult.clone(),
        );
        self.claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerClaimLayerInputMessage {
                op: AB::Expr::from_usize(TowerClaimOp::Write.as_usize()),
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: write_tidx,
                lambda_next: local.lambda_next.map(Into::into),
                lambda_cur: local.lambda_cur.map(Into::into),
                mu: local.mu.map(Into::into),
                prod_offset: local.num_read_count.into(),
                lambda_next_start: local.read_lambda_next_end.map(Into::into),
                lambda_cur_start: local.read_lambda_cur_end.map(Into::into),
                num_count: local.num_write_count.into(),
            },
            write_claim_mult.clone(),
        );
        self.claim_input_bus.send(
            builder,
            local.proof_idx,
            TowerClaimLayerInputMessage {
                op: AB::Expr::from_usize(TowerClaimOp::Logup.as_usize()),
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: logup_tidx,
                lambda_next: local.lambda_next.map(Into::into),
                lambda_cur: local.lambda_cur.map(Into::into),
                mu: local.mu.map(Into::into),
                prod_offset: AB::Expr::ZERO,
                lambda_next_start: local.write_lambda_next_end.map(Into::into),
                lambda_cur_start: local.write_lambda_cur_end.map(Into::into),
                num_count: local.num_logup_count.into(),
            },
            logup_claim_mult.clone(),
        );
        // 1b. Receive read/write/logup output from claim airs
        self.prod_read_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerProdSumClaimMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_next_claim: local.read_claim_next.map(Into::into),
                lambda_cur_claim: local.read_claim_cur.map(Into::into),
                lambda_next_end: local.read_lambda_next_end.map(Into::into),
                lambda_cur_end: local.read_lambda_cur_end.map(Into::into),
            },
            read_claim_mult,
        );
        self.prod_write_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerProdSumClaimMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_next_claim: local.write_claim_next.map(Into::into),
                lambda_cur_claim: local.write_claim_cur.map(Into::into),
                lambda_next_end: local.write_lambda_next_end.map(Into::into),
                lambda_cur_end: local.write_lambda_cur_end.map(Into::into),
            },
            write_claim_mult,
        );
        self.logup_claim_bus.receive(
            builder,
            local.proof_idx,
            TowerLogupClaimMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                lambda_next_claim: local.logup_claim_next.map(Into::into),
                lambda_cur_claim: local.logup_claim_cur.map(Into::into),
            },
            logup_claim_mult,
        );

        // 1. TowerLayerInputBus
        // 1a. Receive GKR layers input
        self.layer_input_bus.receive(
            builder,
            local.proof_idx,
            TowerLayerInputMessage {
                chip_idx: local.chip_idx.into(),
                tidx: local.tidx.into(),
                num_layers: local.num_layers.into(),
                num_read_specs: local.num_read_count.into(),
                num_write_specs: local.num_write_count.into(),
                num_logup_specs: local.num_logup_count.into(),
                sumcheck_claim_in: local.sumcheck_claim_in.map(Into::into),
                lambda_cur: local.lambda_cur.map(Into::into),
            },
            local.is_first_chip_idx * has_tower.clone(),
        );
        // 2. TowerLayerOutputBus
        // 2a. Send GKR input layer claims back
        let noop = local.is_noop.into();
        let output_tidx = noop.clone() * local.tidx + is_not_noop.clone() * tidx_end.clone();
        let output_claim = core::array::from_fn(|i| {
            noop.clone() * local.sumcheck_claim_in[i]
                + is_not_noop.clone() * folded_claim[i].clone()
        });
        let output_lambda = core::array::from_fn(|i| {
            noop.clone() * local.lambda_cur[i] + is_not_noop.clone() * local.lambda_next[i]
        });
        self.layer_output_bus.send(
            builder,
            local.proof_idx,
            TowerLayerOutputMessage {
                chip_idx: local.chip_idx.into(),
                tidx: output_tidx,
                layer_idx_end: local.layer_idx.into(),
                input_layer_claim: output_claim.map(Into::into),
                lambda_next: output_lambda.map(Into::into),
                mu: local.mu.map(Into::into),
            },
            is_last.clone() * has_tower.clone(),
        );
        // 3. TowerSumcheckInputBus
        // 3a. Send claim to sumcheck
        // only send sumcheck on non root layer
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckInputMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                is_last_layer: is_last.clone(),
                tidx: local.tidx + AB::Expr::from_usize(SUMCHECK_INIT_LEN),
                claim: local.sumcheck_claim_in.map(Into::into),
            },
            active_layer.clone(),
        );
        // 3. TowerSumcheckOutputBus
        // 3a. Receive sumcheck results
        let cur_fold = ext_field_add::<AB::Expr>(local.read_claim_cur, local.write_claim_cur);
        let sumcheck_claim_out = ext_field_multiply::<AB::Expr>(
            ext_field_add::<AB::Expr>(cur_fold, local.logup_claim_cur),
            local.eq_at_r_prime,
        );
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            TowerSumcheckOutputMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                tidx: tidx_after_sumcheck.clone(),
                claim_out: sumcheck_claim_out.map(Into::into),
                eq_at_r_prime: local.eq_at_r_prime.map(Into::into),
            },
            active_layer.clone(),
        );
        // 4. TowerSumcheckChallengeBus
        // 4a. Send challenge mu
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: local.layer_idx.into(),
                sumcheck_round: local.layer_idx.into(),
                challenge: local.mu.map(Into::into),
            },
            is_transition.clone() * active_layer.clone(),
        );

        ///////////////////////////////////////////////////////////////////////
        // External Interactions
        ///////////////////////////////////////////////////////////////////////

        // 1. TranscriptBus
        let non_root_init_tidx = local.tidx;
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            non_root_init_tidx,
            local.layer_idx,
            active_layer.clone(),
        );
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            local.tidx + AB::Expr::ONE,
            AB::Expr::ZERO,
            active_layer.clone(),
        );
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            local.tidx + AB::Expr::from_usize(2),
            AB::Expr::from_usize(3),
            active_layer.clone(),
        );
        self.transcript_bus.observe(
            builder,
            local.proof_idx,
            local.tidx + AB::Expr::from_usize(3),
            AB::Expr::ZERO,
            active_layer.clone(),
        );

        let non_root_mu_label_tidx = tidx_after_sumcheck.clone() + out_eval_span;
        for (i, value) in LABEL_MERGE_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                non_root_mu_label_tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                active_layer.clone(),
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
                active_layer.clone(),
            );
        }
        let non_root_lambda_tidx = non_root_lambda_label_tidx + AB::Expr::from_usize(LABEL_COMBINE);

        // 1a. Sample `lambda_next` after the merge challenge.
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            non_root_lambda_tidx,
            local.lambda_next,
            active_layer.clone(),
        );
        // 1b. Sample `mu` after child-claim observations and merge label.
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            non_root_mu_tidx,
            local.mu,
            active_layer,
        );
    }
}
