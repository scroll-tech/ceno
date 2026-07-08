use core::borrow::Borrow;

use crate::{
    bus::{
        ForkFinalSampleBus, ForkFinalSampleMessage, ForkedTranscriptBus,
        ForkedTranscriptBusMessage, MainBus, MainMessage, TowerModuleBus, TowerModuleMessage,
    },
    tower::bus::{
        TowerInputShapeBus, TowerInputShapeMessage, TowerLayerInputBus, TowerLayerInputMessage,
        TowerLayerOutputBus, TowerLayerOutputMessage, TowerSumcheckChallengeBus,
        TowerSumcheckChallengeMessage,
    },
};
use openvm_circuit_primitives::{
    SubAir,
    is_zero::{IsZeroAuxCols, IsZeroIo, IsZeroSubAir},
    utils::not,
};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use recursion_circuit::{
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::assert_zeros,
};
use stark_recursion_circuit_derive::AlignedBorrow;

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerInputCols<T> {
    /// Whether the current row is enabled (i.e. not padding)
    pub is_enabled: T,

    pub proof_idx: T,
    pub idx: T,
    pub is_first_idx: T,
    pub is_first: T,
    pub fork_id: T,

    pub n_logup: T,

    /// Flag indicating whether there are any interactions
    /// n_logup = 0 <=> total_interactions = 0
    pub is_n_logup_zero: T,
    pub is_n_logup_zero_aux: IsZeroAuxCols<T>,
    /// Zero iff this row has no forked tower transcript rows.
    pub is_tower_transcript_zero: T,
    pub is_tower_transcript_zero_aux: IsZeroAuxCols<T>,

    /// Transcript index
    pub tidx: T,
    pub fork_final_sample_tidx: T,

    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    /// Root denominator claim
    pub q0_claim: [T; D_EF],

    pub read_out_0: [T; D_EF],
    pub read_out_1: [T; D_EF],
    pub write_out_0: [T; D_EF],
    pub write_out_1: [T; D_EF],
    pub logup_out_0: [T; D_EF],
    pub logup_out_1: [T; D_EF],
    pub logup_out_2: [T; D_EF],
    pub logup_out_3: [T; D_EF],
    pub has_read_out: T,
    pub has_write_out: T,
    pub has_logup_out: T,
    pub has_read: T,
    pub has_write: T,
    pub has_logup: T,
    pub read_tower_vars: T,
    pub write_tower_vars: T,
    pub logup_tower_vars: T,
    pub max_layer_count: T,

    pub alpha_logup: [T; D_EF],
    pub beta: [T; D_EF],

    pub input_layer_claim: [T; D_EF],
    pub layer_output_lambda: [T; D_EF],
    pub layer_output_mu: [T; D_EF],
}

/// The TowerInputAir handles reading and passing the TowerInput
pub struct TowerInputAir {
    // Buses
    pub tower_module_bus: TowerModuleBus,
    pub main_bus: MainBus,
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub fork_final_sample_bus: ForkFinalSampleBus,
    pub input_shape_bus: TowerInputShapeBus,
    pub layer_input_bus: TowerLayerInputBus,
    pub layer_output_bus: TowerLayerOutputBus,
    pub sumcheck_challenge_bus: TowerSumcheckChallengeBus,
    pub send_main: bool,
}

impl<F: Field> BaseAir<F> for TowerInputAir {
    fn width(&self) -> usize {
        TowerInputCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerInputAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerInputAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for TowerInputAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &TowerInputCols<AB::Var> = (*local).borrow();
        let next: &TowerInputCols<AB::Var> = (*next).borrow();

        ///////////////////////////////////////////////////////////////////////
        // Proof Index Constraints
        ///////////////////////////////////////////////////////////////////////

        type LoopSubAir = NestedForLoopSubAir<2>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.idx],
                    is_first: [local.is_first_idx, local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.idx],
                    is_first: [next.is_first_idx, next.is_first],
                }
                .map_into(),
            ),
        );

        ///////////////////////////////////////////////////////////////////////
        // Base Constraints
        ///////////////////////////////////////////////////////////////////////

        // 1. Check if n_logup is zero (no logup constraints needed)
        IsZeroSubAir.eval(
            builder,
            (
                IsZeroIo::new(
                    local.n_logup.into(),
                    local.is_n_logup_zero.into(),
                    local.is_enabled.into(),
                ),
                local.is_n_logup_zero_aux.inv,
            ),
        );
        builder.assert_bool(local.has_read_out);
        builder.assert_bool(local.has_write_out);
        builder.assert_bool(local.has_logup_out);
        builder.assert_bool(local.has_read);
        builder.assert_bool(local.has_write);
        builder.assert_bool(local.has_logup);

        ///////////////////////////////////////////////////////////////////////
        // Output Constraints
        ///////////////////////////////////////////////////////////////////////

        let has_interactions = AB::Expr::ONE - local.is_n_logup_zero;
        let tower_transcript_count = local.has_read_out
            + local.has_write_out
            + local.has_logup_out
            + has_interactions.clone();
        IsZeroSubAir.eval(
            builder,
            (
                IsZeroIo::new(
                    tower_transcript_count,
                    local.is_tower_transcript_zero.into(),
                    local.is_enabled.into(),
                ),
                local.is_tower_transcript_zero_aux.inv,
            ),
        );
        let has_tower_transcript = AB::Expr::ONE - local.is_tower_transcript_zero;
        let has_tower_out = AB::Expr::ONE
            - (AB::Expr::ONE - local.has_read_out)
                * (AB::Expr::ONE - local.has_write_out)
                * (AB::Expr::ONE - local.has_logup_out);

        builder
            .when(local.is_enabled * has_tower_transcript.clone())
            .assert_eq(local.has_read_out, local.has_read);
        builder
            .when(local.is_enabled * has_tower_transcript.clone())
            .assert_eq(local.has_write_out, local.has_write);
        builder
            .when(local.is_enabled * has_tower_transcript.clone())
            .assert_eq(local.has_logup_out, local.has_logup);
        builder
            .when(local.is_enabled * has_tower_transcript.clone())
            .assert_eq(local.n_logup, local.max_layer_count);

        // Input layer claim defaults to zero when no interactions
        assert_zeros(
            &mut builder.when(not::<AB::Expr>(has_interactions.clone())),
            local.input_layer_claim,
        );
        assert_zeros(
            &mut builder.when(not::<AB::Expr>(has_interactions.clone())),
            local.layer_output_lambda,
        );
        assert_zeros(
            &mut builder.when(not::<AB::Expr>(has_interactions.clone())),
            local.layer_output_mu,
        );

        ///////////////////////////////////////////////////////////////////////
        // Module Interactions
        ///////////////////////////////////////////////////////////////////////

        let num_layers = local.n_logup;

        // Add PoW (if any) and alpha label+sample, beta label+sample
        use crate::tower::tower_transcript_len::{
            ALPHA_BETA_LEN, ALPHA_LEN, LABEL_COMBINE, LABEL_COMBINE_FIELDS, LABEL_MERGE,
            LABEL_PRODUCT_SUM, LABEL_PRODUCT_SUM_FIELDS, ROUND_LEN, SUMCHECK_INIT_LEN,
        };
        let tidx_after_alpha_beta = local.tidx + AB::Expr::from_usize(ALPHA_BETA_LEN);
        // Add GKR layers + Sumcheck.
        // Layer 0 includes sumcheck init, one round, and post-sumcheck.
        // Layer j>0 additionally samples lambda and has j+1 sumcheck rounds.
        // layers_cumulative(n) =
        //   n*(SUMCHECK_INIT_LEN + POST_SUMCHECK_LEN)
        //   + n*(n+1)/2*ROUND_LEN
        //   + n*ALPHA_LEN, for n > 0, including native's final post-merge alpha.
        let read_active_layers = local.read_tower_vars - local.has_read_out;
        let write_active_layers = local.write_tower_vars - local.has_write_out;
        let logup_active_layers = local.logup_tower_vars - local.has_logup_out;
        let claim_span = read_active_layers * AB::Expr::from_usize(2 * D_EF)
            + write_active_layers * AB::Expr::from_usize(2 * D_EF)
            + logup_active_layers * AB::Expr::from_usize(4 * D_EF);
        let fixed_span =
            num_layers.clone() * AB::Expr::from_usize(SUMCHECK_INIT_LEN + LABEL_MERGE + D_EF);
        let round_span = num_layers.clone()
            * (num_layers.clone() + AB::Expr::ONE)
            * AB::Expr::from_usize(ROUND_LEN / 2);
        let alpha_span = num_layers.clone() * AB::Expr::from_usize(ALPHA_LEN);
        let tidx_after_gkr_layers = tidx_after_alpha_beta.clone()
            + has_interactions.clone() * (fixed_span + round_span + alpha_span + claim_span);
        // 1. TowerLayerInputBus
        // 1a. Send input to TowerLayerAir
        self.layer_input_bus.send(
            builder,
            local.proof_idx,
            TowerLayerInputMessage {
                idx: local.idx.into(),
                tidx: tidx_after_alpha_beta.clone() * has_interactions.clone(),
                r0_claim: local.r0_claim.map(Into::into),
                w0_claim: local.w0_claim.map(Into::into),
                q0_claim: local.q0_claim.map(Into::into),
            },
            local.is_enabled * has_interactions.clone(),
        );
        // 2. TowerLayerOutputBus
        // 2a. Receive input layer claim from TowerLayerAir
        self.layer_output_bus.receive(
            builder,
            local.proof_idx,
            TowerLayerOutputMessage {
                idx: local.idx.into(),
                tidx: tidx_after_gkr_layers.clone(),
                layer_idx_end: num_layers - AB::Expr::ONE,
                input_layer_claim: local.input_layer_claim.map(Into::into),
                lambda: local.layer_output_lambda.map(Into::into),
                mu: local.layer_output_mu.map(Into::into),
            },
            local.is_enabled * has_interactions.clone(),
        );
        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                idx: local.idx.into(),
                layer_idx: AB::Expr::ZERO,
                sumcheck_round: AB::Expr::ZERO,
                challenge: local.beta.map(Into::into),
            },
            local.is_enabled * has_interactions.clone(),
        );
        self.input_shape_bus.receive(
            builder,
            local.proof_idx,
            TowerInputShapeMessage {
                idx: local.idx.into(),
                has_read: local.has_read.into(),
                has_write: local.has_write.into(),
                has_logup: local.has_logup.into(),
                read_tower_vars: local.read_tower_vars.into(),
                write_tower_vars: local.write_tower_vars.into(),
                logup_tower_vars: local.logup_tower_vars.into(),
                max_layer_count: local.max_layer_count.into(),
            },
            local.is_enabled * has_tower_transcript.clone(),
        );
        self.fork_final_sample_bus.send(
            builder,
            local.proof_idx,
            ForkFinalSampleMessage {
                fork_id: local.fork_id.into(),
                tidx: local.fork_final_sample_tidx.into(),
            },
            local.is_enabled * has_tower_transcript.clone(),
        );
        ///////////////////////////////////////////////////////////////////////
        // External Interactions
        ///////////////////////////////////////////////////////////////////////

        // 1. TowerModuleBus
        // 1a. Receive initial GKR module message on first layer
        self.tower_module_bus.receive(
            builder,
            local.proof_idx,
            TowerModuleMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                n_logup: local.n_logup.into(),
            },
            local.is_enabled,
        );

        // 2. TranscriptBus
        // 2a. Observe grouped tower out-evals before alpha/beta sampling.
        let out_eval_start_tidx = local.tidx
            - local.has_read_out * AB::Expr::from_usize(2 * D_EF)
            - local.has_write_out * AB::Expr::from_usize(2 * D_EF)
            - local.has_logup_out * AB::Expr::from_usize(4 * D_EF);
        let mut out_eval_tidx = out_eval_start_tidx;
        for eval in [local.read_out_0, local.read_out_1] {
            for i in 0..D_EF {
                self.forked_transcript_bus.receive(
                    builder,
                    local.proof_idx,
                    ForkedTranscriptBusMessage {
                        fork_id: local.fork_id.into(),
                        tidx: out_eval_tidx.clone() + AB::Expr::from_usize(i),
                        value: eval[i].into(),
                        is_sample: AB::Expr::ZERO,
                    },
                    local.is_enabled * local.has_read_out,
                );
            }
            out_eval_tidx += local.has_read_out * AB::Expr::from_usize(D_EF);
        }
        for eval in [local.write_out_0, local.write_out_1] {
            for i in 0..D_EF {
                self.forked_transcript_bus.receive(
                    builder,
                    local.proof_idx,
                    ForkedTranscriptBusMessage {
                        fork_id: local.fork_id.into(),
                        tidx: out_eval_tidx.clone() + AB::Expr::from_usize(i),
                        value: eval[i].into(),
                        is_sample: AB::Expr::ZERO,
                    },
                    local.is_enabled * local.has_write_out,
                );
            }
            out_eval_tidx += local.has_write_out * AB::Expr::from_usize(D_EF);
        }
        for eval in [
            local.logup_out_0,
            local.logup_out_1,
            local.logup_out_2,
            local.logup_out_3,
        ] {
            for i in 0..D_EF {
                self.forked_transcript_bus.receive(
                    builder,
                    local.proof_idx,
                    ForkedTranscriptBusMessage {
                        fork_id: local.fork_id.into(),
                        tidx: out_eval_tidx.clone() + AB::Expr::from_usize(i),
                        value: eval[i].into(),
                        is_sample: AB::Expr::ZERO,
                    },
                    local.is_enabled * local.has_logup_out,
                );
            }
            out_eval_tidx += local.has_logup_out * AB::Expr::from_usize(D_EF);
        }

        // 2b. Observe labels and sample alpha_logup/beta challenges.
        for (offset, value) in LABEL_COMBINE_FIELDS.into_iter().enumerate() {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(offset),
                    value: AB::Expr::from_u32(value),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_enabled * has_tower_out.clone(),
            );
        }
        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(LABEL_COMBINE + i),
                    value: local.alpha_logup[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled * has_tower_out.clone(),
            );
        }
        for (offset, value) in LABEL_PRODUCT_SUM_FIELDS.into_iter().enumerate() {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(ALPHA_LEN + offset),
                    value: AB::Expr::from_u32(value),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_enabled * has_tower_out.clone(),
            );
        }
        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(ALPHA_LEN + LABEL_PRODUCT_SUM + i),
                    value: local.beta[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled * has_tower_out.clone(),
            );
        }
        self.main_bus.send(
            builder,
            local.proof_idx,
            MainMessage {
                idx: local.idx.into(),
                tidx: tidx_after_gkr_layers.clone(),
                claim: local.input_layer_claim.map(Into::into),
            },
            local.is_enabled * has_interactions * AB::Expr::from_bool(self.send_main),
        );
    }
}
