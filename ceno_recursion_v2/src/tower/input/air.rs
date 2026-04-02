use core::borrow::Borrow;

use crate::{
    bus::{MainBus, MainMessage, TowerModuleBus, TowerModuleMessage, TranscriptBus},
    tower::bus::{
        TowerLayerInputBus, TowerLayerInputMessage, TowerLayerOutputBus, TowerLayerOutputMessage,
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
    subairs::proof_idx::{ProofIdxIoCols, ProofIdxSubAir},
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

    pub n_logup: T,

    /// Flag indicating whether there are any interactions
    /// n_logup = 0 <=> total_interactions = 0
    pub is_n_logup_zero: T,
    pub is_n_logup_zero_aux: IsZeroAuxCols<T>,

    /// Transcript index
    pub tidx: T,

    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    /// Root denominator claim
    pub q0_claim: [T; D_EF],

    pub alpha_logup: [T; D_EF],

    pub input_layer_claim: [T; D_EF],
    pub layer_output_lambda: [T; D_EF],
    pub layer_output_mu: [T; D_EF],
}

/// The TowerInputAir handles reading and passing the TowerInput
pub struct TowerInputAir {
    // Buses
    pub tower_module_bus: TowerModuleBus,
    pub main_bus: MainBus,
    pub transcript_bus: TranscriptBus,
    pub layer_input_bus: TowerLayerInputBus,
    pub layer_output_bus: TowerLayerOutputBus,
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

        // This subair has the following constraints:
        // 1. Boolean enabled flag
        // 2. Disabled rows are followed by disabled rows
        // 3. Proof index increments by exactly one between enabled rows
        ProofIdxSubAir.eval(
            builder,
            (
                ProofIdxIoCols {
                    is_enabled: local.is_enabled,
                    proof_idx: local.proof_idx,
                }
                .map_into(),
                ProofIdxIoCols {
                    is_enabled: next.is_enabled,
                    proof_idx: next.proof_idx,
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

        ///////////////////////////////////////////////////////////////////////
        // Output Constraints
        ///////////////////////////////////////////////////////////////////////

        let has_interactions = AB::Expr::ONE - local.is_n_logup_zero;
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
            ALPHA_BETA_LEN, ALPHA_LEN, POST_SUMCHECK_LEN, ROUND_LEN, SUMCHECK_INIT_LEN,
        };
        let tidx_after_alpha_beta = local.tidx + AB::Expr::from_usize(ALPHA_BETA_LEN);
        // Add GKR layers + Sumcheck.
        // Total GKR span: n*(10n+25) - 13 for n>0.
        // layers_cumulative(n) = 10n² + 25n - 13.
        let gkr_inner = num_layers.clone() * AB::Expr::from_usize(ROUND_LEN / 2)
            + AB::Expr::from_usize(
                ALPHA_LEN + SUMCHECK_INIT_LEN + POST_SUMCHECK_LEN - ROUND_LEN / 2,
            );
        let tidx_after_gkr_layers = tidx_after_alpha_beta.clone()
            + has_interactions.clone()
                * (num_layers.clone() * gkr_inner
                    - AB::Expr::from_usize(ALPHA_LEN + SUMCHECK_INIT_LEN));
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
        // 2a. Sample alpha_logup challenge
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            local.tidx,
            local.alpha_logup.map(Into::into),
            local.is_enabled,
        );
        self.main_bus.send(
            builder,
            local.proof_idx,
            MainMessage {
                idx: local.idx.into(),
                tidx: tidx_after_gkr_layers.clone(),
                claim: local.input_layer_claim.map(Into::into),
            },
            local.is_enabled * has_interactions,
        );
    }
}
