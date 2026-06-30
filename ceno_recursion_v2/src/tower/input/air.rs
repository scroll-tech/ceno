use core::borrow::Borrow;

use crate::{
    bus::{
        MainBus, MainMessage, TowerModuleBus, TowerModuleMessage, TowerRootClaimBus,
        TowerRootClaimMessage, TranscriptBus,
    },
    tower::bus::{
        TowerLayerInputBus, TowerLayerInputMessage, TowerLayerOutputBus, TowerLayerOutputMessage,
        TowerLogupRootBus, TowerLogupRootInputBus, TowerLogupRootInputMessage,
        TowerLogupRootMessage, TowerProdInitMessage, TowerProdRootInputMessage,
        TowerProdRootMessage, TowerReadInitBus, TowerReadRootBus, TowerReadRootInputBus,
        TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage, TowerWriteInitBus,
        TowerWriteRootBus, TowerWriteRootInputBus,
    },
};
use openvm_circuit_primitives::{
    SubAir,
    is_zero::{IsZeroAuxCols, IsZeroIo, IsZeroSubAir},
    utils::{assert_array_eq, not},
};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use recursion_circuit::utils::assert_zeros;
use stark_recursion_circuit_derive::AlignedBorrow;

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerInputCols<T> {
    /// Whether the current row is enabled (i.e. not padding)
    pub is_enabled: T,

    pub proof_idx: T,
    pub idx: T,
    pub chip_idx: T,

    pub num_layers: T,
    pub num_read_specs: T,
    pub num_write_specs: T,
    pub num_logup_specs: T,

    /// Flag indicating whether there are any interactions
    /// num_layers = 0 <=> total_interactions = 0
    pub is_num_layers_zero: T,
    pub is_num_layers_zero_aux: IsZeroAuxCols<T>,
    pub is_num_layers_one: T,
    pub is_num_layers_one_aux: IsZeroAuxCols<T>,

    /// Transcript index
    pub tidx: T,
    pub final_tidx: T,

    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    /// Root numerator claim
    pub p0_claim: [T; D_EF],
    /// Root denominator claim
    pub q0_claim: [T; D_EF],

    pub alpha_logup: [T; D_EF],
    pub r_1: [T; D_EF],

    pub read_initial_claim: [T; D_EF],
    pub write_initial_claim: [T; D_EF],
    pub logup_initial_claim: [T; D_EF],
    pub initial_tower_claim: [T; D_EF],
    pub write_lambda_1_start: [T; D_EF],
    pub logup_lambda_1_start: [T; D_EF],

    pub input_layer_claim: [T; D_EF],
    pub layer_output_lambda: [T; D_EF],
    pub layer_output_mu: [T; D_EF],
}

/// The TowerInputAir handles reading and passing the TowerInput
pub struct TowerInputAir {
    // Buses
    pub tower_module_bus: TowerModuleBus,
    pub tower_root_claim_bus: TowerRootClaimBus,
    pub main_bus: MainBus,
    pub transcript_bus: TranscriptBus,
    pub layer_input_bus: TowerLayerInputBus,
    pub layer_output_bus: TowerLayerOutputBus,
    pub read_root_input_bus: TowerReadRootInputBus,
    pub read_root_bus: TowerReadRootBus,
    pub read_init_bus: TowerReadInitBus,
    pub write_root_input_bus: TowerWriteRootInputBus,
    pub write_root_bus: TowerWriteRootBus,
    pub write_init_bus: TowerWriteInitBus,
    pub logup_root_input_bus: TowerLogupRootInputBus,
    pub logup_root_bus: TowerLogupRootBus,
    pub sumcheck_challenge_bus: TowerSumcheckChallengeBus,
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

        builder.assert_bool(local.is_enabled);
        builder
            .when_transition()
            .when(AB::Expr::ONE - local.is_enabled)
            .assert_zero(next.is_enabled);
        builder
            .when_first_row()
            .when(local.is_enabled)
            .assert_zero(local.proof_idx);
        builder
            .when_first_row()
            .when(local.is_enabled)
            .assert_zero(local.idx);

        let proof_diff: AB::Expr = next.proof_idx - local.proof_idx;
        builder
            .when_transition()
            .when(next.is_enabled)
            .assert_bool(proof_diff.clone());
        builder
            .when_transition()
            .when(next.is_enabled * proof_diff.clone())
            .assert_zero(next.idx);
        builder
            .when_transition()
            .when(next.is_enabled * (AB::Expr::ONE - proof_diff))
            .assert_eq(next.idx, local.idx + AB::Expr::ONE);
        builder
            .when(local.is_enabled)
            .assert_eq(local.idx, local.chip_idx);

        ///////////////////////////////////////////////////////////////////////
        // Base Constraints
        ///////////////////////////////////////////////////////////////////////

        // 1. Check if num_layers is zero (no tower reduction needed)
        IsZeroSubAir.eval(
            builder,
            (
                IsZeroIo::new(
                    local.num_layers.into(),
                    local.is_num_layers_zero.into(),
                    local.is_enabled.into(),
                ),
                local.is_num_layers_zero_aux.inv,
            ),
        );
        IsZeroSubAir.eval(
            builder,
            (
                IsZeroIo::new(
                    local.num_layers - AB::Expr::ONE,
                    local.is_num_layers_one.into(),
                    local.is_enabled.into(),
                ),
                local.is_num_layers_one_aux.inv,
            ),
        );
        ///////////////////////////////////////////////////////////////////////
        // Output Constraints
        ///////////////////////////////////////////////////////////////////////

        let has_interactions = AB::Expr::ONE - local.is_num_layers_zero;
        let has_non_root_layers =
            has_interactions.clone() * (AB::Expr::ONE - local.is_num_layers_one);
        let initial_sum = {
            let read_plus_write = recursion_circuit::utils::ext_field_add::<AB::Expr>(
                local.read_initial_claim,
                local.write_initial_claim,
            );
            recursion_circuit::utils::ext_field_add::<AB::Expr>(
                read_plus_write,
                local.logup_initial_claim,
            )
        };
        assert_array_eq(builder, local.initial_tower_claim, initial_sum);

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

        let num_layers = local.num_layers;
        let prod_eval_span = AB::Expr::from_usize(2 * D_EF);
        let read_claim_tidx = local.tidx;
        let write_claim_tidx = read_claim_tidx + local.num_read_specs * prod_eval_span.clone();
        let logup_claim_tidx = write_claim_tidx.clone() + local.num_write_specs * prod_eval_span;
        let out_eval_span = (local.num_read_specs * AB::Expr::from_usize(2)
            + local.num_write_specs * AB::Expr::from_usize(2)
            + local.num_logup_specs * AB::Expr::from_usize(4))
            * AB::Expr::from_usize(D_EF);
        use crate::tower::tower_transcript_len::{
            ALPHA_BETA_LEN, LABEL_COMBINE, LABEL_COMBINE_VALUES, LABEL_PRODUCT_SUM,
            LABEL_PRODUCT_SUM_VALUES,
        };
        let layer_start_tidx =
            local.tidx + out_eval_span.clone() + AB::Expr::from_usize(ALPHA_BETA_LEN);
        let one = {
            let mut arr = core::array::from_fn(|_| AB::Expr::ZERO);
            arr[0] = AB::Expr::ONE;
            arr
        };

        self.read_root_input_bus.send(
            builder,
            local.proof_idx,
            TowerProdRootInputMessage {
                chip_idx: local.chip_idx.into(),
                tidx: read_claim_tidx.into(),
                lambda_1: local.alpha_logup.map(Into::into),
                r_1: local.r_1.map(Into::into),
                lambda_1_start: one.clone(),
                num_prod_count: local.num_read_specs.into(),
            },
            local.is_enabled * local.num_read_specs,
        );
        self.write_root_input_bus.send(
            builder,
            local.proof_idx,
            TowerProdRootInputMessage {
                chip_idx: local.chip_idx.into(),
                tidx: write_claim_tidx,
                lambda_1: local.alpha_logup.map(Into::into),
                r_1: local.r_1.map(Into::into),
                lambda_1_start: local.write_lambda_1_start.map(Into::into),
                num_prod_count: local.num_write_specs.into(),
            },
            local.is_enabled * local.num_write_specs,
        );
        self.logup_root_input_bus.send(
            builder,
            local.proof_idx,
            TowerLogupRootInputMessage {
                chip_idx: local.chip_idx.into(),
                tidx: logup_claim_tidx,
                lambda_1: local.alpha_logup.map(Into::into),
                r_1: local.r_1.map(Into::into),
                lambda_1_start: local.logup_lambda_1_start.map(Into::into),
                num_logup_count: local.num_logup_specs.into(),
            },
            local.is_enabled * local.num_logup_specs,
        );
        // Receive chip-level root claims from child AIRs for ProofShapeAir's global root checks.
        self.read_root_bus.receive(
            builder,
            local.proof_idx,
            TowerProdRootMessage {
                chip_idx: local.chip_idx.into(),
                output_claim: local.r0_claim.map(Into::into),
            },
            local.is_enabled * local.num_read_specs,
        );
        self.write_root_bus.receive(
            builder,
            local.proof_idx,
            TowerProdRootMessage {
                chip_idx: local.chip_idx.into(),
                output_claim: local.w0_claim.map(Into::into),
            },
            local.is_enabled * local.num_write_specs,
        );
        self.logup_root_bus.receive(
            builder,
            local.proof_idx,
            TowerLogupRootMessage {
                chip_idx: local.chip_idx.into(),
                p0_claim: local.p0_claim.map(Into::into),
                q0_claim: local.q0_claim.map(Into::into),
                initial_claim: local.logup_initial_claim.map(Into::into),
            },
            local.is_enabled * local.num_logup_specs,
        );
        // Receive the read and write contributions that assemble the initial tower claim.
        self.read_init_bus.receive(
            builder,
            local.proof_idx,
            TowerProdInitMessage {
                chip_idx: local.chip_idx.into(),
                initial_claim: local.read_initial_claim.map(Into::into),
            },
            local.is_enabled * local.num_read_specs,
        );
        self.write_init_bus.receive(
            builder,
            local.proof_idx,
            TowerProdInitMessage {
                chip_idx: local.chip_idx.into(),
                initial_claim: local.write_initial_claim.map(Into::into),
            },
            local.is_enabled * local.num_write_specs,
        );

        // Add PoW (if any) and alpha label+sample, beta label+sample
        // 1. TowerLayerInputBus
        // 1a. Send input to TowerLayerAir
        self.layer_input_bus.send(
            builder,
            local.proof_idx,
            TowerLayerInputMessage {
                chip_idx: local.chip_idx.into(),
                tidx: layer_start_tidx.clone(),
                num_layers: local.num_layers.into(),
                num_read_specs: local.num_read_specs.into(),
                num_write_specs: local.num_write_specs.into(),
                num_logup_specs: local.num_logup_specs.into(),
                sumcheck_claim_in: local.initial_tower_claim.map(Into::into),
                lambda_cur: local.alpha_logup.map(Into::into),
            },
            local.is_enabled * has_interactions.clone(),
        );
        // 2. TowerLayerOutputBus
        // 2a. Receive input layer claim from TowerLayerAir
        self.layer_output_bus.receive(
            builder,
            local.proof_idx,
            TowerLayerOutputMessage {
                chip_idx: local.chip_idx.into(),
                tidx: local.final_tidx.into(),
                layer_idx_end: num_layers - has_interactions.clone(),
                input_layer_claim: local.input_layer_claim.map(Into::into),
                lambda_next: local.layer_output_lambda.map(Into::into),
                mu: local.layer_output_mu.map(Into::into),
            },
            local.is_enabled * has_interactions.clone(),
        );

        self.sumcheck_challenge_bus.send(
            builder,
            local.proof_idx,
            TowerSumcheckChallengeMessage {
                chip_idx: local.chip_idx.into(),
                layer_idx: AB::Expr::ZERO,
                sumcheck_round: AB::Expr::ZERO,
                challenge: local.r_1.map(Into::into),
            },
            local.is_enabled * has_non_root_layers,
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
                chip_idx: local.chip_idx.into(),
                num_layers: local.num_layers.into(),
                num_read_specs: local.num_read_specs.into(),
                num_write_specs: local.num_write_specs.into(),
                num_logup_specs: local.num_logup_specs.into(),
            },
            local.is_enabled,
        );

        self.tower_root_claim_bus.send(
            builder,
            local.proof_idx,
            TowerRootClaimMessage {
                chip_idx: local.chip_idx.into(),
                r0_claim: local.r0_claim.map(Into::into),
                w0_claim: local.w0_claim.map(Into::into),
                p0_claim: local.p0_claim.map(Into::into),
                q0_claim: local.q0_claim.map(Into::into),
            },
            local.is_enabled,
        );

        self.main_bus.send(
            builder,
            local.proof_idx,
            MainMessage {
                chip_idx: local.chip_idx.into(),
                tidx: local.final_tidx.into(),
                claim: local.input_layer_claim.map(Into::into),
            },
            local.is_enabled * has_interactions.clone(),
        );

        let root_lambda_label_tidx = local.tidx + out_eval_span;
        for (i, value) in LABEL_COMBINE_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                root_lambda_label_tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                local.is_enabled * has_interactions.clone(),
            );
        }
        let root_lambda_tidx = root_lambda_label_tidx + AB::Expr::from_usize(LABEL_COMBINE);
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            root_lambda_tidx.clone(),
            local.alpha_logup,
            local.is_enabled * has_interactions.clone(),
        );

        let root_mu_label_tidx = root_lambda_tidx + AB::Expr::from_usize(D_EF);
        for (i, value) in LABEL_PRODUCT_SUM_VALUES.iter().enumerate() {
            self.transcript_bus.observe(
                builder,
                local.proof_idx,
                root_mu_label_tidx.clone() + AB::Expr::from_usize(i),
                AB::Expr::from_usize(*value),
                local.is_enabled * has_interactions.clone(),
            );
        }
        let root_mu_tidx = root_mu_label_tidx + AB::Expr::from_usize(LABEL_PRODUCT_SUM);
        self.transcript_bus.sample_ext(
            builder,
            local.proof_idx,
            root_mu_tidx,
            local.r_1,
            local.is_enabled * has_interactions,
        );
    }
}
