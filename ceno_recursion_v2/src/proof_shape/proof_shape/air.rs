use std::{borrow::Borrow, sync::Arc};

use itertools::fold;
use openvm_circuit_primitives::{
    SubAir,
    encoder::Encoder,
    utils::{and, not, or},
};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        AirShapeBus, AirShapeBusMessage, ExpressionClaimNMaxBus, ExpressionClaimNMaxMessage,
        ForkedTranscriptBus, ForkedTranscriptBusMessage, FractionFolderInputBus,
        FractionFolderInputMessage, HyperdimBus, HyperdimBusMessage, LiftedHeightsBus,
        LiftedHeightsBusMessage, LookupChallengeBus, LookupChallengeKind, LookupChallengeMessage,
        NLiftBus, NLiftMessage, TowerModuleBus, TowerModuleMessage, TranscriptBus,
        TranscriptBusMessage,
    },
    circuit::inner::vm_pvs::VmPvs,
    primitives::bus::{RangeCheckerBus, RangeCheckerBusMessage},
    proof_shape::{
        AirMetadata,
        bus::{
            AirShapeProperty, ProofShapePermutationBus, ProofShapePermutationMessage,
            StartingTidxBus, StartingTidxMessage,
        },
    },
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    tower::tower_transcript_len,
    utils::TranscriptLabel,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct ProofShapeCols<F, const NUM_LIMBS: usize> {
    pub proof_idx: F,
    pub is_valid: F,
    pub is_first: F,
    pub is_last: F,

    pub sorted_idx: F,
    /// Represents `log2(next_pow_2(height))` when `is_present`.
    ///
    /// Has a special use on summary row (when `is_last`).
    pub log_height: F,
    /// Whether this AIR needs rotation openings.
    pub need_rot: F,

    // First possible transcript index of the current AIR.
    pub starting_tidx: F,

    // Columns that may be read from the transcript.
    pub is_present: F,

    /// Lifted trace height (`2^log_height`) used in downstream lookups when `is_present`.
    ///
    /// Has a special use on summary row (when `is_last`).
    pub height_1: F,
    pub height_2: F,

    // Number of present AIRs so far
    pub num_present: F,

    /// Limb decomposition of per-instance heights used for range/decomposition checks.
    pub height_1_limbs: [F; NUM_LIMBS],
    pub height_2_limbs: [F; NUM_LIMBS],

    /// The maximum hypercube dimension across all present AIR traces, or zero.
    /// Computed as max(0, n0, n1, ...) where ni = log_height_i for each present trace.
    pub n_max: F,
    pub is_n_max_greater: F,

    pub num_air_id_lookups: F,
    pub num_columns: F,

    /// The Poseidon2 sponge state at the fork point (trunk state just before
    /// forking). Constrained to be identical across all rows within a proof.
    pub lookup_challenge_alpha: [F; D_EF],
    pub lookup_challenge_beta: [F; D_EF],
    pub after_forked_challenge_1: [F; D_EF],
    pub after_forked_challenge_2: [F; D_EF],
}

// Variable-length columns are stored at the end
pub struct ProofShapeVarCols<'a, F> {
    pub idx_flags: &'a [F], // [F; IDX_FLAGS]
}

/// AIR for verifying the proof shape (trace heights, widths, commitments) of a child proof
/// within the recursion circuit.
///
/// The AIR enforces per-AIR shape consistency and forwards metadata to downstream buses.
pub struct ProofShapeAir<const NUM_LIMBS: usize, const LIMB_BITS: usize> {
    // Parameters derived from vk
    pub per_air: Vec<AirMetadata>,

    // Primitives
    pub idx_encoder: Arc<Encoder>,
    pub range_bus: RangeCheckerBus,

    // Internal buses
    pub permutation_bus: ProofShapePermutationBus,
    pub starting_tidx_bus: StartingTidxBus,
    pub lookup_challenge_bus: LookupChallengeBus,

    // Inter-module buses
    pub tower_module_bus: TowerModuleBus,
    pub air_shape_bus: AirShapeBus,
    pub expression_claim_n_max_bus: ExpressionClaimNMaxBus,
    pub fraction_folder_input_bus: FractionFolderInputBus,
    pub hyperdim_bus: HyperdimBus,
    pub lifted_heights_bus: LiftedHeightsBus,
    pub transcript_bus: TranscriptBus,
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub n_lift_bus: NLiftBus,
}

impl<F, const NUM_LIMBS: usize, const LIMB_BITS: usize> BaseAir<F>
    for ProofShapeAir<NUM_LIMBS, LIMB_BITS>
{
    fn width(&self) -> usize {
        ProofShapeCols::<F, NUM_LIMBS>::width() + self.idx_encoder.width()
    }
}
impl<F, const NUM_LIMBS: usize, const LIMB_BITS: usize> BaseAirWithPublicValues<F>
    for ProofShapeAir<NUM_LIMBS, LIMB_BITS>
{
}
impl<F, const NUM_LIMBS: usize, const LIMB_BITS: usize> PartitionedBaseAir<F>
    for ProofShapeAir<NUM_LIMBS, LIMB_BITS>
{
}

impl<const NUM_LIMBS: usize, const LIMB_BITS: usize, AB: AirBuilder + InteractionBuilder> Air<AB>
    for ProofShapeAir<NUM_LIMBS, LIMB_BITS>
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let (local, next) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let const_width = ProofShapeCols::<AB::Var, NUM_LIMBS>::width();

        let localv = borrow_var_cols::<AB::Var>(&local[const_width..], self.idx_encoder.width());
        let local: &ProofShapeCols<AB::Var, NUM_LIMBS> = (*local)[..const_width].borrow();
        let next: &ProofShapeCols<AB::Var, NUM_LIMBS> = (*next)[..const_width].borrow();
        let n = local.log_height.into();

        self.idx_encoder.eval(builder, localv.idx_flags);

        NestedForLoopSubAir::<1> {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_valid + local.is_last,
                    counter: [local.proof_idx.into()],
                    is_first: [local.is_first.into()],
                },
                NestedForLoopIoCols {
                    is_enabled: next.is_valid + next.is_last,
                    counter: [next.proof_idx.into()],
                    is_first: [next.is_first.into()],
                },
            ),
        );
        builder
            .when(and(local.is_valid, not(local.is_last)))
            .assert_eq(local.proof_idx, next.proof_idx);

        builder.assert_bool(local.is_present);
        builder.when(local.is_present).assert_one(local.is_valid);

        builder
            .when(local.is_first)
            .assert_eq(local.is_present, local.num_present);
        builder.when(local.is_valid).assert_eq(
            local.num_present + next.is_present * next.is_valid,
            next.num_present,
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // VK FIELD SELECTION
        ///////////////////////////////////////////////////////////////////////////////////////////
        // Select values for TranscriptBus
        let mut is_required = AB::Expr::ZERO;
        let mut air_idx = AB::Expr::ZERO;

        // Select values for LiftedHeightsBus
        let mut num_witin = AB::Expr::ZERO;
        let mut num_structural_witin = AB::Expr::ZERO;
        let mut num_fixed = AB::Expr::ZERO;

        // Select values for NumPublicValuesBus
        let mut num_pvs = AB::Expr::ZERO;
        let mut num_read_count = AB::Expr::ZERO;
        let mut num_write_count = AB::Expr::ZERO;
        let mut num_logup_count = AB::Expr::ZERO;
        // Per-selected-air tower transcript span (used for fork challenge tidx bump).
        let mut tower_tidx_bump = AB::Expr::ZERO;

        for (i, air_data) in self.per_air.iter().enumerate() {
            // We keep a running tally of how many transcript reads there should be up to any
            // given point, and use that to constrain initial_tidx
            let is_current_air = self.idx_encoder.get_flag_expr::<AB>(i, localv.idx_flags);
            let mut when_current = builder.when(is_current_air.clone());
            air_idx += is_current_air.clone() * AB::F::from_usize(i);
            num_witin += is_current_air.clone() * AB::F::from_usize(air_data.num_witin);
            num_structural_witin +=
                is_current_air.clone() * AB::F::from_usize(air_data.num_structural_witin);
            num_fixed += is_current_air.clone() * AB::F::from_usize(air_data.num_fixed);

            num_pvs += is_current_air.clone() * AB::F::from_usize(air_data.num_public_values);

            if air_data.is_required {
                is_required += is_current_air.clone();
                when_current.assert_one(local.is_present);
            }

            num_read_count +=
                is_current_air.clone() * AB::Expr::from_usize(air_data.num_read_count);
            num_write_count +=
                is_current_air.clone() * AB::Expr::from_usize(air_data.num_write_count);
            num_logup_count +=
                is_current_air.clone() * AB::Expr::from_usize(air_data.num_logup_count);

            // Keep this aligned with TowerInputAir's `tidx_after_gkr_layers`
            // arithmetic so fork challenge placement and tower buses share one
            // transcript span model.
            tower_tidx_bump += is_current_air
                * per_air_tower_span::<AB>(
                    n.clone(),
                    air_data.num_read_count,
                    air_data.num_write_count,
                    air_data.num_logup_count,
                );
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        // PERMUTATION AND SORTING
        ///////////////////////////////////////////////////////////////////////////////////////////
        builder.when(local.is_first).assert_zero(local.sorted_idx);
        builder
            .when(next.sorted_idx)
            .assert_eq(local.sorted_idx, next.sorted_idx - AB::F::ONE);

        self.permutation_bus.send(
            builder,
            local.proof_idx,
            ProofShapePermutationMessage {
                idx: local.sorted_idx,
            },
            local.is_valid,
        );

        self.permutation_bus.receive(
            builder,
            local.proof_idx,
            ProofShapePermutationMessage {
                idx: air_idx.clone(),
            },
            local.is_valid,
        );

        builder
            .when(and(not(local.is_present), local.is_valid))
            .assert_zero(local.height_1);
        builder
            .when(and(not(local.is_present), local.is_valid))
            .assert_zero(local.height_2);
        builder
            .when(and(not(local.is_present), local.is_valid))
            .assert_zero(local.log_height);

        // Range check difference using ExponentBus to ensure local.log_height >= next.log_height
        self.range_bus.lookup_key(
            builder,
            RangeCheckerBusMessage {
                value: local.log_height - next.log_height,
                max_bits: AB::Expr::from_usize(5),
            },
            and(local.is_valid, not(next.is_last)),
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // LOOKUP CHALLENGE
        ///////////////////////////////////////////////////////////////////////////////////////////
        for i in 0..D_EF {
            self.lookup_challenge_bus.lookup_key(
                builder,
                local.proof_idx,
                LookupChallengeMessage {
                    kind: AB::Expr::from_usize(LookupChallengeKind::Alpha.as_usize()),
                    word_idx: AB::Expr::from_usize(i),
                    value: local.lookup_challenge_alpha[i].into(),
                },
                local.is_present * local.is_valid,
            );
        }
        for i in 0..D_EF {
            self.lookup_challenge_bus.lookup_key(
                builder,
                local.proof_idx,
                LookupChallengeMessage {
                    kind: AB::Expr::from_usize(LookupChallengeKind::Beta.as_usize()),
                    word_idx: AB::Expr::from_usize(i),
                    value: local.lookup_challenge_beta[i].into(),
                },
                local.is_present * local.is_valid,
            );
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        // TRANSCRIPT OBSERVATIONS
        ///////////////////////////////////////////////////////////////////////////////////////////

        let is_first_idx = self.idx_encoder.get_flag_expr::<AB>(0, localv.idx_flags);

        // The first AIR starts immediately after the fixed trunk transcript prefix.
        builder.when(is_first_idx.clone()).assert_eq(
            local.starting_tidx,
            AB::Expr::from_usize(TranscriptLabel::Riscv.field_len() + VmPvs::<u8>::width())
                + AB::Expr::from_usize(2 * D_EF),
        );

        self.starting_tidx_bus.receive(
            builder,
            local.proof_idx,
            StartingTidxMessage {
                air_idx: air_idx.clone() * local.is_valid
                    + AB::Expr::from_usize(self.per_air.len()) * local.is_last,
                tidx: local.starting_tidx.into(),
            },
            or(
                local.is_last,
                and(local.is_valid, not::<AB::Expr>(is_first_idx)),
            ),
        );

        // Challenges are laid out in trunk transcript as contiguous EF limbs per present AIR.
        // We jump directly to this AIR's segment using num_present (1-based among present AIRs).
        let mut tidx =
            local.starting_tidx.into() + local.num_present * AB::Expr::from_usize(2 * D_EF);

        for i in 0..D_EF {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: tidx.clone() + AB::Expr::from_usize(i),
                    value: local.after_forked_challenge_1[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_present,
            );
        }
        tidx += AB::Expr::from_usize(D_EF) * local.is_present;

        for i in 0..D_EF {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: tidx.clone() + AB::Expr::from_usize(i),
                    value: local.after_forked_challenge_2[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_present,
            );
        }
        tidx += AB::Expr::from_usize(D_EF) * local.is_present;

        // constrain next air tid
        self.starting_tidx_bus.send(
            builder,
            local.proof_idx,
            StartingTidxMessage {
                air_idx: air_idx.clone() + AB::F::ONE,
                tidx,
            },
            local.is_valid,
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // SNAPSHOT STATE CONTINUITY (forked transcript)
        ///////////////////////////////////////////////////////////////////////////////////////////
        // Each present AIR corresponds to one fork whose fork_id equals
        // num_present - 1 (0-based position among present AIRs in sorted order).
        // This assumes a 1:1 mapping between present AIRs and forks, which
        // holds when each chip has exactly one proof instance. Multi-instance
        // chips would require a separate fork_id column.
        // Receive fork transcript words after the fork label prefix.
        let fork_tidx_base = TranscriptLabel::Fork.field_len();
        let fork_id = local.num_present - AB::F::ONE;
        // observe lookup alpha/beta
        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: fork_id.clone().into(),
                    tidx: AB::Expr::from_usize(fork_tidx_base + i),
                    value: local.lookup_challenge_alpha[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_present * local.is_valid,
            );
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: fork_id.clone().into(),
                    tidx: AB::Expr::from_usize(fork_tidx_base + D_EF + i),
                    value: local.lookup_challenge_beta[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_present * local.is_valid,
            );
        }
        self.forked_transcript_bus.receive(
            builder,
            local.proof_idx,
            ForkedTranscriptBusMessage {
                fork_id: fork_id.clone().into(),
                tidx: AB::Expr::from_usize(fork_tidx_base + 2 * D_EF),
                value: fork_id.clone(),
                is_sample: AB::Expr::ZERO,
            },
            local.is_present * local.is_valid,
        );
        // Fork transcript metadata order is fixed: num_present, air_idx, then log_height.
        self.forked_transcript_bus.receive(
            builder,
            local.proof_idx,
            ForkedTranscriptBusMessage {
                fork_id: fork_id.clone().into(),
                tidx: AB::Expr::from_usize(fork_tidx_base + 2 * D_EF + 1),
                value: air_idx.clone(),
                is_sample: AB::Expr::ZERO,
            },
            local.is_present * local.is_valid,
        );
        self.forked_transcript_bus.receive(
            builder,
            local.proof_idx,
            ForkedTranscriptBusMessage {
                fork_id: fork_id.clone().into(),
                tidx: AB::Expr::from_usize(fork_tidx_base + 2 * D_EF + 2),
                value: local.log_height.into(),
                is_sample: AB::Expr::ZERO,
            },
            local.is_present * local.is_valid,
        );

        // Skip the full per-air tower transcript span (out-evals, alpha/beta,
        // and all GKR/sumcheck layer transcript activity) before binding the
        // post-fork sampled challenges.
        let forked_challenge_1_tidx =
            AB::Expr::from_usize(fork_tidx_base + 2 * D_EF + 3) + tower_tidx_bump;
        // Challenge 2 starts after challenge 1 plus the product_sum label span.
        let forked_challenge_2_tidx =
            forked_challenge_1_tidx.clone() + AB::Expr::from_usize(tower_transcript_len::BETA_LEN);

        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: fork_id.clone().into(),
                    tidx: forked_challenge_1_tidx.clone() + AB::Expr::from_usize(i),
                    value: local.after_forked_challenge_1[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_present * local.is_valid,
            );
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: fork_id.clone().into(),
                    tidx: forked_challenge_2_tidx.clone() + AB::Expr::from_usize(i),
                    value: local.after_forked_challenge_2[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_present * local.is_valid,
            );
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        // AIR SHAPE LOOKUP
        ///////////////////////////////////////////////////////////////////////////////////////////
        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::AirId.to_field(),
                value: air_idx.clone(),
            },
            local.is_present * local.num_air_id_lookups,
        );

        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::NumInteractions.to_field(),
                value: AB::Expr::ZERO,
            },
            local.is_present,
        );

        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::NeedRot.to_field(),
                value: local.need_rot.into(),
            },
            local.is_present * local.num_columns,
        );
        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::NumRead.to_field(),
                value: num_read_count.clone(),
            },
            // each layer lookup once if current air was present
            local.is_present * n.clone(),
        );
        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::NumWrite.to_field(),
                value: num_write_count.clone(),
            },
            local.is_present * n.clone(),
        );
        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::NumLk.to_field(),
                value: num_logup_count,
            },
            local.is_present * n.clone(),
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // HYPERDIM LOOKUP
        ///////////////////////////////////////////////////////////////////////////////////////////
        builder.assert_bool(local.need_rot);
        builder
            .when(not(local.is_present))
            .assert_zero(local.need_rot);
        builder
            .when(not(local.is_present))
            .assert_zero(local.num_columns);
        // We range check n in [0, 32).
        self.range_bus.lookup_key(
            builder,
            RangeCheckerBusMessage {
                value: n.clone(),
                max_bits: AB::Expr::from_usize(5),
            },
            local.is_present,
        );

        self.hyperdim_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            HyperdimBusMessage {
                sort_idx: local.sorted_idx.into(),
                n_abs: n.clone(),
                n_sign_bit: AB::Expr::ZERO,
            },
            local.is_present * (local.num_air_id_lookups + AB::F::ONE),
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // LIFTED HEIGHTS LOOKUP + STACKING COMMITMENTS
        ///////////////////////////////////////////////////////////////////////////////////////////

        let _raw_height_1 = fold(
            local.height_1_limbs.iter().enumerate(),
            AB::Expr::ZERO,
            |acc, (i, limb)| acc + (AB::Expr::from_u32(1 << (i * LIMB_BITS)) * *limb),
        );
        let _raw_height_2 = fold(
            local.height_2_limbs.iter().enumerate(),
            AB::Expr::ZERO,
            |acc, (i, limb)| acc + (AB::Expr::from_u32(1 << (i * LIMB_BITS)) * *limb),
        );
        let combined_height = local.height_1 + local.height_2;

        self.lifted_heights_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            LiftedHeightsBusMessage {
                sort_idx: local.sorted_idx.into(),
                part_idx: AB::Expr::ZERO,
                commit_idx: AB::Expr::ZERO,
                hypercube_dim: n.clone(),
                lifted_height: combined_height.into(),
                log_lifted_height: local.log_height.into(),
            },
            local.is_present * (num_witin + num_structural_witin + num_fixed),
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // NUM PUBLIC VALUES
        ///////////////////////////////////////////////////////////////////////////////////////////
        let _ = num_pvs;

        ///////////////////////////////////////////////////////////////////////////////////////////
        // HEIGHT + GKR MESSAGE
        ///////////////////////////////////////////////////////////////////////////////////////////
        for i in 0..NUM_LIMBS {
            self.range_bus.lookup_key(
                builder,
                RangeCheckerBusMessage {
                    value: local.height_1_limbs[i].into(),
                    max_bits: AB::Expr::from_usize(LIMB_BITS),
                },
                local.is_valid,
            );
            self.range_bus.lookup_key(
                builder,
                RangeCheckerBusMessage {
                    value: local.height_2_limbs[i].into(),
                    max_bits: AB::Expr::from_usize(LIMB_BITS),
                },
                local.is_valid,
            );
        }

        // While the (N + 1)-th row (index N) is invalid, we use it to store the final number
        // of total cells. We thus can always constrain local.total_cells + local.num_cells =
        // next.total_cells when local is valid, and when we're on the summary row we can send
        // the stacking main width message.
        //
        // Note that we must constrain that the is_last flag is set correctly, i.e. it must
        // only be set on the row immediately after the N-th.
        builder.assert_bool(local.is_last);
        builder.when(local.is_last).assert_zero(local.is_valid);
        builder.when(next.is_last).assert_one(local.is_valid);
        builder
            .when(local.sorted_idx - AB::F::from_usize(self.per_air.len() - 1))
            .assert_zero(next.is_last);
        builder
            .when(next.is_last)
            .assert_zero(local.sorted_idx - AB::F::from_usize(self.per_air.len() - 1));

        // Constrain n_max on each row. Also constrain that local.is_n_max_greater is one when
        // n_max is greater than n_logup, and zero otherwise.
        builder
            .when(local.is_first)
            .assert_eq(local.n_max, n.clone());
        builder
            .when(local.is_valid)
            .assert_eq(local.n_max, next.n_max);

        builder.assert_bool(local.is_n_max_greater);
        self.range_bus.lookup_key(
            builder,
            RangeCheckerBusMessage {
                value: (local.n_max - n.clone())
                    * (local.is_n_max_greater * AB::F::TWO - AB::F::ONE),
                max_bits: AB::Expr::from_usize(5),
            },
            local.is_last,
        );

        self.tower_module_bus.send(
            builder,
            local.proof_idx,
            TowerModuleMessage {
                idx: air_idx.clone(),
                tidx: local.starting_tidx.into(),
                n_logup: n,
            },
            local.is_last,
        );

        // Send n_max value to expression claim air
        self.expression_claim_n_max_bus.send(
            builder,
            local.proof_idx,
            ExpressionClaimNMaxMessage {
                n_max: local.n_max.into(),
            },
            local.is_last,
        );

        // Send n_lift to constraint folding air
        self.n_lift_bus.send(
            builder,
            local.proof_idx,
            NLiftMessage {
                air_idx: air_idx,
                n_lift: local.log_height.into(),
            },
            local.is_present,
        );

        // Send count of present airs to fraction folder air
        self.fraction_folder_input_bus.send(
            builder,
            local.proof_idx,
            FractionFolderInputMessage {
                num_present_airs: local.num_present,
            },
            local.is_last,
        );
    }
}

fn per_air_tower_span<AB: AirBuilder>(
    n_logup: AB::Expr,
    num_read_count: usize,
    num_write_count: usize,
    num_logup_count: usize,
) -> AB::Expr {
    use tower_transcript_len::{
        ALPHA_BETA_LEN, ALPHA_LEN, POST_SUMCHECK_LEN, ROUND_LEN, SUMCHECK_INIT_LEN,
    };

    // Derivation notes (matches tower transcript replay order used by verifier):
    // 1) Out-evals before alpha/beta:
    //    - read spec contributes 2 EF evals, write spec contributes 2 EF evals,
    //      logup spec contributes 4 EF evals.
    //    - each EF observe_ext contributes D_EF base-field transcript words.
    // 2) Always sample alpha/beta next (ALPHA_BETA_LEN words).
    // 3) If this air has interactions, add full GKR layer transcript span:
    //    this is identical to TowerInputAir's closed-form tidx advancement
    //    from `tidx_after_alpha_beta` to `tidx_after_gkr_layers`.
    let out_eval_words = 2 * num_read_count + 2 * num_write_count + 4 * num_logup_count;
    let out_eval_span = AB::Expr::from_usize(out_eval_words * D_EF);

    let gkr_span = if out_eval_words == 0 {
        AB::Expr::ZERO
    } else {
        let gkr_inner = n_logup.clone() * AB::Expr::from_usize(ROUND_LEN / 2)
            + AB::Expr::from_usize(
                ALPHA_LEN + SUMCHECK_INIT_LEN + POST_SUMCHECK_LEN - ROUND_LEN / 2,
            );
        n_logup * gkr_inner - AB::Expr::from_usize(ALPHA_LEN + SUMCHECK_INIT_LEN)
    };

    out_eval_span + AB::Expr::from_usize(ALPHA_BETA_LEN) + gkr_span
}

pub(super) fn borrow_var_cols<F>(slice: &[F], idx_flags: usize) -> ProofShapeVarCols<'_, F> {
    ProofShapeVarCols {
        idx_flags: &slice[..idx_flags],
    }
}
