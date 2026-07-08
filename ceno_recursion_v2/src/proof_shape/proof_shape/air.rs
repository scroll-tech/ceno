use std::{borrow::Borrow, sync::Arc};

use itertools::fold;
use openvm_circuit_primitives::{
    SubAir,
    encoder::Encoder,
    utils::{and, not},
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
        AirPresenceBus, AirPresenceBusMessage, AirShapeBus, AirShapeBusMessage, ForkFinalSampleBus,
        ForkFinalSampleMessage, ForkedTranscriptBus, ForkedTranscriptBusMessage,
        LookupChallengeBus, LookupChallengeKind, LookupChallengeMessage, MainSelectorShapeBus,
        MainSelectorShapeMessage, MainSelectorSparseIndexShapeBus,
        MainSelectorSparseIndexShapeMessage, TowerModuleBus, TowerModuleMessage, TranscriptBus,
        TranscriptBusMessage,
    },
    primitives::bus::{RangeCheckerBus, RangeCheckerBusMessage},
    proof_shape::{
        AirMetadata, SelectorContextMode,
        bus::{
            AirShapeProperty, ProofShapePermutationBus, ProofShapePermutationMessage,
            StartingTidxBus,
        },
    },
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{LABEL_FORK_FIELDS, TranscriptLabel},
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
    // First possible transcript index of the current AIR.
    pub starting_tidx: F,
    // Fork-local transcript index where the tower verifier starts for this AIR.
    pub tower_tidx: F,
    // First trunk transcript index used by the fork-merge phase.
    pub fork_start_tidx: F,
    // Fork id assigned by native chip-proof iteration order.
    pub fork_id: F,
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

    /// The Poseidon2 sponge state at the fork point (trunk state just before
    /// forking). Constrained to be identical across all rows within a proof.
    pub lookup_challenge_alpha: [F; D_EF],
    pub lookup_challenge_beta: [F; D_EF],
    pub after_forked_challenge_1: [F; D_EF],
    pub after_forked_challenge_1_tidx: F,
    pub after_forked_challenge_2: [F; D_EF],
    pub tower_n_logup: F,
    pub tower_is_read_max: F,
    pub tower_is_write_max: F,
    pub tower_is_logup_max: F,
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
    pub air_presence_bus: AirPresenceBus,
    pub air_shape_bus: AirShapeBus,
    pub transcript_bus: TranscriptBus,
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub fork_final_sample_bus: ForkFinalSampleBus,
    pub main_selector_shape_bus: MainSelectorShapeBus,
    pub main_selector_sparse_index_shape_bus: MainSelectorSparseIndexShapeBus,
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
        builder.assert_bool(local.is_last);
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

        let mut num_read_count = AB::Expr::ZERO;
        let mut num_write_count = AB::Expr::ZERO;
        let mut num_logup_count = AB::Expr::ZERO;
        let mut has_read = AB::Expr::ZERO;
        let mut has_write = AB::Expr::ZERO;
        let mut has_logup = AB::Expr::ZERO;
        let mut rotation_vars = AB::Expr::ZERO;
        let mut ecc_extra_vars = AB::Expr::ZERO;
        let mut read_op_vars = AB::Expr::ZERO;
        let mut write_op_vars = AB::Expr::ZERO;
        let mut logup_op_vars = AB::Expr::ZERO;
        for (i, air_data) in self.per_air.iter().enumerate() {
            // We keep a running tally of how many transcript reads there should be up to any
            // given point, and use that to constrain initial_tidx
            let is_current_air = self.idx_encoder.get_flag_expr::<AB>(i, localv.idx_flags);
            let mut when_current = builder.when(is_current_air.clone());
            air_idx += is_current_air.clone() * AB::F::from_usize(i);

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
            has_read += is_current_air.clone() * AB::Expr::from_bool(air_data.num_read_count > 0);
            has_write += is_current_air.clone() * AB::Expr::from_bool(air_data.num_write_count > 0);
            has_logup += is_current_air.clone() * AB::Expr::from_bool(air_data.num_logup_count > 0);
            rotation_vars += is_current_air.clone() * AB::Expr::from_usize(air_data.rotation_vars);
            ecc_extra_vars +=
                is_current_air.clone() * AB::Expr::from_usize(air_data.ecc_extra_vars);
            read_op_vars += is_current_air.clone() * AB::Expr::from_usize(air_data.read_op_vars);
            write_op_vars += is_current_air.clone() * AB::Expr::from_usize(air_data.write_op_vars);
            logup_op_vars += is_current_air.clone() * AB::Expr::from_usize(air_data.logup_op_vars);

            let selector_enabled = local.is_present * local.is_valid * is_current_air.clone();
            for selector in &air_data.selectors {
                self.air_presence_bus.add_key_with_lookups(
                    builder,
                    local.proof_idx,
                    AirPresenceBusMessage {
                        air_idx: AB::Expr::from_usize(i),
                        is_present: AB::Expr::ONE,
                    },
                    selector_enabled.clone(),
                );
                let height_1: AB::Expr = local.height_1.into();
                let height_2: AB::Expr = local.height_2.into();
                let (ctx_offset, ctx_num_instances) = match selector.context_mode {
                    SelectorContextMode::Total => {
                        (AB::Expr::ZERO, height_1.clone() + height_2.clone())
                    }
                    SelectorContextMode::Read => (AB::Expr::ZERO, height_1.clone()),
                    SelectorContextMode::Write => (height_1.clone(), height_2.clone()),
                };
                let ctx_num_vars = n.clone()
                    + AB::Expr::from_usize(air_data.rotation_vars)
                    + AB::Expr::from_usize(air_data.ecc_extra_vars);
                self.main_selector_shape_bus.send(
                    builder,
                    local.proof_idx,
                    MainSelectorShapeMessage {
                        air_idx: AB::Expr::from_usize(i),
                        selector_idx: AB::Expr::from_usize(selector.selector_idx),
                        kind: AB::Expr::from_usize(selector.kind),
                        point_source: AB::Expr::from_usize(selector.point_source),
                        eval_idx: AB::Expr::from_usize(selector.eval_idx),
                        ctx_offset,
                        ctx_num_instances,
                        ctx_num_vars,
                        ordered_sparse_num_vars: AB::Expr::from_usize(
                            selector.ordered_sparse_num_vars,
                        ),
                        num_sparse_indices: AB::Expr::from_usize(selector.sparse_indices.len()),
                    },
                    selector_enabled.clone(),
                );
                for (sparse_pos, sparse_index) in selector.sparse_indices.iter().enumerate() {
                    self.main_selector_sparse_index_shape_bus.send(
                        builder,
                        local.proof_idx,
                        MainSelectorSparseIndexShapeMessage {
                            air_idx: AB::Expr::from_usize(i),
                            selector_idx: AB::Expr::from_usize(selector.selector_idx),
                            sparse_pos: AB::Expr::from_usize(sparse_pos),
                            sparse_index: AB::Expr::from_usize(*sparse_index),
                        },
                        selector_enabled.clone(),
                    );
                }
            }
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
                max_bits: AB::Expr::from_usize(8),
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

        // All active proof-shape rows for a proof agree on the trunk fork-merge
        // start. The value is also constrained by the trunk TranscriptBus
        // receives below; it is not the same concept as proof-shape post_tidx.
        builder
            .when(local.is_valid)
            .assert_eq(local.fork_start_tidx, next.fork_start_tidx);

        // Native verifier merge phase:
        //   sample one EF from each fresh fork transcript, then observe that EF
        //   on the trunk in fork-id order.
        let merge_tidx = local.fork_start_tidx.into() + local.fork_id * AB::Expr::from_usize(D_EF);
        for i in 0..D_EF {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: merge_tidx.clone() + AB::Expr::from_usize(i),
                    value: local.after_forked_challenge_1[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_present,
            );
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        // SNAPSHOT STATE CONTINUITY (forked transcript)
        ///////////////////////////////////////////////////////////////////////////////////////////
        // Receive fork transcript words after the fork label prefix.
        let fork_tidx_base = TranscriptLabel::Fork.field_len();
        let fork_id = local.fork_id;
        self.forked_transcript_bus.receive(
            builder,
            local.proof_idx,
            ForkedTranscriptBusMessage {
                fork_id: fork_id.clone().into(),
                tidx: AB::Expr::ZERO,
                value: AB::Expr::from_u32(LABEL_FORK_FIELDS[0]),
                is_sample: AB::Expr::ZERO,
            },
            local.is_present * local.is_valid,
        );
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
                value: fork_id.clone().into(),
                is_sample: AB::Expr::ZERO,
            },
            local.is_present * local.is_valid,
        );
        // Fork transcript metadata order is fixed: fork_id, circuit_index,
        // num_instances[0], num_instances[1]. The two fixed num-instance
        // fields are represented as height_1/height_2 in this AIR.
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
                value: local.height_1.into(),
                is_sample: AB::Expr::ZERO,
            },
            local.is_present * local.is_valid,
        );
        self.forked_transcript_bus.receive(
            builder,
            local.proof_idx,
            ForkedTranscriptBusMessage {
                fork_id: fork_id.clone().into(),
                tidx: AB::Expr::from_usize(fork_tidx_base + 2 * D_EF + 3),
                value: local.height_2.into(),
                is_sample: AB::Expr::ZERO,
            },
            local.is_present * local.is_valid,
        );

        // Bind the final sample from this fork transcript. Preflight owns the
        // replayed fork-local tidx; semantic tower AIRs consume the transcript
        // rows before this point.
        let forked_challenge_1_tidx = local.after_forked_challenge_1_tidx.into();
        self.fork_final_sample_bus.receive(
            builder,
            local.proof_idx,
            ForkFinalSampleMessage {
                fork_id: fork_id.clone().into(),
                tidx: forked_challenge_1_tidx.clone(),
            },
            local.is_present * local.is_valid,
        );
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
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        // AIR SHAPE LOOKUP
        ///////////////////////////////////////////////////////////////////////////////////////////
        let base_tower_vars = n.clone() + rotation_vars + ecc_extra_vars;
        // TODO(recursion-v2): prove this low-degree by sending the
        // TowerShapeAir-derived max_layer_count to TowerInputAir. The direct
        // one-hot max expression is too high degree for this AIR.
        let _ = (has_read, has_write, has_logup);
        builder.assert_bool(local.tower_is_read_max);
        builder.assert_bool(local.tower_is_write_max);
        builder.assert_bool(local.tower_is_logup_max);

        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::BaseTowerVars.to_field(),
                value: base_tower_vars,
            },
            local.is_present,
        );
        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::ReadOpVars.to_field(),
                value: read_op_vars,
            },
            local.is_present,
        );
        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::WriteOpVars.to_field(),
                value: write_op_vars,
            },
            local.is_present,
        );
        self.air_shape_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            AirShapeBusMessage {
                sort_idx: local.sorted_idx.into(),
                property_idx: AirShapeProperty::LogupOpVars.to_field(),
                value: logup_op_vars,
            },
            local.is_present,
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // HYPERDIM LOOKUP
        ///////////////////////////////////////////////////////////////////////////////////////////
        // We range check n in [0, 32).
        self.range_bus.lookup_key(
            builder,
            RangeCheckerBusMessage {
                value: n.clone(),
                max_bits: AB::Expr::from_usize(8),
            },
            local.is_present,
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // LIFTED HEIGHTS LOOKUP + STACKING COMMITMENTS
        ///////////////////////////////////////////////////////////////////////////////////////////

        let raw_height_1 = fold(
            local.height_1_limbs.iter().enumerate(),
            AB::Expr::ZERO,
            |acc, (i, limb)| acc + (AB::Expr::from_u32(1 << (i * LIMB_BITS)) * *limb),
        );
        let raw_height_2 = fold(
            local.height_2_limbs.iter().enumerate(),
            AB::Expr::ZERO,
            |acc, (i, limb)| acc + (AB::Expr::from_u32(1 << (i * LIMB_BITS)) * *limb),
        );
        builder
            .when(local.is_valid)
            .assert_eq(local.height_1, raw_height_1);
        builder
            .when(local.is_valid)
            .assert_eq(local.height_2, raw_height_2);
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
                max_bits: AB::Expr::from_usize(8),
            },
            local.is_last,
        );

        self.tower_module_bus.send(
            builder,
            local.proof_idx,
            TowerModuleMessage {
                idx: local.sorted_idx.into(),
                tidx: local.tower_tidx.into(),
                n_logup: local.tower_n_logup.into(),
            },
            local.is_present * local.is_valid,
        );
    }
}

pub(super) fn borrow_var_cols<F>(slice: &[F], idx_flags: usize) -> ProofShapeVarCols<'_, F> {
    ProofShapeVarCols {
        idx_flags: &slice[..idx_flags],
    }
}
