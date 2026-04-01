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
use openvm_stark_sdk::config::baby_bear_poseidon2::DIGEST_SIZE;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        AirShapeBus, AirShapeBusMessage, CachedCommitBus, ExpressionClaimNMaxBus,
        ExpressionClaimNMaxMessage, ForkedTranscriptBus, ForkedTranscriptBusMessage,
        FractionFolderInputBus, FractionFolderInputMessage,
        HyperdimBus, HyperdimBusMessage, LiftedHeightsBus, LiftedHeightsBusMessage, NLiftBus,
        NLiftMessage, TowerModuleBus, TowerModuleMessage, TranscriptBus, TranscriptBusMessage,
    },
    primitives::bus::{RangeCheckerBus, RangeCheckerBusMessage},
    proof_shape::{
        AirMetadata,
        bus::{
            AirShapeProperty, NumPublicValuesBus,
            NumPublicValuesMessage, ProofShapePermutationBus, ProofShapePermutationMessage,
            StartingTidxBus, StartingTidxMessage,
        },
    },
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::TranscriptLabel,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct ProofShapeCols<F, const NUM_LIMBS: usize> {
    pub proof_idx: F,
    pub is_valid: F,
    pub is_first: F,
    pub is_last: F,

    // loop: proof_idx -> idx (air idx)
    pub idx: F,
    pub sorted_idx: F,
    /// Represents `log2(next_pow_2(height))` when `is_present`.
    ///
    /// Has a special use on summary row (when `is_last`).
    pub log_height: F,
    /// Whether this AIR needs rotation openings.
    pub need_rot: F,

    // First possible tidx and non-main cidx of the current AIR
    pub starting_tidx: F,
    // pub starting_cidx: F,

    // Columns that may be read from the transcript. Note that cached_commits is also read
    // from the transcript.
    pub is_present: F,

    /// Lifted trace height (`2^log_height`) used in downstream lookups when `is_present`.
    ///
    /// Has a special use on summary row (when `is_last`).
    pub height: F,

    // Number of present AIRs so far
    pub num_present: F,

    /// Limb decomposition of `height` used for range/decomposition checks.
    pub height_limbs: [F; NUM_LIMBS],

    /// The maximum hypercube dimension across all present AIR traces, or zero.
    /// Computed as max(0, n0, n1, ...) where ni = log_height_i for each present trace.
    pub n_max: F,
    pub is_n_max_greater: F,

    pub num_air_id_lookups: F,
    pub num_columns: F,

    /// The Poseidon2 sponge state at the fork point (trunk state just before
    /// forking). Constrained to be identical across all rows within a proof.
    pub current_snapshot_state: [F; POSEIDON2_WIDTH],
}

// Variable-length columns are stored at the end
pub struct ProofShapeVarCols<'a, F> {
    pub idx_flags: &'a [F],                     // [F; IDX_FLAGS]
    pub cached_commits: &'a [[F; DIGEST_SIZE]], // [[F; DIGEST_SIZE]; MAX_CACHED]
}

/// AIR for verifying the proof shape (trace heights, widths, commitments) of a child proof
/// within the recursion circuit.
///
/// The AIR enforces per-AIR shape consistency and forwards metadata to downstream buses.
pub struct ProofShapeAir<const NUM_LIMBS: usize, const LIMB_BITS: usize> {
    // Parameters derived from vk
    pub per_air: Vec<AirMetadata>,
    pub min_cached_idx: usize,
    pub max_cached: usize,
    pub commit_mult: usize,

    // Primitives
    pub idx_encoder: Arc<Encoder>,
    pub range_bus: RangeCheckerBus,

    // Internal buses
    pub permutation_bus: ProofShapePermutationBus,
    pub starting_tidx_bus: StartingTidxBus,
    pub num_pvs_bus: NumPublicValuesBus,

    // Inter-module buses
    pub tower_module_bus: TowerModuleBus,
    pub air_shape_bus: AirShapeBus,
    pub expression_claim_n_max_bus: ExpressionClaimNMaxBus,
    pub fraction_folder_input_bus: FractionFolderInputBus,
    pub hyperdim_bus: HyperdimBus,
    pub lifted_heights_bus: LiftedHeightsBus,
    // pub commitments_bus: GlobalCommitmentsBus,
    pub transcript_bus: TranscriptBus,
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub n_lift_bus: NLiftBus,

    // For continuations
    pub cached_commit_bus: CachedCommitBus,
    pub continuations_enabled: bool,
}

impl<F, const NUM_LIMBS: usize, const LIMB_BITS: usize> BaseAir<F>
    for ProofShapeAir<NUM_LIMBS, LIMB_BITS>
{
    fn width(&self) -> usize {
        ProofShapeCols::<F, NUM_LIMBS>::width()
            + self.idx_encoder.width()
            + self.max_cached * DIGEST_SIZE
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

        let localv = borrow_var_cols::<AB::Var>(
            &local[const_width..],
            self.idx_encoder.width(),
            self.max_cached,
        );
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
            ProofShapePermutationMessage { idx: local.idx },
            local.is_valid,
        );

        builder
            .when(and(not(local.is_present), local.is_valid))
            .assert_zero(local.height);
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
        // VK FIELD SELECTION
        ///////////////////////////////////////////////////////////////////////////////////////////
        // Select values for TranscriptBus
        let mut is_required = AB::Expr::ZERO;
        let mut is_min_cached = AB::Expr::ZERO;
        let mut has_preprocessed = AB::Expr::ZERO;
        let mut cached_present = vec![AB::Expr::ZERO; self.max_cached];

        // Select values for LiftedHeightsBus
        let mut main_common_width = AB::Expr::ZERO;
        let mut preprocessed_stacked_width = AB::Expr::ZERO;
        let mut cached_widths = vec![AB::Expr::ZERO; self.max_cached];

        // Select values for CommitmentsBus
        let mut preprocessed_commit = [AB::Expr::ZERO; DIGEST_SIZE];

        // Select values for NumPublicValuesBus
        let mut num_pvs = AB::Expr::ZERO;
        let mut has_pvs = AB::Expr::ZERO;
        let mut num_read_count = AB::Expr::ZERO;
        let mut num_write_count = AB::Expr::ZERO;
        let mut num_logup_count = AB::Expr::ZERO;

        for (i, air_data) in self.per_air.iter().enumerate() {
            // We keep a running tally of how many transcript reads there should be up to any
            // given point, and use that to constrain initial_tidx
            let is_current_air = self.idx_encoder.get_flag_expr::<AB>(i, localv.idx_flags);
            let mut when_current = builder.when(is_current_air.clone());

            when_current.assert_eq(local.idx, AB::F::from_usize(i));

            main_common_width += is_current_air.clone() * AB::F::from_usize(air_data.main_width);

            if air_data.num_public_values != 0 {
                has_pvs += is_current_air.clone();
            }
            num_pvs += is_current_air.clone() * AB::F::from_usize(air_data.num_public_values);

            if air_data.is_required {
                is_required += is_current_air.clone();
                when_current.assert_one(local.is_present);
            }

            if i == self.min_cached_idx {
                is_min_cached += is_current_air.clone();
            }

            assert!(air_data.preprocessed_data.is_none());
            if let Some(preprocessed) = &air_data.preprocessed_data {
                when_current.assert_eq(
                    local.log_height,
                    AB::Expr::from_usize(0usize.wrapping_add_signed(preprocessed.hypercube_dim)),
                );
                has_preprocessed += is_current_air.clone();

                preprocessed_stacked_width += is_current_air.clone()
                    * AB::F::from_usize(air_data.preprocessed_width.unwrap());
                (0..DIGEST_SIZE).for_each(|didx| {
                    preprocessed_commit[didx] += is_current_air.clone()
                        * AB::F::from_u32(preprocessed.commit[didx].as_canonical_u32());
                });
            }

            for (cached_idx, width) in air_data.cached_widths.iter().enumerate() {
                cached_present[cached_idx] += is_current_air.clone();
                cached_widths[cached_idx] += is_current_air.clone() * AB::Expr::from_usize(*width);
            }

            num_read_count +=
                is_current_air.clone() * AB::Expr::from_usize(air_data.num_read_count);
            num_write_count +=
                is_current_air.clone() * AB::Expr::from_usize(air_data.num_write_count);
            num_logup_count +=
                is_current_air.clone() * AB::Expr::from_usize(air_data.num_logup_count);
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        // TRANSCRIPT OBSERVATIONS
        ///////////////////////////////////////////////////////////////////////////////////////////
        let is_first_idx = self.idx_encoder.get_flag_expr::<AB>(0, localv.idx_flags);
        // FIXME: simplify separators
        builder.when(is_first_idx.clone()).assert_eq(
            local.starting_tidx,
            AB::Expr::from_usize(TranscriptLabel::Riscv.field_len()),
        );

        self.starting_tidx_bus.receive(
            builder,
            local.proof_idx,
            StartingTidxMessage {
                air_idx: local.idx * local.is_valid
                    + AB::Expr::from_usize(self.per_air.len()) * local.is_last,
                tidx: local.starting_tidx.into(),
            },
            or(
                local.is_last,
                and(local.is_valid, not::<AB::Expr>(is_first_idx)),
            ),
        );

        let mut tidx = local.starting_tidx.into();
        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: tidx.clone(),
                value: local.is_present.into(),
                is_sample: AB::Expr::ZERO,
            },
            not::<AB::Expr>(is_required.clone()) * local.is_valid,
        );
        tidx += not::<AB::Expr>(is_required) * local.is_valid;

        for (didx, commit_val) in preprocessed_commit.iter().enumerate() {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: tidx.clone() + AB::Expr::from_usize(didx),
                    value: commit_val.clone(),
                    is_sample: AB::Expr::ZERO,
                },
                has_preprocessed.clone() * local.is_present,
            );
        }
        tidx += has_preprocessed.clone() * AB::Expr::from_usize(DIGEST_SIZE) * local.is_present;

        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: tidx.clone(),
                value: local.log_height.into(),
                is_sample: AB::Expr::ZERO,
            },
            not::<AB::Expr>(has_preprocessed.clone()) * local.is_present,
        );
        tidx += not::<AB::Expr>(has_preprocessed.clone()) * local.is_present;

        (0..self.max_cached).for_each(|i| {
            for didx in 0..DIGEST_SIZE {
                self.transcript_bus.receive(
                    builder,
                    local.proof_idx,
                    TranscriptBusMessage {
                        tidx: tidx.clone(),
                        value: localv.cached_commits[i][didx].into(),
                        is_sample: AB::Expr::ZERO,
                    },
                    cached_present[i].clone() * local.is_present,
                );
                tidx += cached_present[i].clone() * local.is_present;
            }
        });

        let num_pvs_tidx = tidx.clone();
        tidx += num_pvs.clone() * local.is_present;

        // constrain next air tid
        self.starting_tidx_bus.send(
            builder,
            local.proof_idx,
            StartingTidxMessage {
                air_idx: local.idx + AB::F::ONE,
                tidx,
            },
            local.is_valid,
        );

        for didx in 0..DIGEST_SIZE {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: AB::Expr::from_usize(didx),
                    value: localv.cached_commits[self.max_cached - 1][didx].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_last,
            );

            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: AB::Expr::from_usize(didx + DIGEST_SIZE),
                    value: localv.cached_commits[self.max_cached - 1][didx].into(),
                    is_sample: AB::Expr::ZERO,
                },
                is_min_cached.clone() * local.is_valid,
            );
        }

        ///////////////////////////////////////////////////////////////////////////////////////////
        // SNAPSHOT STATE CONTINUITY (forked transcript)
        ///////////////////////////////////////////////////////////////////////////////////////////
        // The sponge state at the fork point is identical for all forks.
        // Constrain: local.current_snapshot_state == next.current_snapshot_state
        // for all valid rows within the same proof.
        for i in 0..POSEIDON2_WIDTH {
            builder
                .when(and(local.is_valid, not(next.is_last)))
                .assert_eq(
                    local.current_snapshot_state[i],
                    next.current_snapshot_state[i],
                );
        }

        // Each present AIR corresponds to one fork whose fork_id equals
        // num_present (1-based position among present AIRs in sorted order).
        // This assumes a 1:1 mapping between present AIRs and forks, which
        // holds when each chip has exactly one proof instance. Multi-instance
        // chips would require a separate fork_id column.
        // Receive the trunk's sponge state at the fork point from the
        // ForkedTranscriptBus, cross-checking current_snapshot_state against
        // TranscriptAir's trunk_fork_state.
        for i in 0..POSEIDON2_WIDTH {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.num_present.into(),
                    fork_tidx: AB::Expr::from_usize(i),
                    value: local.current_snapshot_state[i].into(),
                    is_sample: AB::Expr::ZERO,
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
                value: local.idx.into(),
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
        let _raw_height = fold(
            local.height_limbs.iter().enumerate(),
            AB::Expr::ZERO,
            |acc, (i, limb)| acc + (AB::Expr::from_u32(1 << (i * LIMB_BITS)) * *limb),
        );

        self.lifted_heights_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            LiftedHeightsBusMessage {
                sort_idx: local.sorted_idx.into(),
                part_idx: AB::Expr::ZERO,
                commit_idx: AB::Expr::ZERO,
                hypercube_dim: n.clone(),
                lifted_height: local.height.into(),
                log_lifted_height: local.log_height.into(),
            },
            local.is_present * main_common_width,
        );

        // cidx start from 1
        // TODO(starting-cidx): starting_cidx flow is intentionally disabled in local fork.
        // builder
        //     .when(and(local.is_first, local.is_valid))
        //     .assert_one(local.starting_cidx);
        // let mut cidx_offset = AB::Expr::ZERO;

        // NOTE: this is non used if preprocessed_stacked_width == 0
        // self.lifted_heights_bus.add_key_with_lookups(
        //     builder,
        //     local.proof_idx,
        //     LiftedHeightsBusMessage {
        //         sort_idx: local.sorted_idx.into(),
        //         part_idx: cidx_offset.clone() + AB::F::ONE,
        //         commit_idx: cidx_offset.clone() + local.starting_cidx,
        //         hypercube_dim: n.clone(),
        //         lifted_height: local.height.into(),
        //         log_lifted_height: local.log_height.into(),
        //     },
        //     local.is_present * preprocessed_stacked_width,
        // );

        // NOTE: this is non-used if has_preprocessed == 0
        // self.commitments_bus.add_key_with_lookups(
        //     builder,
        //     local.proof_idx,
        //     CommitmentsBusMessage {
        //         major_idx: AB::Expr::ZERO,
        //         minor_idx: cidx_offset.clone() + local.starting_cidx,
        //         commitment: preprocessed_commit,
        //     },
        //     has_preprocessed.clone() * local.is_present * AB::Expr::from_usize(self.commit_mult),
        // );
        // cidx_offset still be 0
        // cidx_offset += has_preprocessed.clone();
        // TODO(starting-cidx): re-enable if/when commit-index stacking flow is restored.
        // let mut cidx_offset = AB::Expr::ZERO;

        // (0..self.max_cached).for_each(|cached_idx| {
        //     self.lifted_heights_bus.add_key_with_lookups(
        //         builder,
        //         local.proof_idx,
        //         LiftedHeightsBusMessage {
        //             sort_idx: local.sorted_idx.into(),
        //             part_idx: cidx_offset.clone() + AB::F::ONE,
        //             commit_idx: cidx_offset.clone() + local.starting_cidx,
        //             hypercube_dim: n.clone(),
        //             lifted_height: local.height.into(),
        //             log_lifted_height: local.log_height.into(),
        //         },
        //         local.is_present * cached_widths[cached_idx].clone(),
        //     );
        //
        //     // self.commitments_bus.add_key_with_lookups(
        //     //     builder,
        //     //     local.proof_idx,
        //     //     CommitmentsBusMessage {
        //     //         major_idx: AB::Expr::ZERO,
        //     //         minor_idx: cidx_offset.clone() + local.starting_cidx,
        //     //         commitment: localv.cached_commits[cached_idx].map(Into::into),
        //     //     },
        //     //     cached_present[cached_idx].clone()
        //     //         * local.is_present
        //     //         * AB::Expr::from_usize(self.commit_mult),
        //     // );
        //     // cidx_offset += cached_present[cached_idx].clone();
        //
        //     // self.cached_commit_bus.send(
        //     //     builder,
        //     //     local.proof_idx,
        //     //     CachedCommitBusMessage {
        //     //         air_idx: local.idx.into(),
        //     //         cached_idx: AB::Expr::from_usize(cached_idx),
        //     //         cached_commit: localv.cached_commits[cached_idx].map(Into::into),
        //     //     },
        //     //     cached_present[cached_idx].clone()
        //     //         * local.is_valid
        //     //         * AB::Expr::from_bool(self.continuations_enabled),
        //     // );
        // });

        // TODO(starting-cidx): disabled alongside local starting_cidx removal.
        // builder
        //     .when(and(local.is_valid, not(next.is_last)))
        //     .assert_eq(local.starting_cidx + cidx_offset, next.starting_cidx);
        //
        // self.commitments_bus.add_key_with_lookups(
        //     builder,
        //     local.proof_idx,
        //     GlobalCommitmentsBusMessage {
        //         major_idx: AB::Expr::ZERO,
        //         minor_idx: AB::Expr::ZERO,
        //         commitment: localv.cached_commits[self.max_cached - 1].map(Into::into),
        //     },
        //     is_min_cached.clone() * local.is_valid * AB::Expr::from_usize(self.commit_mult),
        // );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // NUM PUBLIC VALUES
        ///////////////////////////////////////////////////////////////////////////////////////////
        self.num_pvs_bus.send(
            builder,
            local.proof_idx,
            NumPublicValuesMessage {
                air_idx: local.idx.into(),
                tidx: num_pvs_tidx,
                num_pvs,
            },
            local.is_present * has_pvs,
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        // HEIGHT + GKR MESSAGE
        ///////////////////////////////////////////////////////////////////////////////////////////
        for i in 0..NUM_LIMBS {
            self.range_bus.lookup_key(
                builder,
                RangeCheckerBusMessage {
                    value: local.height_limbs[i].into(),
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
                idx: local.idx.into(),
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
                air_idx: local.idx.into(),
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

pub(super) fn borrow_var_cols<F>(
    slice: &[F],
    idx_flags: usize,
    max_cached: usize,
) -> ProofShapeVarCols<'_, F> {
    let flags_idx = 0;
    let cached_commits_idx = flags_idx + idx_flags;

    let cached_commits = &slice[cached_commits_idx..cached_commits_idx + max_cached * DIGEST_SIZE];
    let cached_commits: &[[F; DIGEST_SIZE]] = unsafe {
        std::slice::from_raw_parts(
            cached_commits.as_ptr() as *const [F; DIGEST_SIZE],
            max_cached,
        )
    };

    ProofShapeVarCols {
        idx_flags: &slice[flags_idx..cached_commits_idx],
        cached_commits,
    }
}
