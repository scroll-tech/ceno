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
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        AirShapeBus, AirShapeBusMessage, CachedCommitBus, CachedCommitBusMessage, CommitmentsBus,
        CommitmentsBusMessage, ExpressionClaimNMaxBus, ExpressionClaimNMaxMessage,
        FractionFolderInputBus, FractionFolderInputMessage, HyperdimBus, HyperdimBusMessage,
        LiftedHeightsBus, LiftedHeightsBusMessage, NLiftBus, NLiftMessage, TowerModuleBus,
        TowerModuleMessage, TranscriptBus, TranscriptBusMessage,
    },
    primitives::bus::{
        PowerCheckerBus, PowerCheckerBusMessage, RangeCheckerBus, RangeCheckerBusMessage,
    },
    proof_shape::{
        AirMetadata,
        bus::{
            AirShapeProperty, NumPublicValuesBus, NumPublicValuesMessage, ProofShapePermutationBus,
            ProofShapePermutationMessage, StartingTidxBus, StartingTidxMessage,
        },
    },
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
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
    /// Represents log2 trace height when `is_present`.
    ///
    /// Has a special use on summary row (when `is_last`).
    pub log_height: F,
    /// Whether this AIR needs rotation openings.
    pub need_rot: F,

    // First possible tidx and non-main cidx of the current AIR
    pub starting_tidx: F,
    pub starting_cidx: F,

    // Columns that may be read from the transcript. Note that cached_commits is also read
    // from the transcript.
    pub is_present: F,

    /// Will be constrained to be `2^log_height` when `is_present`.
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
    pub pow_bus: PowerCheckerBus,

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
    pub commitments_bus: CommitmentsBus,
    pub transcript_bus: TranscriptBus,
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
    /* debug block: Step 1 placeholder - all constraints deferred pending trace implementation */
    #[allow(unused_variables)]
    let _ = &builder;
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
