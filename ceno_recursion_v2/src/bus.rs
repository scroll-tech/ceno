use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, DIGEST_SIZE};
use recursion_circuit::{
    bus as upstream, define_typed_per_proof_lookup_bus, define_typed_per_proof_permutation_bus,
};
pub use upstream::{
    AirPresenceBus, AirPresenceBusMessage, AirShapeBus, AirShapeBusMessage, CachedCommitBus,
    CachedCommitBusMessage, ColumnClaimsBus, ColumnClaimsMessage, ExpressionClaimNMaxBus,
    ExpressionClaimNMaxMessage, FractionFolderInputBus, FractionFolderInputMessage, HyperdimBus,
    HyperdimBusMessage, LiftedHeightsBus, LiftedHeightsBusMessage, NLiftBus, NLiftMessage,
    PublicValuesBus, PublicValuesBusMessage, SelHypercubeBus, SelHypercubeBusMessage, SelUniBus,
    SelUniBusMessage, TranscriptBus, TranscriptBusMessage,
};

// ── Forked transcript bus ─────────────────────────────────────────────────────
// Carries per-chip fork transcript state, addressed by (fork_id, tidx)
// instead of the absolute tidx used by the trunk TranscriptBus.

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct ForkedTranscriptBusMessage<T> {
    /// Fork identifier (1-based). Matches TranscriptAir's fork_id column.
    pub fork_id: T,
    /// Position within the fork transcript namespace.
    pub tidx: T,
    /// Sponge state element being communicated.
    pub value: T,
    /// 1 if this is a sample operation, 0 if observe.
    pub is_sample: T,
}

define_typed_per_proof_permutation_bus!(ForkedTranscriptBus, ForkedTranscriptBusMessage);

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum LookupChallengeKind {
    Alpha = 0,
    Beta = 1,
}

impl LookupChallengeKind {
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct LookupChallengeMessage<T> {
    pub kind: T,
    pub word_idx: T,
    pub value: T,
}

define_typed_per_proof_lookup_bus!(LookupChallengeBus, LookupChallengeMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct TowerModuleMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub n_logup: T,
}

define_typed_per_proof_permutation_bus!(TowerModuleBus, TowerModuleMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct ForkFinalSampleMessage<T> {
    pub fork_id: T,
    pub tidx: T,
}

define_typed_per_proof_permutation_bus!(ForkFinalSampleBus, ForkFinalSampleMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainBus, MainMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainSumcheckInputMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainSumcheckInputBus, MainSumcheckInputMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainSumcheckOutputMessage<T> {
    pub idx: T,
    pub claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainSumcheckOutputBus, MainSumcheckOutputMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainExpressionClaimMessage<T> {
    pub idx: T,
    pub claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainExpressionClaimBus, MainExpressionClaimMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainGlobalClaimMessage<T> {
    pub expected: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainGlobalClaimBus, MainGlobalClaimMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainGlobalPointMessage<T> {
    pub round_idx: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(MainGlobalPointBus, MainGlobalPointMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainEvalMessage<T> {
    pub idx: T,
    pub eval_idx: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(MainEvalBus, MainEvalMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainContributionMessage<T> {
    pub idx: T,
    pub contribution: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainContributionBus, MainContributionMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainSelectorResultMessage<T> {
    pub idx: T,
    pub eval_idx: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainSelectorResultBus, MainSelectorResultMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainSelectorPointMessage<T> {
    pub idx: T,
    pub air_idx: T,
    pub selector_idx: T,
    pub source_kind: T,
    pub round_idx: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(MainSelectorPointBus, MainSelectorPointMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct EccRtMessage<T> {
    pub idx: T,
    pub round_idx: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(EccRtBus, EccRtMessage);

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MainEccRtChallengeKind {
    Rt = 0,
    OutRt = 1,
    Alpha = 2,
}

impl MainEccRtChallengeKind {
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainEccRtChallengeMessage<T> {
    pub idx: T,
    pub round_idx: T,
    pub kind: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(MainEccRtChallengeBus, MainEccRtChallengeMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainEccRtSumcheckFinalMessage<T> {
    pub idx: T,
    pub claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainEccRtSumcheckFinalBus, MainEccRtSumcheckFinalMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainEccRtEquationTotalsMessage<T> {
    pub idx: T,
    pub add_eval: [T; D_EF],
    pub bypass_eval: [T; D_EF],
    pub export_eval: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainEccRtEquationTotalsBus, MainEccRtEquationTotalsMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainEccRtQuarkFinalMessage<T> {
    pub idx: T,
    pub quark_out: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(MainEccRtQuarkFinalBus, MainEccRtQuarkFinalMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainSelectorShapeMessage<T> {
    pub air_idx: T,
    pub selector_idx: T,
    pub kind: T,
    pub point_source: T,
    pub eval_idx: T,
    pub ctx_offset: T,
    pub ctx_num_instances: T,
    pub ctx_num_vars: T,
    pub ordered_sparse_num_vars: T,
    pub num_sparse_indices: T,
}

define_typed_per_proof_permutation_bus!(MainSelectorShapeBus, MainSelectorShapeMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct MainSelectorSparseIndexShapeMessage<T> {
    pub air_idx: T,
    pub selector_idx: T,
    pub sparse_pos: T,
    pub sparse_index: T,
}

define_typed_per_proof_permutation_bus!(
    MainSelectorSparseIndexShapeBus,
    MainSelectorSparseIndexShapeMessage
);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct TowerMainPointMessage<T> {
    pub idx: T,
    pub round_idx: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(TowerMainPointBus, TowerMainPointMessage);

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PcsBasefoldQueryStage {
    ReducedOpening = 0,
    FinalFolded = 1,
    QueryIndex = 2,
}

impl PcsBasefoldQueryStage {
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsBasefoldQueryMessage<T> {
    pub query_idx: T,
    pub stage: T,
    pub round: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(PcsBasefoldQueryBus, PcsBasefoldQueryMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsBaseInputOpeningMessage<T> {
    pub query_idx: T,
    pub opening_idx: T,
    pub reduced_index: T,
    pub value_idx: T,
    pub elem_idx: T,
    pub log2_height: T,
    pub opened_value: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(PcsBaseInputOpeningBus, PcsBaseInputOpeningMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsFinalMessageMessage<T> {
    pub tidx: T,
    pub value: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(PcsFinalMessageBus, PcsFinalMessageMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsQuerySampleMessage<T> {
    pub tidx: T,
    pub value: T,
}

define_typed_per_proof_lookup_bus!(PcsQuerySampleBus, PcsQuerySampleMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsCommitmentRootMessage<T> {
    pub commit_major: T,
    pub commit_minor: T,
    pub root: [T; DIGEST_SIZE],
}

define_typed_per_proof_lookup_bus!(PcsCommitmentRootBus, PcsCommitmentRootMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsCommitPhaseLeafMessage<T> {
    pub query_idx: T,
    pub round: T,
    pub leaf_idx: T,
    pub left: [T; D_EF],
    pub right: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(PcsCommitPhaseLeafBus, PcsCommitPhaseLeafMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsSumcheckClaimMessage<T> {
    pub idx: T,
    pub claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(PcsSumcheckClaimBus, PcsSumcheckClaimMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsFoldChallengeMessage<T> {
    pub sumcheck_idx: T,
    pub round: T,
    pub challenge: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(PcsFoldChallengeBus, PcsFoldChallengeMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsBatchCoeffMessage<T> {
    pub global_coeff_idx: T,
    pub coeff: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(PcsBatchCoeffBus, PcsBatchCoeffMessage);

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct PcsBatchAlphaMessage<T> {
    pub tidx: T,
    pub alpha: [T; D_EF],
}

define_typed_per_proof_lookup_bus!(PcsBatchAlphaBus, PcsBatchAlphaMessage);
