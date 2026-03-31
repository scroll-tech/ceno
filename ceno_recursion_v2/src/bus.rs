use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use recursion_circuit::{bus as upstream, define_typed_per_proof_permutation_bus};
pub use upstream::{
    AirPresenceBus, AirPresenceBusMessage, AirShapeBus, AirShapeBusMessage, CachedCommitBus,
    CachedCommitBusMessage, ColumnClaimsBus, ColumnClaimsMessage, CommitmentsBus,
    CommitmentsBusMessage, ExpressionClaimNMaxBus, ExpressionClaimNMaxMessage,
    FractionFolderInputBus, FractionFolderInputMessage, HyperdimBus, HyperdimBusMessage,
    LiftedHeightsBus, LiftedHeightsBusMessage, NLiftBus, NLiftMessage, PublicValuesBus,
    PublicValuesBusMessage, SelHypercubeBus, SelHypercubeBusMessage, SelUniBus, SelUniBusMessage,
    TranscriptBus, TranscriptBusMessage,
};

// ── Forked transcript bus ─────────────────────────────────────────────────────
// Carries per-chip fork transcript operations, addressed by (air_id, fork_tidx)
// instead of the absolute tidx used by the trunk TranscriptBus.

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct ForkedTranscriptBusMessage<T> {
    /// Child proof's AIR index for this fork.
    pub air_id: T,
    /// Fork-local transcript position (starts at 0 for each fork).
    pub fork_tidx: T,
    /// Observed or sampled field element.
    pub value: T,
    /// 1 if this is a sample operation, 0 if observe.
    pub is_sample: T,
}

define_typed_per_proof_permutation_bus!(ForkedTranscriptBus, ForkedTranscriptBusMessage);

// ── Fork state sidechain bus ──────────────────────────────────────────────────
// Carries the full Poseidon2 sponge state from the trunk's fork point to
// each forked transcript chain, so the fork can start from the correct state.

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct ForkStateBusMessage<T> {
    pub fork_id: T,
    pub state: [T; POSEIDON2_WIDTH],
}

define_typed_per_proof_permutation_bus!(ForkStateBus, ForkStateBusMessage);

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
