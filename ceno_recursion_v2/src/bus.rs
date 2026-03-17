use recursion_circuit::{bus as upstream, define_typed_per_proof_permutation_bus};
pub use upstream::{
    AirPresenceBus, AirPresenceBusMessage, AirShapeBus, AirShapeBusMessage,
    BatchConstraintModuleBus, CachedCommitBus, CachedCommitBusMessage, CommitmentsBus,
    CommitmentsBusMessage, ExpressionClaimNMaxBus, ExpressionClaimNMaxMessage,
    FractionFolderInputBus, FractionFolderInputMessage, HyperdimBus, HyperdimBusMessage,
    LiftedHeightsBus, LiftedHeightsBusMessage, NLiftBus, NLiftMessage, PublicValuesBus,
    PublicValuesBusMessage, TranscriptBus, TranscriptBusMessage,
};

#[repr(C)]
#[derive(stark_recursion_circuit_derive::AlignedBorrow, Debug, Clone, Copy)]
pub struct GkrModuleMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub n_logup: T,
}

define_typed_per_proof_permutation_bus!(GkrModuleBus, GkrModuleMessage);
