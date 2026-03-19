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
