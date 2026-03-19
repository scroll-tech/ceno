use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::define_typed_per_proof_permutation_bus;

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerXiSamplerMessage<T> {
    pub idx: T,
    pub tidx: T,
}

define_typed_per_proof_permutation_bus!(TowerXiSamplerBus, TowerXiSamplerMessage);

/// Message sent from TowerInputAir to TowerLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLayerInputMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    pub q0_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLayerInputBus, TowerLayerInputMessage);

/// Message sent from TowerInputAir to TowerLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLayerOutputMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub layer_idx_end: T,
    pub input_layer_claim: [T; D_EF],
    pub lambda: [T; D_EF],
    pub mu: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLayerOutputBus, TowerLayerOutputMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerProdLayerChallengeMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub tidx: T,
    pub lambda: [T; D_EF],
    pub lambda_prime: [T; D_EF],
    pub mu: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerProdReadClaimInputBus, TowerProdLayerChallengeMessage);
define_typed_per_proof_permutation_bus!(
    TowerProdWriteClaimInputBus,
    TowerProdLayerChallengeMessage
);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerProdSumClaimMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub lambda_claim: [T; D_EF],
    pub lambda_prime_claim: [T; D_EF],
    pub num_prod_count: T,
}

define_typed_per_proof_permutation_bus!(TowerProdReadClaimBus, TowerProdSumClaimMessage);
define_typed_per_proof_permutation_bus!(TowerProdWriteClaimBus, TowerProdSumClaimMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLogupLayerChallengeMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub tidx: T,
    pub lambda: [T; D_EF],
    pub lambda_prime: [T; D_EF],
    pub mu: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLogupClaimInputBus, TowerLogupLayerChallengeMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLogupClaimMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub lambda_claim: [T; D_EF],
    pub lambda_prime_claim: [T; D_EF],
    pub num_logup_count: T,
}

define_typed_per_proof_permutation_bus!(TowerLogupClaimBus, TowerLogupClaimMessage);

/// Message sent from TowerLayerAir to TowerLayerSumcheckAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerSumcheckInputMessage<T> {
    /// Module index within the proof
    pub idx: T,
    /// GKR layer index
    pub layer_idx: T,
    pub is_last_layer: T,
    /// Transcript index for sumcheck
    pub tidx: T,
    /// Combined claim to verify
    pub claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerSumcheckInputBus, TowerSumcheckInputMessage);

/// Message sent from TowerLayerSumcheckAir to TowerLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerSumcheckOutputMessage<T> {
    /// Module index within the proof
    pub idx: T,
    /// GKR layer index
    pub layer_idx: T,
    /// Transcript index after sumcheck
    pub tidx: T,
    /// New claim after sumcheck
    pub claim_out: [T; D_EF],
    /// Equality polynomial evaluation at r'
    pub eq_at_r_prime: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerSumcheckOutputBus, TowerSumcheckOutputMessage);

/// Message for passing challenges between consecutive sumcheck sub-rounds
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerSumcheckChallengeMessage<T> {
    /// Module index within the proof
    pub idx: T,
    /// GKR layer index
    pub layer_idx: T,
    /// Sumcheck round number
    pub sumcheck_round: T,
    /// The challenge value
    pub challenge: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage);
