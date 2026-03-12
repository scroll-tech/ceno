use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::define_typed_per_proof_permutation_bus;

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrXiSamplerMessage<T> {
    pub idx: T,
    pub tidx: T,
}

define_typed_per_proof_permutation_bus!(GkrXiSamplerBus, GkrXiSamplerMessage);

/// Message sent from GkrInputAir to GkrLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrLayerInputMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub r0_claim: [T; D_EF],
    pub w0_claim: [T; D_EF],
    pub q0_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(GkrLayerInputBus, GkrLayerInputMessage);

/// Message sent from GkrInputAir to GkrLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrLayerOutputMessage<T> {
    pub idx: T,
    pub tidx: T,
    pub layer_idx_end: T,
    pub input_layer_claim: [T; D_EF],
    pub lambda: [T; D_EF],
    pub mu: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(GkrLayerOutputBus, GkrLayerOutputMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrProdLayerChallengeMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub tidx: T,
    pub lambda: [T; D_EF],
    pub lambda_prime: [T; D_EF],
    pub mu: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(GkrProdReadClaimInputBus, GkrProdLayerChallengeMessage);
define_typed_per_proof_permutation_bus!(GkrProdWriteClaimInputBus, GkrProdLayerChallengeMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrProdSumClaimMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub lambda_claim: [T; D_EF],
    pub lambda_prime_claim: [T; D_EF],
    pub num_prod_count: T,
}

define_typed_per_proof_permutation_bus!(GkrProdReadClaimBus, GkrProdSumClaimMessage);
define_typed_per_proof_permutation_bus!(GkrProdWriteClaimBus, GkrProdSumClaimMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrLogupLayerChallengeMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub tidx: T,
    pub lambda: [T; D_EF],
    pub lambda_prime: [T; D_EF],
    pub mu: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(GkrLogupClaimInputBus, GkrLogupLayerChallengeMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrLogupClaimMessage<T> {
    pub idx: T,
    pub layer_idx: T,
    pub lambda_claim: [T; D_EF],
    pub lambda_prime_claim: [T; D_EF],
    pub num_logup_count: T,
}

define_typed_per_proof_permutation_bus!(GkrLogupClaimBus, GkrLogupClaimMessage);

/// Message sent from GkrLayerAir to GkrLayerSumcheckAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrSumcheckInputMessage<T> {
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

define_typed_per_proof_permutation_bus!(GkrSumcheckInputBus, GkrSumcheckInputMessage);

/// Message sent from GkrLayerSumcheckAir to GkrLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrSumcheckOutputMessage<T> {
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

define_typed_per_proof_permutation_bus!(GkrSumcheckOutputBus, GkrSumcheckOutputMessage);

/// Message for passing challenges between consecutive sumcheck sub-rounds
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct GkrSumcheckChallengeMessage<T> {
    /// Module index within the proof
    pub idx: T,
    /// GKR layer index
    pub layer_idx: T,
    /// Sumcheck round number
    pub sumcheck_round: T,
    /// The challenge value
    pub challenge: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(GkrSumcheckChallengeBus, GkrSumcheckChallengeMessage);
