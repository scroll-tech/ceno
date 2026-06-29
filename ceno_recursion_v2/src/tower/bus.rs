use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::define_typed_per_proof_permutation_bus;

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerXiSamplerMessage<T> {
    pub chip_id: T,
    pub tidx: T,
}

define_typed_per_proof_permutation_bus!(TowerXiSamplerBus, TowerXiSamplerMessage);

/// Message sent from TowerInputAir to TowerLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLayerInputMessage<T> {
    pub chip_id: T,
    pub tidx: T,
    pub num_layers: T,
    pub num_read_specs: T,
    pub num_write_specs: T,
    pub num_logup_specs: T,
    pub initial_tower_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLayerInputBus, TowerLayerInputMessage);

/// Message sent from TowerInputAir to TowerLayerAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLayerOutputMessage<T> {
    pub chip_id: T,
    pub tidx: T,
    pub layer_idx_end: T,
    pub input_layer_claim: [T; D_EF],
    pub lambda_next: [T; D_EF],
    pub mu: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLayerOutputBus, TowerLayerOutputMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerProdLayerInputMessage<T> {
    pub chip_id: T,
    pub layer_idx: T,
    pub tidx: T,
    pub lambda_next: [T; D_EF],
    pub lambda_cur: [T; D_EF],
    pub mu: [T; D_EF],
    pub prod_offset: T,
    pub lambda_next_start: [T; D_EF],
    pub lambda_cur_start: [T; D_EF],
    pub num_prod_count: T,
}

define_typed_per_proof_permutation_bus!(TowerProdReadClaimInputBus, TowerProdLayerInputMessage);
define_typed_per_proof_permutation_bus!(TowerProdWriteClaimInputBus, TowerProdLayerInputMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerProdSumClaimMessage<T> {
    pub chip_id: T,
    pub layer_idx: T,
    pub lambda_next_claim: [T; D_EF],
    pub lambda_cur_claim: [T; D_EF],
    pub lambda_next_end: [T; D_EF],
    pub lambda_cur_end: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerProdReadClaimBus, TowerProdSumClaimMessage);
define_typed_per_proof_permutation_bus!(TowerProdWriteClaimBus, TowerProdSumClaimMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLogupLayerChallengeMessage<T> {
    pub chip_id: T,
    pub layer_idx: T,
    pub tidx: T,
    pub lambda_next: [T; D_EF],
    pub lambda_cur: [T; D_EF],
    pub mu: [T; D_EF],
    pub lambda_next_start: [T; D_EF],
    pub lambda_cur_start: [T; D_EF],
    pub num_logup_count: T,
}

define_typed_per_proof_permutation_bus!(TowerLogupClaimInputBus, TowerLogupLayerChallengeMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLogupClaimMessage<T> {
    pub chip_id: T,
    pub layer_idx: T,
    pub lambda_next_claim: [T; D_EF],
    pub lambda_cur_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLogupClaimBus, TowerLogupClaimMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerProdRootInputMessage<T> {
    pub chip_id: T,
    pub tidx: T,
    pub lambda_1: [T; D_EF],
    pub r_1: [T; D_EF],
    pub lambda_1_start: [T; D_EF],
    pub num_prod_count: T,
}

define_typed_per_proof_permutation_bus!(TowerReadRootInputBus, TowerProdRootInputMessage);
define_typed_per_proof_permutation_bus!(TowerWriteRootInputBus, TowerProdRootInputMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerProdRootMessage<T> {
    pub chip_id: T,
    pub output_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerReadRootBus, TowerProdRootMessage);
define_typed_per_proof_permutation_bus!(TowerWriteRootBus, TowerProdRootMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerProdInitMessage<T> {
    pub chip_id: T,
    pub initial_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerReadInitBus, TowerProdInitMessage);
define_typed_per_proof_permutation_bus!(TowerWriteInitBus, TowerProdInitMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLogupRootInputMessage<T> {
    pub chip_id: T,
    pub tidx: T,
    pub lambda_1: [T; D_EF],
    pub r_1: [T; D_EF],
    pub lambda_1_start: [T; D_EF],
    pub num_logup_count: T,
}

define_typed_per_proof_permutation_bus!(TowerLogupRootInputBus, TowerLogupRootInputMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLogupRootMessage<T> {
    pub chip_id: T,
    pub p0_claim: [T; D_EF],
    pub q0_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLogupRootBus, TowerLogupRootMessage);

#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerLogupInitMessage<T> {
    pub chip_id: T,
    pub initial_claim: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerLogupInitBus, TowerLogupInitMessage);

/// Message sent from TowerLayerAir to TowerLayerSumcheckAir
#[repr(C)]
#[derive(AlignedBorrow, Debug, Clone)]
pub struct TowerSumcheckInputMessage<T> {
    /// Module index within the proof
    pub chip_id: T,
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
    pub chip_id: T,
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
    pub chip_id: T,
    /// GKR layer index
    pub layer_idx: T,
    /// Sumcheck round number
    pub sumcheck_round: T,
    /// The challenge value
    pub challenge: [T; D_EF],
}

define_typed_per_proof_permutation_bus!(TowerSumcheckChallengeBus, TowerSumcheckChallengeMessage);
