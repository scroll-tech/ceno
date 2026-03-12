use std::sync::Arc;

use ceno_zkvm::{scheme::ZKVMProof, structs::ZKVMVerifyingKey};
use ff_ext::BabyBearExt4;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_stark_backend::{
    keygen::types::MultiStarkVerifyingKey,
    proof::Proof,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;

pub type RecursionField = BabyBearExt4;
pub type RecursionPcs = Basefold<RecursionField, BasefoldRSParams>;
pub type RecursionVk = ZKVMVerifyingKey<RecursionField, RecursionPcs>;
pub type RecursionProof = ZKVMProof<RecursionField, RecursionPcs>;

pub fn convert_proof_from_zkvm(
    _proof: &RecursionProof,
) -> Proof<BabyBearPoseidon2Config> {
    unimplemented!("Bridge ZKVMProof -> Proof<BabyBearPoseidon2Config> conversion");
}

pub fn convert_vk_from_zkvm(
    _vk: &RecursionVk,
) -> Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>> {
    unimplemented!("Bridge ZKVMVerifyingKey -> MultiStarkVerifyingKey conversion");
}
