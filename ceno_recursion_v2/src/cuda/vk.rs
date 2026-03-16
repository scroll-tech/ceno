use openvm_cuda_common::d_buffer::DeviceBuffer;
use openvm_stark_backend::{
    SystemParams, WhirProximityStrategy, interaction::LogUpSecurityParameters,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{DIGEST_SIZE, Digest, F};

use crate::system::RecursionVk;

use super::types::AirData;

pub struct VerifyingKeyGpu {
    pub cpu: RecursionVk,
    pub per_air: DeviceBuffer<AirData>,
    pub system_params: SystemParams,
    pub pre_hash: [F; DIGEST_SIZE],
}

impl VerifyingKeyGpu {
    pub fn new(vk: &RecursionVk) -> Self {
        Self {
            cpu: vk.clone(),
            per_air: DeviceBuffer::new(),
            system_params: placeholder_system_params(),
            pre_hash: Digest::default(),
        }
    }
}

fn placeholder_system_params() -> SystemParams {
    SystemParams::new(
        1, // log_blowup
        1, // l_skip
        1, // n_stack
        1, // w_stack
        1, // log_final_poly_len
        1, // folding_pow_bits
        1, // mu_pow_bits
        WhirProximityStrategy::UniqueDecoding,
        80, // security bits
        LogUpSecurityParameters {
            max_interaction_count: 1,
            log_max_message_length: 1,
            pow_bits: 0,
        },
    )
}
