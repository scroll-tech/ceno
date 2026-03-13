use openvm_cuda_common::d_buffer::DeviceBuffer;
use openvm_stark_backend::SystemParams;
use openvm_stark_sdk::config::baby_bear_poseidon2::{DIGEST_SIZE, F};

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
            system_params: SystemParams::new_for_testing(20),
            pre_hash: [F::ZERO; DIGEST_SIZE],
        }
    }
}
