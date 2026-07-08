use ceno_zkvm::structs::VK_DIGEST_LEN;

use crate::system::{RecursionField, RecursionVk, child_vk_digest};

pub struct VerifyingKeyGpu {
    pub cpu: RecursionVk,
    pub digest: [RecursionField; VK_DIGEST_LEN],
}

impl VerifyingKeyGpu {
    pub fn new(vk: &RecursionVk) -> Self {
        Self {
            cpu: vk.clone(),
            digest: child_vk_digest(vk),
        }
    }
}
