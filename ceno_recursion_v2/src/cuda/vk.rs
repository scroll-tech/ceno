use ceno_zkvm::structs::VK_DIGEST_LEN;

use crate::system::{RecursionField, RecursionVk, child_vk_digest};

pub struct VerifyingKeyGpu {
    pub digest: [RecursionField; VK_DIGEST_LEN],
}

impl VerifyingKeyGpu {
    pub fn new(vk: &RecursionVk) -> Self {
        Self {
            digest: child_vk_digest(vk),
        }
    }
}
