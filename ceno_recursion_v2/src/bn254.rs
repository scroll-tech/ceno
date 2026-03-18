use openvm_stark_sdk::config::baby_bear_poseidon2::{DIGEST_SIZE, F};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

pub const BN254_BYTES: usize = 32;

/// Minimal byte wrapper for commit values used by the forked inner circuit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommitBytes([u8; BN254_BYTES]);

impl CommitBytes {
    pub fn new(bytes: [u8; BN254_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8; BN254_BYTES] {
        &self.0
    }

    pub fn reverse(&mut self) {
        self.0.reverse();
    }
}

impl From<[F; DIGEST_SIZE]> for CommitBytes {
    fn from(value: [F; DIGEST_SIZE]) -> Self {
        Self::from(value.map(|x| x.as_canonical_u32()))
    }
}

impl From<[u32; DIGEST_SIZE]> for CommitBytes {
    fn from(value: [u32; DIGEST_SIZE]) -> Self {
        let mut bytes = [0u8; BN254_BYTES];
        for (idx, limb) in value.iter().enumerate() {
            let start = idx * 4;
            bytes[start..start + 4].copy_from_slice(&limb.to_le_bytes());
        }
        Self(bytes)
    }
}

impl From<CommitBytes> for [u32; DIGEST_SIZE] {
    fn from(value: CommitBytes) -> Self {
        core::array::from_fn(|idx| {
            let start = idx * 4;
            u32::from_le_bytes([
                value.0[start],
                value.0[start + 1],
                value.0[start + 2],
                value.0[start + 3],
            ])
        })
    }
}

