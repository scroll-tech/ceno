use ff_ext::ExtensionField;
use multilinear_extensions::{Instance, ToExpr};

use crate::{
    chip_handler::{MemoryExpr, general::PublicValuesQuery},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::riscv::constants::UINT_LIMBS,
};

pub const PUBIO_COMMIT_WORDS: usize = 8;
pub const PUBIO_DIGEST_U16_LIMBS: usize = PUBIO_COMMIT_WORDS * UINT_LIMBS;

#[derive(Debug)]
pub struct PubioCommitLayout<E: ExtensionField> {
    /// Public digest instances laid out as 16-bit limbs, little-endian per word.
    pub digest_u16_limbs: [Instance; PUBIO_DIGEST_U16_LIMBS],
    pub digest_words: [MemoryExpr<E>; PUBIO_COMMIT_WORDS],
}

impl<E: ExtensionField> PubioCommitLayout<E> {
    pub fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        let digest_u16_limbs = cb.query_public_io_digest()?;
        let digest_words = core::array::from_fn(|word_idx| {
            let limb_base = word_idx * UINT_LIMBS;
            [
                digest_u16_limbs[limb_base].expr(),
                digest_u16_limbs[limb_base + 1].expr(),
            ]
        });

        Ok(Self {
            digest_u16_limbs,
            digest_words,
        })
    }
}


