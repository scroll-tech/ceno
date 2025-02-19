#![deny(clippy::cargo)]
extern crate core;

pub(crate) mod constants;
pub(crate) mod plonky2_goldilock_mds;
pub use constants::SPONGE_WIDTH;
#[cfg(test)]
pub use plonky2_goldilock_mds::P2MdsMatrixGoldilocks;
pub mod challenger;
pub mod digest;
pub mod poseidon;
pub mod poseidon_hash;
// pub mod poseidon_permutation;
