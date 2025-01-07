#![deny(clippy::cargo)]
extern crate core;

pub(crate) mod constants;
pub use constants::SPONGE_WIDTH;
pub mod digest;
pub mod poseidon;
mod poseidon_goldilocks;
pub mod poseidon_hash;
pub mod poseidon_permutation;
