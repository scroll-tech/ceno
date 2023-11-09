//! This crate implements Goldilocks field with modulus 2^64 - 2^32 + 1
//! Credit: the majority of the code is borrowed or inspired from Plonky2 with modifications.

pub use fp::Goldilocks;

mod fp;
mod util;

#[cfg(test)]
mod tests;
