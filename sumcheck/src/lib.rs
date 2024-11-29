#![deny(clippy::cargo)]
#[cfg(feature = "non_pow2_rayon_thread")]
pub mod local_thread_pool;
mod macros;
mod prover;
mod prover_v2;
pub mod structs;
pub mod util;
mod verifier;

#[cfg(test)]
mod test;
