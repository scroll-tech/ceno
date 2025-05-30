#![deny(clippy::cargo)]
pub use multilinear_extensions::macros;
pub mod extrapolate;
mod prover;
pub mod structs;
pub mod util;
mod verifier;

#[cfg(test)]
mod test;
