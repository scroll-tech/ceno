#![deny(clippy::cargo)]
#![feature(decl_macro)]
pub mod macros;
mod prover;
mod prover_v2;
pub mod structs;
pub mod util;
mod verifier;

#[cfg(test)]
mod test;
