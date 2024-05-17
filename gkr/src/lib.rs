#![feature(associated_const_equality)]

mod circuit;
pub mod error;
pub mod gadgets;
pub mod macros;
mod prover;
pub mod structs;
pub mod utils;
mod verifier;

#[cfg(test)]
mod test;
