#![deny(clippy::cargo)]
#![feature(decl_macro)]
#![feature(generic_const_exprs)]
pub mod macros;
mod prover;
pub mod structs;
pub mod util;
mod verifier;

#[cfg(test)]
mod test;
