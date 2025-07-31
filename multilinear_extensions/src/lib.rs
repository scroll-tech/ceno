#![deny(clippy::cargo)]
#![feature(decl_macro)]
#![feature(strict_overflow_ops)]
mod expression;
pub use expression::{utils::monomialize_expr_to_wit_terms, *};
pub mod macros;
pub mod mle;
pub mod smart_slice;
pub mod util;
pub mod virtual_poly;
pub mod virtual_polys;

#[cfg(test)]
mod test;
