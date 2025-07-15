#![deny(clippy::cargo)]
#![feature(decl_macro)]
#![feature(strict_overflow_ops)]
pub mod expression;
pub use expression::*;
pub mod macros;
pub mod mle;
pub mod smart_slice;
pub mod util;
pub mod virtual_poly;
pub mod virtual_polys;

#[cfg(test)]
mod test;
