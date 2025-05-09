#![deny(clippy::cargo)]
#![feature(decl_macro)]
#![feature(strict_overflow_ops)]
mod expression;
pub use expression::*;
pub mod macros;
pub mod mle;
pub mod util;
pub mod virtual_poly;
pub mod virtual_polys;

#[cfg(test)]
mod test;
