#![deny(clippy::cargo)]
#![feature(box_patterns)]
#![feature(stmt_expr_attributes)]
#![feature(variant_count)]
#![feature(strict_overflow_ops)]

pub mod error;
pub mod instructions;
pub mod scheme;
pub mod tables;
pub use utils::u64vec;
mod chip_handler;
pub mod circuit_builder;
pub mod e2e;
pub mod expression;
pub mod gadgets;
mod keygen;
pub mod state;
pub mod stats;
pub mod structs;
mod uint;
mod utils;
mod virtual_polys;
mod witness;

pub use structs::ROMType;
pub use uint::Value;
pub use utils::with_panic_hook;
