#![deny(clippy::cargo)]
#![feature(box_patterns)]
#![feature(stmt_expr_attributes)]
#![feature(variant_count)]

pub mod error;
pub mod instructions;
pub mod scheme;
pub mod tables;
pub use utils::u64vec;
mod chip_handler;
pub mod circuit_builder;
pub mod e2e;
pub mod gadgets;
mod keygen;
pub mod precompiles;
pub mod state;
pub mod stats;
pub mod structs;
mod uint;
mod utils;
#[cfg(all(feature = "jemalloc", unix, not(test)))]
pub use utils::print_allocated_bytes;
mod witness;

pub use structs::ROMType;
pub use uint::Value;
pub use utils::with_panic_hook;
