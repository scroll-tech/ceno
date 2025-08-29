//! Definition of the range tables and their circuits.

mod range_impl;

mod range_circuit;
pub use range_circuit::{DynamicRangeTableCircuit, RangeTable, RangeTableCircuit};
