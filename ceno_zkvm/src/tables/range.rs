//! Definition of the range tables and their circuits.

mod range_impl;

mod range_circuit;
pub use range_circuit::{
    DoubleRangeTableCircuit, DynamicRangeTableCircuit, RangeTable, RangeTableCircuit,
};

use crate::ROMType;

pub struct DoubleU8Table;
impl RangeTable for DoubleU8Table {
    const ROM_TYPE: ROMType = ROMType::DoubleU8;

    fn len() -> usize {
        1 << 16
    }
}
pub type DoubleU8TableCircuit<E> = DoubleRangeTableCircuit<E, 8, 8, DoubleU8Table>;
