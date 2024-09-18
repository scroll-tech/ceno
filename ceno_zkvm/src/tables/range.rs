//! Definition of the range tables and their circuits.

mod range_impl;

mod range_circuit;
use range_circuit::{RangeTable, RangeTableCircuit};

use crate::structs::ROMType;

pub struct U5Table;
impl RangeTable for U5Table {
    const ROM_TYPE: ROMType = ROMType::U5;
    fn len() -> usize {
        1 << 5
    }
}
pub type U5TableCircuit<E> = RangeTableCircuit<E, U5Table>;

pub struct U8Table;
impl RangeTable for U8Table {
    const ROM_TYPE: ROMType = ROMType::U8;
    fn len() -> usize {
        1 << 8
    }
}
pub type U8TableCircuit<E> = RangeTableCircuit<E, U8Table>;

pub struct U16Table;
impl RangeTable for U16Table {
    const ROM_TYPE: ROMType = ROMType::U16;
    fn len() -> usize {
        1 << 16
    }
}
pub type U16TableCircuit<E> = RangeTableCircuit<E, U16Table>;
