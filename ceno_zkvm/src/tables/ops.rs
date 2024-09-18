//! Definition of the ops tables and their circuits.

mod ops_impl;

mod ops_circuit;
pub use ops_circuit::{OpsTable, OpsTableCircuit};

use crate::structs::ROMType;

pub struct AndTable;
impl OpsTable for AndTable {
    const ROM_TYPE: ROMType = ROMType::And;
    fn len() -> usize {
        1 << 16
    }

    fn content() -> Vec<[u64; 3]> {
        (0..Self::len() as u64)
            .map(|i| {
                let (a, b) = Self::unpack(i);
                [a, b, a & b]
            })
            .collect()
    }
}
pub type AndTableCircuit<E> = OpsTableCircuit<E, AndTable>;
