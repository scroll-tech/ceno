//! Definition of the ops tables and their circuits.

mod ops_impl;

mod ops_circuit;
use ops_circuit::{OpsTable, OpsTableCircuit};

use crate::structs::ROMType;

pub struct AndTable;
impl OpsTable for AndTable {
    const ROM_TYPE: ROMType = ROMType::And;
    fn len() -> usize {
        1 << 16
    }

    fn content() -> Vec<u64> {
        // TODO
        (0..Self::len()).map(|i| i as u64).collect()
    }
}
pub type AndTableCircuit<E> = OpsTableCircuit<E, AndTable>;
