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

pub struct OrTable;
impl OpsTable for OrTable {
    const ROM_TYPE: ROMType = ROMType::Or;
    fn len() -> usize {
        1 << 16
    }

    fn content() -> Vec<[u64; 3]> {
        (0..Self::len() as u64)
            .map(|i| {
                let (a, b) = Self::unpack(i);
                [a, b, a | b]
            })
            .collect()
    }
}
pub type OrTableCircuit<E> = OpsTableCircuit<E, OrTable>;

pub struct XorTable;
impl OpsTable for XorTable {
    const ROM_TYPE: ROMType = ROMType::Xor;
    fn len() -> usize {
        1 << 16
    }

    fn content() -> Vec<[u64; 3]> {
        (0..Self::len() as u64)
            .map(|i| {
                let (a, b) = Self::unpack(i);
                [a, b, a ^ b]
            })
            .collect()
    }
}
pub type XorTableCircuit<E> = OpsTableCircuit<E, XorTable>;

pub struct LtuTable;
impl OpsTable for LtuTable {
    const ROM_TYPE: ROMType = ROMType::Ltu;
    fn len() -> usize {
        1 << 16
    }

    fn content() -> Vec<[u64; 3]> {
        (0..Self::len() as u64)
            .map(|i| {
                let (a, b) = Self::unpack(i);
                [a, b, if a < b { 1 } else { 0 }]
            })
            .collect()
    }
}
pub type LtuTableCircuit<E> = OpsTableCircuit<E, LtuTable>;

pub struct PowTable;
impl OpsTable for PowTable {
    const ROM_TYPE: ROMType = ROMType::Pow;
    fn len() -> usize {
        1 << 5
    }

    fn content() -> Vec<[u64; 3]> {
        (0..Self::len() as u64).map(|b| [2, b, 1 << b]).collect()
    }
}
pub type PowTableCircuit<E> = OpsTableCircuit<E, PowTable>;
