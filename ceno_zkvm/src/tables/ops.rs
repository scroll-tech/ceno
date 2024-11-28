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
        (0..Self::len() as u64)
            .map(|exponent| [2, exponent, 1 << exponent])
            .collect()
    }

    fn pack(base: u64, exponent: u64) -> u64 {
        assert_eq!(base, 2);
        exponent
    }

    fn unpack(exponent: u64) -> (u64, u64) {
        (2, exponent)
    }
}
pub type PowTableCircuit<E> = OpsTableCircuit<E, PowTable>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        tables::TableCircuit,
    };
    use goldilocks::{GoldilocksExt2 as E, SmallField};

    #[test]
    fn test_ops_pow_table_assign() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let config = PowTableCircuit::<E>::construct_circuit(&mut cb).unwrap();

        let fixed = PowTableCircuit::<E>::generate_fixed_traces(&config, cb.cs.num_fixed, &());

        for (i, row) in fixed.iter_rows().enumerate() {
            let (base, exp) = PowTable::unpack(i as u64);
            assert_eq!(PowTable::pack(base, exp), i as u64);
            assert_eq!(base, unsafe { row[0].assume_init() }.to_canonical_u64());
            assert_eq!(exp, unsafe { row[1].assume_init() }.to_canonical_u64());
            assert_eq!(
                base.pow(exp.try_into().unwrap()),
                unsafe { row[2].assume_init() }.to_canonical_u64()
            );
        }
    }
}
