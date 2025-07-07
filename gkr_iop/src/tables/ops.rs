use crate::tables::{LookupTable, OpsTable};

pub struct AndTable;
impl OpsTable for AndTable {
    const ROM_TYPE: LookupTable = LookupTable::And;
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

pub struct OrTable;
impl OpsTable for OrTable {
    const ROM_TYPE: LookupTable = LookupTable::Or;
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

pub struct XorTable;
impl OpsTable for XorTable {
    const ROM_TYPE: LookupTable = LookupTable::Xor;
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

pub struct LtuTable;
impl OpsTable for LtuTable {
    const ROM_TYPE: LookupTable = LookupTable::Ltu;
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
pub struct PowTable;
impl OpsTable for PowTable {
    const ROM_TYPE: LookupTable = LookupTable::Pow;
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
