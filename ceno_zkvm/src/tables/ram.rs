use ram_circuit::{RamTable, RamTableCircuit};

use crate::{instructions::riscv::constants::UINT_LIMBS, structs::RAMType};

mod ram_circuit;
mod ram_impl;

pub struct MemTable;

impl RamTable for MemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS + 1; // +1 including timestamp
    fn len() -> usize {
        // TODO figure out better way to define memory size
        1 << 16
    }

    fn init_state() -> Vec<u32> {
        vec![0; Self::len()]
    }
}
pub type MemTableCircuit<E> = RamTableCircuit<E, MemTable>;

pub struct RegTable;

impl RamTable for RegTable {
    const RAM_TYPE: RAMType = RAMType::Register;
    const V_LIMBS: usize = UINT_LIMBS + 1; // +1 including timestamp
    fn len() -> usize {
        32 // register size 32
    }

    fn init_state() -> Vec<u32> {
        // hardcode special initial value for register
        vec![0; Self::len()]
    }
}

pub type RegTableCircuit<E> = RamTableCircuit<E, RegTable>;
