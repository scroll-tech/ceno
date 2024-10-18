use ram_circuit::{RamTable, RamTableCircuit};

use crate::{instructions::riscv::constants::UINT_LIMBS, structs::RAMType};

mod ram_circuit;
mod ram_impl;

pub struct MemTable;

impl MemTable {
    const U32_MEM_ADDR: usize = (u32::BITS / 8).trailing_zeros() as usize;
}

impl RamTable for MemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS + 1; // +1 including timestamp
    fn len() -> usize {
        // TODO figure out better way to define memory entry count
        1 << 21
    }

    #[inline(always)]
    fn addr(entry_index: usize) -> u32 {
        (entry_index as u32) << Self::U32_MEM_ADDR
    }
}
pub type MemTableCircuit<E> = RamTableCircuit<E, MemTable>;

#[derive(Clone)]
pub struct RegTable;

impl RamTable for RegTable {
    const RAM_TYPE: RAMType = RAMType::Register;
    const V_LIMBS: usize = UINT_LIMBS + 1; // +1 including timestamp
    fn len() -> usize {
        32 // register size 32
    }
}

pub type RegTableCircuit<E> = RamTableCircuit<E, RegTable>;
