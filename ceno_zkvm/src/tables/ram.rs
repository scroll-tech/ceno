use ceno_emul::{Addr, CENO_PLATFORM, WORD_SIZE};
use ram_circuit::RamTableCircuit;

use crate::{instructions::riscv::constants::UINT_LIMBS, structs::RAMType};

mod ram_circuit;
mod ram_impl;
pub use ram_circuit::{MemFinalRecord, MemInitRecord, RamTable};

#[derive(Clone)]
pub struct MemTable;

impl RamTable for MemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS; // See `MemoryExpr`.

    fn len() -> usize {
        // TODO figure out better way to define memory entry count
        1 << 10
    }

    fn addr(entry_index: usize) -> Addr {
        CENO_PLATFORM.ram_start() + (entry_index * WORD_SIZE) as Addr
    }
}
pub type MemTableCircuit<E> = RamTableCircuit<E, MemTable>;

#[derive(Clone)]
pub struct RegTable;

impl RamTable for RegTable {
    const RAM_TYPE: RAMType = RAMType::Register;
    const V_LIMBS: usize = UINT_LIMBS; // See `RegisterExpr`.

    fn len() -> usize {
        32 // register size 32
    }

    fn addr(entry_index: usize) -> Addr {
        entry_index as Addr
    }
}

pub type RegTableCircuit<E> = RamTableCircuit<E, RegTable>;
