use ceno_emul::{Addr, CENO_PLATFORM, VMState, WORD_SIZE, Word};
use ram_circuit::RamTableCircuit;

use crate::{instructions::riscv::constants::UINT_LIMBS, structs::RAMType};

mod ram_circuit;
mod ram_impl;
use ram_circuit::RamTable;
pub use ram_circuit::{MemFinalRecord, MemInitRecord};

#[derive(Clone)]
pub struct MemTable;

impl RamTable for MemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.

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
        VMState::REG_COUNT.next_power_of_two()
    }

    fn addr(entry_index: usize) -> Addr {
        entry_index as Addr
    }
}

pub type RegTableCircuit<E> = RamTableCircuit<E, RegTable>;

pub fn initial_registers() -> Vec<MemInitRecord> {
    RegTable::init_state()
}

pub fn initial_memory(ram_content: &[Word]) -> Vec<MemInitRecord> {
    let mut mem_init = MemTable::init_state();
    for (i, value) in ram_content.iter().enumerate() {
        mem_init[i].value = *value;
    }
    mem_init
}
