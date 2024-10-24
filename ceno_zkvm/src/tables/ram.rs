use ceno_emul::{Addr, CENO_PLATFORM, WORD_SIZE, Word};
use ram_circuit::{DynVolatileRamCircuit, NonVolatileRamCircuit, NonVolatileRamTable};

use crate::{instructions::riscv::constants::UINT_LIMBS, structs::RAMType};

mod ram_circuit;
mod ram_impl;
use ram_circuit::DynVolatileRamTable;
pub use ram_circuit::{MemFinalRecord, MemInitRecord};

/// offset: RAM_START, addr dynamic size, max_addr = RAM_END, all initial value 0
#[derive(Clone)]
pub struct MemTable;

impl DynVolatileRamTable for MemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS; // See `MemoryExpr`.

    fn addr(entry_index: usize) -> Addr {
        Self::offset() + (entry_index * WORD_SIZE) as Addr
    }

    fn max_len() -> usize {
        // +1 for start is inclusive
        (CENO_PLATFORM.ram_end() - CENO_PLATFORM.ram_start() + 1) as usize / WORD_SIZE
    }

    fn offset() -> Addr {
        CENO_PLATFORM.ram_start()
    }
}

pub type MemCircuit<E> = DynVolatileRamCircuit<E, MemTable>;

/// RegTable, fix size without offset
#[derive(Clone)]
pub struct RegTable;

impl NonVolatileRamTable for RegTable {
    const RAM_TYPE: RAMType = RAMType::Register;
    const V_LIMBS: usize = UINT_LIMBS; // See `RegisterExpr`.

    fn len() -> usize {
        32 // register size 32
    }

    fn addr(entry_index: usize) -> Addr {
        entry_index as Addr
    }

    fn offset() -> Addr {
        0
    }
}

pub type RegTableCircuit<E> = NonVolatileRamCircuit<E, RegTable>;

/// offset: DATA_START, addr dynamic size, max_addr = DATA_END with initial value
#[derive(Clone)]
pub struct ProgramDataTable;

impl NonVolatileRamTable for ProgramDataTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS; // See `MemoryExpr`.

    fn addr(entry_index: usize) -> Addr {
        Self::offset() + (entry_index * WORD_SIZE) as Addr
    }

    fn len() -> usize {
        todo!()
    }

    fn offset() -> Addr {
        CENO_PLATFORM.program_data_start()
    }
}

pub type ProgramDataCircuit<E> = NonVolatileRamCircuit<E, ProgramDataTable>;

pub fn initial_registers() -> Vec<MemInitRecord> {
    RegTable::init_state()
}

pub fn init_program_data(ram_content: &[Word]) -> Vec<MemInitRecord> {
    let mut mem_init = ProgramDataTable::init_state();
    for (i, value) in ram_content.iter().enumerate() {
        mem_init[i].value = *value;
    }
    mem_init
}
