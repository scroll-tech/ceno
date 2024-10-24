use ceno_emul::{Addr, CENO_PLATFORM, WORD_SIZE, Word};
use ram_circuit::{DynVolatileRamCircuit, NonVolatileRamCircuit, NonVolatileTable};

use crate::{instructions::riscv::constants::UINT_LIMBS, structs::RAMType};

mod ram_circuit;
mod ram_impl;
pub use ram_circuit::{DynVolatileRamTable, MemFinalRecord, MemInitRecord};

/// offset: RAM_START, addr dynamic size, max_addr = RAM_END, all initial value 0
#[derive(Clone)]
pub struct MemTable;

impl DynVolatileRamTable for MemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.

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

impl NonVolatileTable for RegTable {
    const RAM_TYPE: RAMType = RAMType::Register;
    const V_LIMBS: usize = UINT_LIMBS; // See `RegisterExpr`.
    const RW: bool = true;

    fn name() -> &'static str {
        "RegTable"
    }

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

#[derive(Clone)]
pub struct ProgramDataTable;

impl NonVolatileTable for ProgramDataTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const RW: bool = false; // read only

    fn name() -> &'static str {
        "ProgramDataTable"
    }

    fn addr(entry_index: usize) -> Addr {
        Self::offset() + (entry_index * WORD_SIZE) as Addr
    }

    fn len() -> usize {
        // +1 for start is inclusive
        (CENO_PLATFORM.program_data_end() - CENO_PLATFORM.program_data_start() + 1) as usize
            / WORD_SIZE
    }

    fn offset() -> Addr {
        CENO_PLATFORM.program_data_start()
    }
}

pub type ProgramDataCircuit<E> = NonVolatileRamCircuit<E, ProgramDataTable>;

#[derive(Clone)]
pub struct PubIOTable;

impl NonVolatileTable for PubIOTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const RW: bool = false; // read only

    fn name() -> &'static str {
        "PubIOTable"
    }

    fn addr(entry_index: usize) -> Addr {
        Self::offset() + (entry_index * WORD_SIZE) as Addr
    }

    fn len() -> usize {
        // +1 for start is inclusive
        (CENO_PLATFORM.public_io_end() - CENO_PLATFORM.public_io_start() + 1) as usize / WORD_SIZE
    }

    fn offset() -> Addr {
        CENO_PLATFORM.public_io_start()
    }
}

pub type PubIOCircuit<E> = NonVolatileRamCircuit<E, PubIOTable>;

pub fn initial_registers() -> Vec<MemInitRecord> {
    RegTable::init_state()
}

pub fn init_program_data(program_data_content: &[Word]) -> Vec<MemInitRecord> {
    let mut program_data_init = ProgramDataTable::init_state();
    for (i, value) in program_data_content.iter().enumerate() {
        program_data_init[i].value = *value;
    }
    program_data_init
}
