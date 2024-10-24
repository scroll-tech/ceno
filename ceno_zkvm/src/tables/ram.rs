use ceno_emul::{Addr, CENO_PLATFORM, Word};
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
    const OFFSET_ADDR: Addr = CENO_PLATFORM.ram_start();
    const END_ADDR: Addr = CENO_PLATFORM.ram_end() + 1;

    fn name() -> &'static str {
        "MemTable"
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
    const OFFSET_ADDR: Addr = 0;
    const END_ADDR: Addr = 0;

    fn name() -> &'static str {
        "RegTable"
    }

    fn len() -> usize {
        32 // register size 32
    }
}

pub type RegTableCircuit<E> = NonVolatileRamCircuit<E, RegTable>;

#[derive(Clone)]
pub struct ProgramDataTable;

impl NonVolatileTable for ProgramDataTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const RW: bool = false; // read only
    const OFFSET_ADDR: Addr = CENO_PLATFORM.program_data_start();
    const END_ADDR: Addr = CENO_PLATFORM.program_data_end() + 1;

    fn name() -> &'static str {
        "ProgramDataTable"
    }
}

pub type ProgramDataCircuit<E> = NonVolatileRamCircuit<E, ProgramDataTable>;

#[derive(Clone)]
pub struct PubIOTable;

impl NonVolatileTable for PubIOTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const RW: bool = false; // read only
    const OFFSET_ADDR: Addr = CENO_PLATFORM.public_io_start();
    const END_ADDR: Addr = CENO_PLATFORM.public_io_end() + 1;

    fn name() -> &'static str {
        "PubIOTable"
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
