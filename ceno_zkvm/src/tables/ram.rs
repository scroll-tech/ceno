use ceno_emul::{Addr, VMState, WORD_SIZE};
use ram_circuit::{DynVolatileRamCircuit, NonVolatileRamCircuit, PubIORamCircuit};

use crate::{
    instructions::riscv::constants::UINT_LIMBS,
    structs::{ProgramParams, RAMType},
};

mod ram_circuit;
mod ram_impl;
pub use ram_circuit::{DynVolatileRamTable, MemFinalRecord, MemInitRecord, NonVolatileTable};

#[derive(Clone)]
pub struct MemTable;

impl DynVolatileRamTable for MemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.

    fn offset_addr(params: &ProgramParams) -> Addr {
        params.platform.ram_start()
    }

    fn end_addr(params: &ProgramParams) -> Addr {
        params.platform.ram_end()
    }

    fn name() -> &'static str {
        "MemTable"
    }

    fn max_len(params: &ProgramParams) -> usize {
        let max_size =
            (Self::end_addr(params) - Self::offset_addr(params)).div_ceil(WORD_SIZE as u32) as Addr;
        1 << (u32::BITS - 1 - max_size.leading_zeros()) // prev_power_of_2
    }
}

pub type MemCircuit<E> = DynVolatileRamCircuit<E, MemTable>;

/// RegTable, fix size without offset
#[derive(Clone)]
pub struct RegTable;

impl NonVolatileTable for RegTable {
    const RAM_TYPE: RAMType = RAMType::Register;
    const V_LIMBS: usize = UINT_LIMBS; // See `RegisterExpr`.
    const WRITABLE: bool = true;

    fn name() -> &'static str {
        "RegTable"
    }

    fn len(_params: &ProgramParams) -> usize {
        VMState::REG_COUNT.next_power_of_two()
    }
}

pub type RegTableCircuit<E> = NonVolatileRamCircuit<E, RegTable>;

#[derive(Clone)]
pub struct StaticMemTable;

impl NonVolatileTable for StaticMemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const WRITABLE: bool = true;

    fn len(params: &ProgramParams) -> usize {
        params.static_memory_len
    }

    fn name() -> &'static str {
        "StaticMemTable"
    }
}

pub type StaticMemCircuit<E> = NonVolatileRamCircuit<E, StaticMemTable>;

#[derive(Clone)]
pub struct PubIOTable;

impl NonVolatileTable for PubIOTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const WRITABLE: bool = false;

    fn len(params: &ProgramParams) -> usize {
        params.pub_io_len
    }

    fn name() -> &'static str {
        "PubIOTable"
    }
}

pub type PubIOCircuit<E> = PubIORamCircuit<E, PubIOTable>;
