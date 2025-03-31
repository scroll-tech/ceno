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
pub struct HeapTable;

impl DynVolatileRamTable for HeapTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const ZERO_INIT: bool = true;
    const DESCENDING: bool = false;

    fn offset_addr(params: &ProgramParams) -> Addr {
        params.platform.heap.start
    }

    fn end_addr(params: &ProgramParams) -> Addr {
        params.platform.heap.end
    }

    fn name() -> &'static str {
        "HeapTable"
    }
}

pub type HeapCircuit<E> = DynVolatileRamCircuit<E, HeapTable>;

#[derive(Clone)]
pub struct StackTable;

impl DynVolatileRamTable for StackTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const ZERO_INIT: bool = true;
    const DESCENDING: bool = true;

    fn offset_addr(params: &ProgramParams) -> Addr {
        // stack address goes in descending order
        // end address is exclusive
        params.platform.stack.end - WORD_SIZE as u32
    }

    fn end_addr(params: &ProgramParams) -> Addr {
        // stack address goes in descending order
        params.platform.stack.start
    }

    fn max_len(params: &ProgramParams) -> usize {
        let max_size = (Self::offset_addr(params) - Self::end_addr(params))
            .div_ceil(WORD_SIZE as u32) as Addr
            + 1;
        println!("stack max size {}", max_size);
        1 << (u32::BITS - 1 - max_size.leading_zeros()) // prev_power_of_2
    }

    fn name() -> &'static str {
        "StackTable"
    }
}

pub type StackCircuit<E> = DynVolatileRamCircuit<E, StackTable>;

#[derive(Clone)]
pub struct HintsTable;
impl DynVolatileRamTable for HintsTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = 1; // See `MemoryExpr`.
    const ZERO_INIT: bool = false;
    const DESCENDING: bool = false;

    fn offset_addr(params: &ProgramParams) -> Addr {
        params.platform.hints.start
    }

    fn end_addr(params: &ProgramParams) -> Addr {
        params.platform.hints.end
    }

    fn name() -> &'static str {
        "HintsTable"
    }
}
pub type HintsCircuit<E> = DynVolatileRamCircuit<E, HintsTable>;

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
        params.pubio_len
    }

    fn name() -> &'static str {
        "PubIOTable"
    }
}

pub type PubIOCircuit<E> = PubIORamCircuit<E, PubIOTable>;
