use ceno_emul::{Addr, VMState, WORD_SIZE};
use ram_circuit::{DynVolatileRamCircuit, NonVolatileRamCircuit, PubIORamCircuit};

use crate::{
    instructions::riscv::constants::UINT_LIMBS,
    structs::{ProgramParams, RAMType},
};

mod ram_circuit;
mod ram_impl;
use crate::tables::ram::{
    ram_circuit::{LocalFinalRamCircuit, RamBusCircuit},
    ram_impl::{
        DynVolatileRamTableConfig, DynVolatileRamTableInitConfig, NonVolatileInitTableConfig,
    },
};
pub use ram_circuit::{DynVolatileRamTable, MemFinalRecord, MemInitRecord, NonVolatileTable};

#[derive(Clone)]
pub struct HeapTable;

impl DynVolatileRamTable for HeapTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS;
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

pub type HeapInitCircuit<E> =
    DynVolatileRamCircuit<E, HeapTable, DynVolatileRamTableInitConfig<HeapTable>>;

#[derive(Clone)]
pub struct StackTable;

impl DynVolatileRamTable for StackTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS;
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

    fn name() -> &'static str {
        "StackTable"
    }

    fn max_len(params: &ProgramParams) -> usize {
        let max_size = (Self::offset_addr(params) - Self::end_addr(params))
            .div_ceil(WORD_SIZE as u32) as Addr
            + 1;
        1 << (u32::BITS - 1 - max_size.leading_zeros()) // prev_power_of_2
    }
}

pub type StackInitCircuit<E> =
    DynVolatileRamCircuit<E, StackTable, DynVolatileRamTableInitConfig<StackTable>>;

#[derive(Clone)]
pub struct HintsTable;
impl DynVolatileRamTable for HintsTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS;
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
pub type HintsCircuit<E> =
    DynVolatileRamCircuit<E, HintsTable, DynVolatileRamTableConfig<HintsTable>>;

/// RegTable, fix size without offset
#[derive(Clone)]
pub struct RegTable;

impl NonVolatileTable for RegTable {
    const RAM_TYPE: RAMType = RAMType::Register;
    const V_LIMBS: usize = UINT_LIMBS;
    const WRITABLE: bool = true;

    fn name() -> &'static str {
        "RegTable"
    }

    fn len(_params: &ProgramParams) -> usize {
        VMState::REG_COUNT.next_power_of_two()
    }
}

pub type RegTableInitCircuit<E> =
    NonVolatileRamCircuit<E, RegTable, NonVolatileInitTableConfig<RegTable>>;

#[derive(Clone)]
pub struct StaticMemTable;

impl NonVolatileTable for StaticMemTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS;
    const WRITABLE: bool = true;

    fn name() -> &'static str {
        "StaticMemTable"
    }

    fn len(params: &ProgramParams) -> usize {
        params.static_memory_len
    }
}

pub type StaticMemInitCircuit<E> =
    NonVolatileRamCircuit<E, StaticMemTable, NonVolatileInitTableConfig<StaticMemTable>>;

#[derive(Clone)]
pub struct PubIOTable;

impl NonVolatileTable for PubIOTable {
    const RAM_TYPE: RAMType = RAMType::Memory;
    const V_LIMBS: usize = UINT_LIMBS;
    const WRITABLE: bool = false;

    fn name() -> &'static str {
        "PubIOTable"
    }

    fn len(params: &ProgramParams) -> usize {
        params.pubio_len
    }
}

pub type PubIOCircuit<E> = PubIORamCircuit<E, PubIOTable>;
pub type LocalFinalCircuit<'a, E> = LocalFinalRamCircuit<'a, UINT_LIMBS, E>;
pub type RBCircuit<'a, E> = RamBusCircuit<'a, UINT_LIMBS, E>;
