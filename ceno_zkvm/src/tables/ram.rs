use ceno_emul::{Addr, CENO_PLATFORM, VMState, WORD_SIZE};
use ram_circuit::{DynVolatileRamCircuit, NonVolatileRamCircuit, PubIORamCircuit};

use crate::{instructions::riscv::constants::UINT_LIMBS, structs::RAMType};

mod ram_circuit;
mod ram_impl;
pub use ram_circuit::{DynVolatileRamTable, MemFinalRecord, MemInitRecord, NonVolatileTable};

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

    fn max_len() -> usize {
        let max_size = (Self::END_ADDR - Self::OFFSET_ADDR) / WORD_SIZE as Addr;
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

    fn len() -> usize {
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

    fn len() -> usize {
        // TODO: take as program parameter.
        1 << 16 // words - 256KiB
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

    fn len() -> usize {
        // TODO: take as program parameter.
        1 << 2 // words
    }

    fn name() -> &'static str {
        "PubIOTable"
    }
}

pub type PubIOCircuit<E> = PubIORamCircuit<E, PubIOTable>;
