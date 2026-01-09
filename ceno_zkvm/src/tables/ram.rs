use ceno_emul::{Addr, VM_REG_COUNT, WORD_SIZE};
use ff_ext::ExtensionField;
use gkr_iop::error::CircuitBuilderError;
use multilinear_extensions::{Expression, Instance, StructuralWitIn, StructuralWitInType, ToExpr};
use ram_circuit::{DynVolatileRamCircuit, NonVolatileRamCircuit, PubIORamInitCircuit};

use crate::{
    instructions::riscv::constants::UINT_LIMBS,
    structs::{ProgramParams, RAMType},
};

mod ram_circuit;
mod ram_impl;
use crate::{
    chip_handler::general::PublicValuesQuery,
    circuit_builder::CircuitBuilder,
    instructions::riscv::constants::{HEAP_LENGTH_IDX, HINT_LENGTH_IDX},
    scheme::PublicValues,
    structs::WitnessId,
    tables::ram::{
        ram_circuit::LocalFinalRamCircuit,
        ram_impl::{DynVolatileRamTableInitConfig, NonVolatileInitTableConfig},
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

    fn addr_expr<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Expression<E>, StructuralWitIn), CircuitBuilderError> {
        let max_len = Self::max_len(params);
        let addr = cb.create_structural_witin(
            || "addr",
            StructuralWitInType::EqualDistanceDynamicSequence {
                max_len,
                offset_instance_id: cb.query_heap_start_addr()?.0 as WitnessId,
                multi_factor: WORD_SIZE,
                descending: Self::DESCENDING,
            },
        );
        Ok((addr.expr(), addr))
    }

    fn offset_addr(_params: &ProgramParams) -> Addr {
        unimplemented!("heap offset is dynamic")
    }

    fn dynamic_offset_addr(params: &ProgramParams, pv: &PublicValues) -> Addr {
        let heap_start = pv.heap_start_addr;
        assert!(
            heap_start >= params.platform.heap.start,
            "heap_start {:x} < platform min heap start {:x}",
            heap_start,
            params.platform.heap.start
        );
        heap_start
    }

    fn end_addr(_params: &ProgramParams) -> Addr {
        unimplemented!("heap end address is dynamic")
    }

    fn name() -> &'static str {
        "HeapTable"
    }

    fn max_len(params: &ProgramParams) -> usize {
        let max_size = (params.platform.heap.end - params.platform.heap.start)
            .div_ceil(WORD_SIZE as u32) as Addr;
        1 << (u32::BITS - 1 - max_size.leading_zeros())
    }

    fn dynamic_addr(params: &ProgramParams, entry_index: usize, pv: &PublicValues) -> Addr {
        let addr = Self::dynamic_offset_addr(params, pv) + (entry_index * WORD_SIZE) as Addr;
        assert!(
            addr < params.platform.heap.end,
            "heap addr {:x} >= platform max heap end {:x}",
            addr,
            params.platform.heap.end
        );
        addr
    }

    fn dynamic_length_instance() -> Option<Instance> {
        Some(Instance(HEAP_LENGTH_IDX))
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

    fn addr_expr<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Expression<E>, StructuralWitIn), CircuitBuilderError> {
        let max_len = Self::max_len(params);
        let addr = cb.create_structural_witin(
            || "addr",
            StructuralWitInType::EqualDistanceDynamicSequence {
                max_len,
                offset_instance_id: cb.query_hint_start_addr()?.0 as WitnessId,
                multi_factor: WORD_SIZE,
                descending: Self::DESCENDING,
            },
        );
        Ok((addr.expr(), addr))
    }

    fn offset_addr(_params: &ProgramParams) -> Addr {
        unimplemented!("hints offset is dynamic")
    }

    fn dynamic_offset_addr(params: &ProgramParams, pv: &PublicValues) -> Addr {
        let hint_start = pv.hint_start_addr;
        assert!(
            hint_start >= params.platform.hints.start,
            "hint_start {:x} < platform min hint start {:x}",
            hint_start,
            params.platform.hints.start
        );
        hint_start
    }

    fn end_addr(_params: &ProgramParams) -> Addr {
        unimplemented!("hints end address is dynamic")
    }

    fn name() -> &'static str {
        "HintsTable"
    }

    fn max_len(params: &ProgramParams) -> usize {
        let max_size = (params.platform.hints.end - params.platform.hints.start)
            .div_ceil(WORD_SIZE as u32) as Addr;
        1 << (u32::BITS - 1 - max_size.leading_zeros())
    }

    fn dynamic_addr(params: &ProgramParams, entry_index: usize, pv: &PublicValues) -> Addr {
        let addr = Self::dynamic_offset_addr(params, pv) + (entry_index * WORD_SIZE) as Addr;
        assert!(
            addr < params.platform.hints.end,
            "hint addr {:x} >= platform max hint end {:x}",
            addr,
            params.platform.hints.end
        );
        addr
    }

    fn dynamic_length_instance() -> Option<Instance> {
        Some(Instance(HINT_LENGTH_IDX))
    }
}
pub type HintsInitCircuit<E> =
    DynVolatileRamCircuit<E, HintsTable, DynVolatileRamTableInitConfig<HintsTable>>;

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
        VM_REG_COUNT.next_power_of_two()
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

pub type PubIOInitCircuit<E> = PubIORamInitCircuit<E, PubIOTable>;
pub type LocalFinalCircuit<E> = LocalFinalRamCircuit<UINT_LIMBS, E>;
