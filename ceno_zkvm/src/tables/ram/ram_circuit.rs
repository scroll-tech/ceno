use std::{collections::HashMap, marker::PhantomData};

use ceno_emul::{Addr, Cycle, WORD_SIZE, Word};
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, structs::RAMType, tables::TableCircuit,
    witness::RowMajorMatrix,
};

use super::ram_impl::{DynVolatileRamTableConfig, NonVolatileTableConfig, PubIOTableConfig};

#[derive(Clone, Debug)]
pub struct MemInitRecord {
    pub addr: Addr,
    pub value: Word,
}

pub struct MemFinalRecord {
    pub addr: Addr,
    pub cycle: Cycle,
    pub value: Word,
}

/// - **Non-Volatile**: The initial values can be set to any arbitrary value.
///
/// **Special Note**:
/// Setting `WRITABLE = false` does not strictly enforce immutability in this protocol.
/// it only guarantees that the initial and final values remain invariant,
/// allowing for temporary modifications within the lifecycle.
// pub trait NonVolatileTable: Default + Sized {
//     // const RAM_TYPE: RAMType;
//     // const V_LIMBS: usize;
//     // const WRITABLE: bool;
//     // const OFFSET_ADDR: Addr;
//     // const END_ADDR: Addr;

//     fn ram_type(&self) -> RAMType;
//     fn v_limbs(&self) -> usize;
//     fn writable(&self) -> bool;
//     fn offset_addr(&self) -> Addr;
//     fn end_addr(&self) -> Addr;

//     fn name(&self) -> &'static str;

//     fn len(&self) -> usize {
//         //(Self::END_ADDR - Self::OFFSET_ADDR) as usize / WORD_SIZE
//         (self.end_addr() - self.offset_addr()) as usize / WORD_SIZE
//     }

//     fn addr(&self, entry_index: usize) -> Addr {
//         // Self::OFFSET_ADDR + (entry_index * WORD_SIZE) as Addr
//         self.offset_addr() + (entry_index * WORD_SIZE) as Addr
//     }

//     fn init_state(&self) -> Vec<MemInitRecord> {
//         (0..self.len())
//             .map(|i| MemInitRecord {
//                 addr: self.addr(i),
//                 value: 0,
//             })
//             .collect()
//     }
// }

#[derive(Clone)]
pub struct NonVolatileTable {
    pub ram_type: RAMType,
    pub v_limbs: usize,
    pub writable: bool,
    pub offset_addr: Addr,
    pub end_addr: Addr,
    pub name: &'static str,
}

impl NonVolatileTable {
    pub fn len(&self) -> usize {
        //(Self::END_ADDR - Self::OFFSET_ADDR) as usize / WORD_SIZE
        (self.end_addr() - self.offset_addr()) as usize / WORD_SIZE
    }

    pub fn addr(&self, entry_index: usize) -> Addr {
        // Self::OFFSET_ADDR + (entry_index * WORD_SIZE) as Addr
        self.offset_addr() + (entry_index * WORD_SIZE) as Addr
    }

    pub fn init_state(&self) -> Vec<MemInitRecord> {
        (0..self.len())
            .map(|i| MemInitRecord {
                addr: self.addr(i),
                value: 0,
            })
            .collect()
    }
}

/// non-volatile indicates initial value is configurable
#[derive(Default)]
pub struct NonVolatileRamCircuit {
    nvram: NonVolatileTable
};

impl<E: ExtensionField> TableCircuit<E>
    for NonVolatileRamCircuit
{
    type TableConfig = NonVolatileTableConfig;
    type FixedInput = [MemInitRecord];
    type WitnessInput = [MemFinalRecord];

    fn name(&self) -> String {
        format!("RAM_{:?}_{}", self.nvram.ram_type(), self.nvram.name())
    }

    fn construct_circuit(
        &self,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || self.name(),
            |cb| Self::TableConfig::construct_circuit(self, cb),
        )
    }

    fn generate_fixed_traces(
        &self,
        config: &Self::TableConfig,
        num_fixed: usize,
        init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        // assume returned table is well-formed include padding
        config.gen_init_state(num_fixed, init_v)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        config.assign_instances(num_witin, final_v)
    }
}

#[derive(Default)]
pub struct PubIORamCircuit<E> {
    phantom: PhantomData<(E)>,
    nvt: NonVolatileTable,
}

impl<E: ExtensionField> TableCircuit<E>
    for PubIORamCircuit<E>
{
    type TableConfig = PubIOTableConfig;
    type FixedInput = ();
    type WitnessInput = [MemFinalRecord];

    fn name(&self) -> String {
        format!("RAM_{:?}_{}", self.nvt.ram_type(), self.nvt.name())
    }

    fn construct_circuit(
        nvt: NonVolatileTable,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || self.name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
    }

    fn generate_fixed_traces(
        &self,
        config: &Self::TableConfig,
        num_fixed: usize,
        _init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        // assume returned table is well-formed include padding
        config.gen_init_state(num_fixed)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        config.assign_instances(num_witin, final_v)
    }
}

/// - **Dynamic**: The address space is bounded within a specific range,
///   though the range itself may be dynamically determined per proof.
/// - **Volatile**: The initial values are set to `0`
// pub trait DynVolatileRamTable {
//     const RAM_TYPE: RAMType;
//     const V_LIMBS: usize;

//     const OFFSET_ADDR: Addr;
//     const END_ADDR: Addr;

//     fn name() -> &'static str;

//     fn max_len() -> usize {
//         (Self::END_ADDR - Self::OFFSET_ADDR) as usize / WORD_SIZE
//     }

//     fn addr(entry_index: usize) -> Addr {
//         Self::OFFSET_ADDR + (entry_index * WORD_SIZE) as Addr
//     }
// }

pub struct DynVolatileRamTable {
        ram_type: RAMType,
        v_limbs: usize,
    
        offset_addr: Addr,
        end_addr: Addr,
    
        name: &'static str
}

impl DynVolatileRamTable {
        pub fn max_len() -> usize {
            (Self::END_ADDR - Self::OFFSET_ADDR) as usize / WORD_SIZE
        }
    
        pub fn addr(entry_index: usize) -> Addr {
            Self::OFFSET_ADDR + (entry_index * WORD_SIZE) as Addr
        }
    }


#[derive(Default)]
pub struct DynVolatileRamCircuit<E> {
    phantom: PhantomData<E>,
    dvram: DynVolatileRamTable
}

impl<E: ExtensionField> TableCircuit<E>
    for DynVolatileRamCircuit<E>
{
    type TableConfig = DynVolatileRamTableConfig<DVRAM>;
    type FixedInput = ();
    type WitnessInput = [MemFinalRecord];

    fn name(&self) -> String {
        format!("RAM_{:?}", DVRAM::RAM_TYPE)
    }

    fn construct_circuit(
        &self,
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
    }

    fn generate_fixed_traces(
        &self,
        _config: &Self::TableConfig,
        _num_fixed: usize,
        _init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::<E::BaseField>::new(0, 0)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        config.assign_instances(num_witin, final_v)
    }
}
