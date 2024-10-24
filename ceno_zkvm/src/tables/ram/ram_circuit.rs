use std::{collections::HashMap, marker::PhantomData};

use ceno_emul::{Addr, Cycle, Word};
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
    pub cycle: Cycle,
    pub value: Word,
}

pub trait NonVolatileTable {
    const RAM_TYPE: RAMType;
    const V_LIMBS: usize;
    const RW: bool;

    fn len() -> usize;

    fn offset() -> Addr;

    fn addr(entry_index: usize) -> Addr;

    fn init_state() -> Vec<MemInitRecord> {
        (0..Self::len())
            .map(|i| MemInitRecord {
                addr: Self::addr(i),
                value: 0,
            })
            .collect()
    }
}

pub struct NonVolatileRamCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, NVRAM: NonVolatileTable + Send + Sync + Clone> TableCircuit<E>
    for NonVolatileRamCircuit<E, NVRAM>
{
    type TableConfig = NonVolatileTableConfig<NVRAM>;
    type FixedInput = [MemInitRecord];
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}", NVRAM::RAM_TYPE)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
    }

    fn generate_fixed_traces(
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

pub struct PubIOCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, NVRAM: NonVolatileTable + Send + Sync + Clone> TableCircuit<E>
    for PubIOCircuit<E, NVRAM>
{
    type TableConfig = PubIOTableConfig<NVRAM>;
    type FixedInput = ();
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}", NVRAM::RAM_TYPE)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
    }

    fn generate_fixed_traces(
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

/// trait to define a DynVolatileRamTable
pub trait DynVolatileRamTable {
    const RAM_TYPE: RAMType;
    const V_LIMBS: usize;

    fn max_len() -> usize;

    fn offset() -> Addr;

    fn addr(entry_index: usize) -> Addr;
}

pub struct DynVolatileRamCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, DVRAM: DynVolatileRamTable + Send + Sync + Clone> TableCircuit<E>
    for DynVolatileRamCircuit<E, DVRAM>
{
    type TableConfig = DynVolatileRamTableConfig<DVRAM>;
    type FixedInput = ();
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}", DVRAM::RAM_TYPE)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
    }

    fn generate_fixed_traces(
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
