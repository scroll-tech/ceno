use std::{collections::HashMap, marker::PhantomData};

use ceno_emul::{Addr, Cycle, Word};
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, structs::RAMType, tables::TableCircuit,
    witness::RowMajorMatrix,
};

use super::ram_impl::RamTableConfig;

#[derive(Clone, Debug)]
pub struct MemInitRecord {
    pub addr: Addr,
    pub value: Word,
}

pub struct MemFinalRecord {
    pub cycle: Cycle,
    pub value: Word,
}

/// Impl trait as parameter to RamTableCircuit.
pub trait RamTable {
    const RAM_TYPE: RAMType;
    const V_LIMBS: usize;

    fn len() -> usize;

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

pub struct RamTableCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, RAM: RamTable + Send + Sync + Clone> TableCircuit<E>
    for RamTableCircuit<E, RAM>
{
    type TableConfig = RamTableConfig<RAM>;
    type FixedInput = [MemInitRecord];
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}", RAM::RAM_TYPE)
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
        let mut table = config.gen_init_state(num_fixed, init_v);
        Self::padding_zero(&mut table, num_fixed).expect("padding error");
        table
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let mut table = config.assign_instances(num_witin, final_v)?;
        Self::padding_zero(&mut table, num_witin)?;
        Ok(table)
    }
}
