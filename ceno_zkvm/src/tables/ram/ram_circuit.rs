use std::{collections::HashMap, marker::PhantomData};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, structs::RAMType, tables::TableCircuit,
    witness::RowMajorMatrix,
};

use super::ram_impl::RamTableConfig;

/// Use this trait as parameter to MemoryCircuit.
pub trait RamTable {
    const RAM_TYPE: RAMType;
    const V_LIMBS: usize;

    fn len() -> usize;

    fn init_state() -> Vec<u32>;
}

pub struct RamTableCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, RAM: RamTable> TableCircuit<E> for RamTableCircuit<E, RAM> {
    type TableConfig = RamTableConfig;
    type FixedInput = Option<Vec<u32>>;
    type WitnessInput = (Vec<u32>, Vec<u32>);

    fn name() -> String {
        format!("RAM_{:?}", RAM::RAM_TYPE)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb, RAM::RAM_TYPE, RAM::len()),
        )
    }

    fn generate_fixed_traces(
        config: &RamTableConfig,
        num_fixed: usize,
        input: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        let mut table = if let Some(init_v) = input.as_ref() {
            config.gen_init_state(num_fixed, init_v)
        } else {
            config.gen_init_state(num_fixed, &RAM::init_state())
        };
        Self::padding_zero(&mut table, num_fixed).expect("padding error");
        table
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        (final_v, final_t): &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let mut table = config.assign_instances(num_witin, final_v, final_t)?;
        Self::padding_zero(&mut table, num_witin)?;
        Ok(table)
    }
}
