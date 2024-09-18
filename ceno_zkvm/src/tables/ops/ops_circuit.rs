//! Ops tables as circuits with trait TableCircuit.

use super::ops_impl::OpTableConfig;

use std::{collections::HashMap, marker::PhantomData};

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, structs::ROMType, tables::TableCircuit,
    witness::RowMajorMatrix,
};
use ff_ext::ExtensionField;

/// Use this trait as parameter to OpsTableCircuit.
pub trait OpsTable {
    const ROM_TYPE: ROMType;

    fn len() -> usize;

    fn content() -> Vec<u64>;
}

pub struct OpsTableCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, OP: OpsTable> TableCircuit<E> for OpsTableCircuit<E, OP> {
    type TableConfig = OpTableConfig;
    type FixedInput = ();
    type WitnessInput = ();

    fn name() -> String {
        format!("OPS_{:?}", OP::ROM_TYPE)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<OpTableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| OpTableConfig::construct_circuit(cb, OP::ROM_TYPE),
        )
    }

    fn generate_fixed_traces(
        config: &OpTableConfig,
        num_fixed: usize,
        _input: &(),
    ) -> RowMajorMatrix<E::BaseField> {
        config.generate_fixed_traces(num_fixed, OP::content())
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        _input: &(),
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[OP::ROM_TYPE as usize];
        config.assign_instances(num_witin, multiplicity, OP::len())
    }
}
