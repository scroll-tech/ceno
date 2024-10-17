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

    /// The content of the table: [[a, b, result], ...]
    fn content() -> Vec<[u64; 3]>;

    fn pack(a: u64, b: u64) -> u64 {
        a | (b << 8)
    }

    fn unpack(i: u64) -> (u64, u64) {
        (i & 0xff, (i >> 8) & 0xff)
    }
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
            |cb| OpTableConfig::construct_circuit(cb, OP::ROM_TYPE, OP::len()),
        )
    }

    fn generate_fixed_traces(
        config: &OpTableConfig,
        num_fixed: usize,
        _input: &(),
    ) -> RowMajorMatrix<E::BaseField> {
        let mut table = config.generate_fixed_traces(num_fixed, OP::content());
        Self::padding_zero(&mut table, num_fixed).expect("padding error");
        table
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        _input: &(),
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[OP::ROM_TYPE as usize];
        let mut table = config.assign_instances(num_witin, multiplicity, OP::len())?;
        Self::padding_zero(&mut table, num_witin)?;
        Ok(table)
    }
}
