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

    // TODO(Matthias): pack and upnack look pretty stupid.
    // Why do we need to pack those into 64 bits here, but not eg pack the result as well?
    // What's the point?
    // OK, so both `a` and `b` have to be within 8 bits?  Should we assert that?
    // (Otherwise, unpack don't work.)
    fn pack(a: u64, b: u64) -> u64 {
        assert!(a < 256);
        assert!(b < 256);
        a | (b << 8)
    }

    fn unpack(i: u64) -> (u64, u64) {
        assert!(i < 1 << 16);
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
