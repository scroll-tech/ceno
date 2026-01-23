//! Ops tables as circuits with trait TableCircuit.

use super::ops_impl::OpTableConfig;

use std::{collections::HashMap, marker::PhantomData};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    structs::ProgramParams,
    tables::{RMMCollections, TableCircuit},
};
use ff_ext::ExtensionField;
use gkr_iop::tables::OpsTable;
use witness::RowMajorMatrix;

pub struct OpsTableCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, OP: OpsTable> TableCircuit<E> for OpsTableCircuit<E, OP> {
    type TableConfig = OpTableConfig;
    type FixedInput = ();
    type WitnessInput<'a> = ();

    fn name() -> String {
        format!("{:?}_OPS_ROM_TABLE", OP::ROM_TYPE)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<OpTableConfig, ZKVMError> {
        Ok(cb.namespace(
            || Self::name(),
            |cb| OpTableConfig::construct_circuit(cb, OP::ROM_TYPE, OP::len()),
        )?)
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
        num_structural_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        _input: &(),
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[OP::ROM_TYPE as usize];
        Ok(config.assign_instances(num_witin, num_structural_witin, multiplicity, OP::len())?)
    }
}
