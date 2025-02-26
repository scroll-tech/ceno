//! Range tables as circuits with trait TableCircuit.

use super::range_impl::RangeTableConfig;

use std::{collections::HashMap, marker::PhantomData};

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, instructions::InstancePaddingStrategy,
    structs::ROMType, tables::TableCircuit, witness::RowMajorMatrix,
};
use ff_ext::ExtensionField;

/// Use this trait as parameter to RangeTableCircuit.
pub trait RangeTable {
    const ROM_TYPE: ROMType;

    fn len() -> usize;

    fn content() -> Vec<u64> {
        (0..Self::len() as u64).collect()
    }
}

pub struct RangeTableCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, RANGE: RangeTable> TableCircuit<E> for RangeTableCircuit<E, RANGE> {
    type TableConfig = RangeTableConfig;
    type FixedInput = ();
    type WitnessInput = ();

    fn name() -> String {
        format!("RANGE_{:?}", RANGE::ROM_TYPE)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<RangeTableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| RangeTableConfig::construct_circuit(cb, RANGE::ROM_TYPE, RANGE::len()),
        )
    }

    fn generate_fixed_traces(
        _config: &RangeTableConfig,
        _num_fixed: usize,
        _input: &(),
    ) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::<E::BaseField>::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        _input: &(),
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[RANGE::ROM_TYPE as usize];
        config.assign_instances(
            num_witin,
            num_structural_witin,
            multiplicity,
            RANGE::content(),
            RANGE::len(),
        )
    }
}
