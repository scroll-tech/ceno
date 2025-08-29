//! Range tables as circuits with trait TableCircuit.

use super::range_impl::RangeTableConfig;

use std::{collections::HashMap, marker::PhantomData};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    structs::{ProgramParams, ROMType},
    tables::{
        RMMCollections, TableCircuit,
        range::range_impl::{DoubleRangeTableConfig, DynamicRangeTableConfig},
    },
};
use ff_ext::ExtensionField;
use gkr_iop::tables::LookupTable;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

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

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<RangeTableConfig, ZKVMError> {
        Ok(cb.namespace(
            || Self::name(),
            |cb| RangeTableConfig::construct_circuit(cb, RANGE::ROM_TYPE, RANGE::len()),
        )?)
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
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[RANGE::ROM_TYPE as usize];

        Ok(config.assign_instances(
            num_witin,
            num_structural_witin,
            multiplicity,
            RANGE::content(),
            RANGE::len(),
        )?)
    }
}

pub struct DynamicRangeTableCircuit<E, const MAX_BITS: usize>(PhantomData<E>);

impl<E: ExtensionField, const MAX_BITS: usize> TableCircuit<E>
    for DynamicRangeTableCircuit<E, MAX_BITS>
{
    type TableConfig = DynamicRangeTableConfig;
    type FixedInput = ();
    type WitnessInput = ();

    fn name() -> String {
        format!("DYNAMIC_RANGE_{}", MAX_BITS)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<DynamicRangeTableConfig, ZKVMError> {
        Ok(cb.namespace(
            || Self::name(),
            |cb| DynamicRangeTableConfig::construct_circuit(cb, MAX_BITS),
        )?)
    }

    fn generate_fixed_traces(
        _config: &DynamicRangeTableConfig,
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
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[LookupTable::Dynamic as usize];

        Ok(config.assign_instances(num_witin, num_structural_witin, multiplicity, MAX_BITS)?)
    }
}

pub struct DoubleRangeTableCircuit<E, const MAX_BITS_1: usize, const MAX_BITS_2: usize, R>(
    PhantomData<(E, R)>,
);

impl<E: ExtensionField, const MAX_BITS_1: usize, const MAX_BITS_2: usize, R: RangeTable>
    TableCircuit<E> for DoubleRangeTableCircuit<E, MAX_BITS_1, MAX_BITS_2, R>
{
    type TableConfig = DoubleRangeTableConfig;
    type FixedInput = ();
    type WitnessInput = ();

    fn name() -> String {
        format!("DOUBLE_RANGE_{:?}", R::ROM_TYPE)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<DoubleRangeTableConfig, ZKVMError> {
        Ok(cb.namespace(
            || Self::name(),
            |cb| DoubleRangeTableConfig::construct_circuit(cb, R::ROM_TYPE, MAX_BITS_1, MAX_BITS_2),
        )?)
    }

    fn generate_fixed_traces(
        _config: &DoubleRangeTableConfig,
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
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        let multiplicity = &multiplicity[R::ROM_TYPE as usize];

        Ok(config.assign_instances(
            num_witin,
            num_structural_witin,
            multiplicity,
            MAX_BITS_1,
            MAX_BITS_2,
        )?)
    }
}
