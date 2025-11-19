//! Range tables as circuits with trait TableCircuit.

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
use gkr_iop::{
    chip::Chip,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
    tables::LookupTable,
};
use itertools::Itertools;
use multilinear_extensions::ToExpr;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

/// Use this trait as parameter to RangeTableCircuit.
pub trait RangeTable {
    const ROM_TYPE: ROMType;

    fn len() -> usize;

    fn content() -> Vec<u64> {
        (0..Self::len() as u64).collect()
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
        assert_eq!(MAX_BITS_1 + MAX_BITS_2, R::len().ilog2() as usize);
        Ok(cb.namespace(
            || Self::name(),
            |cb| DoubleRangeTableConfig::construct_circuit(cb, R::ROM_TYPE, MAX_BITS_1, MAX_BITS_2),
        )?)
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::TableConfig, Option<GKRCircuit<E>>), ZKVMError> {
        let config = Self::construct_circuit(cb, param)?;
        let lk_table_len = cb.cs.lk_table_expressions.len() * 2;

        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let selector_type = SelectorType::Whole(selector.expr());

        // all shared the same selector
        let (out_evals, mut chip) = (
            [
                // r_record
                vec![],
                // w_record
                vec![],
                // lk_record
                (0..lk_table_len).collect_vec(),
                // zero_record
                vec![],
            ],
            Chip::new_from_cb(cb, 0),
        );

        // register selector to legacy constrain system
        cb.cs.lk_selector = Some(selector_type.clone());

        let layer = Layer::from_circuit_builder(cb, Self::name(), 0, out_evals);
        chip.add_layer(layer);

        Ok((config, Some(chip.gkr_circuit())))
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

        Ok(config.assign_instances(num_witin, num_structural_witin, multiplicity)?)
    }
}
