use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, structs::ProgramParams};
use ff_ext::ExtensionField;
use gkr_iop::{
    chip::Chip,
    default_out_eval_groups,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
};
use multilinear_extensions::ToExpr;
use std::collections::HashMap;
use witness::RowMajorMatrix;

mod shard_ram;
pub use shard_ram::*;

mod range;
pub use range::*;

mod ops;
pub use ops::*;

mod program;
pub use program::{InsnRecord, ProgramTableCircuit, ProgramTableConfig};

mod ram;
pub use ram::*;

/// format: [witness, structural_witness]
pub type RMMCollections<F> = [RowMajorMatrix<F>; 2];

pub trait TableCircuit<E: ExtensionField> {
    type TableConfig: Send + Sync;
    type FixedInput: Send + Sync + ?Sized;
    type WitnessInput<'a>: Send + Sync + ?Sized;

    fn name() -> String;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError>;

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::TableConfig, Option<GKRCircuit<E>>), ZKVMError> {
        let config = Self::construct_circuit(cb, param)?;

        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let selector_type = SelectorType::Prefix(selector.expr());
        cb.cs.set_default_read_selector(selector_type.clone());
        cb.cs.set_default_write_selector(selector_type.clone());
        cb.cs.set_default_lookup_selector(selector_type.clone());

        let out_evals = default_out_eval_groups(cb);
        let mut chip = Chip::new_from_cb(cb, 0);

        let layer = Layer::from_circuit_builder(cb, Self::name(), 0, out_evals);
        chip.add_layer(layer);

        Ok((config, Some(chip.gkr_circuit())))
    }

    fn generate_fixed_traces(
        config: &Self::TableConfig,
        num_fixed: usize,
        input: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField>;

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        input: &Self::WitnessInput<'_>,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError>;
}
