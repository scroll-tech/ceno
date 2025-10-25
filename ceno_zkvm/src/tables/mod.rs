use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, structs::ProgramParams};
use ff_ext::ExtensionField;
use gkr_iop::{
    chip::Chip,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
};
use itertools::Itertools;
use multilinear_extensions::{StructuralWitInType, ToExpr};
use std::collections::HashMap;
use witness::RowMajorMatrix;

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
    type WitnessInput: Send + Sync + ?Sized;

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
        let r_table_len = cb.cs.r_table_expressions.len();
        let w_table_len = cb.cs.w_table_expressions.len();
        let lk_table_len = cb.cs.lk_table_expressions.len() * 2;

        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let selector_type = SelectorType::Whole(selector.expr());

        // all shared the same selector
        let (out_evals, mut chip) = (
            [
                // r_record
                (0..r_table_len).collect_vec(),
                // w_record
                (r_table_len..r_table_len + w_table_len).collect_vec(),
                // lk_record
                (r_table_len + w_table_len..r_table_len + w_table_len + lk_table_len).collect_vec(),
                // zero_record
                vec![],
            ],
            Chip::new_from_cb(cb, 0),
        );

        // register selector to legacy constrain system
        if r_table_len > 0 {
            cb.cs.r_selector = Some(selector_type.clone());
        }
        if w_table_len > 0 {
            cb.cs.w_selector = Some(selector_type.clone());
        }
        if lk_table_len > 0 {
            cb.cs.lk_selector = Some(selector_type.clone());
        }

        let layer = Layer::from_circuit_builder(cb, "Rounds".to_string(), 0, out_evals);
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
        input: &Self::WitnessInput,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError>;
}
