use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, witness::RowMajorMatrix};
use ff_ext::ExtensionField;
use std::collections::HashMap;

mod range;
pub use range::*;

mod program;
pub use program::{InsnRecord, ProgramTableCircuit};

pub trait TableCircuit<E: ExtensionField> {
    type TableConfig: Send + Sync;
    type FixedInput: Send + Sync + ?Sized;
    type WitnessInput: Send + Sync + ?Sized;

    fn name() -> String;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::TableConfig, ZKVMError>;

    fn generate_fixed_traces(
        config: &Self::TableConfig,
        num_fixed: usize,
        input: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField>;

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        input: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError>;
}
