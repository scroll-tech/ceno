use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, witness::RowMajorMatrix};
use ff_ext::ExtensionField;

mod range;
pub use range::RangeTableCircuit;

pub trait TableCircuit<E: ExtensionField> {
    type TableConfig: Send + Sync;
    type Input: Send + Sync;

    fn name() -> String;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::TableConfig, ZKVMError>;

    fn generate_fixed_traces(
        config: &Self::TableConfig,
        num_fixed: usize,
    ) -> RowMajorMatrix<E::BaseField>;

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        inputs: &[Self::Input],
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError>;
}
