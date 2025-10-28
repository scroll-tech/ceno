use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, structs::ProgramParams};
use ff_ext::ExtensionField;
use gkr_iop::gkr::GKRCircuit;
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
        Ok((config, None))
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
