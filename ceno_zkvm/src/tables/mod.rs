use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, scheme::constants::MIN_PAR_SIZE,
    witness::RowMajorMatrix,
};
use ff::Field;
use ff_ext::ExtensionField;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use std::{collections::HashMap, mem::MaybeUninit};
mod range;
pub use range::*;

mod ops;
pub use ops::*;

mod program;
pub use program::{InsnRecord, ProgramTableCircuit};

mod ram;
pub use ram::*;

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
    ) -> RowMajorMatrix<E::BaseField> {
        let (valid_len, mut table) = Self::generate_fixed_traces_inner(config, num_fixed, input);
        // Fill the padding with zeros, if any.
        table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .skip(valid_len)
            .for_each(|row| {
                row.iter_mut()
                    .for_each(|r| *r = MaybeUninit::new(E::BaseField::ZERO));
            });
        table
    }

    fn generate_fixed_traces_inner(
        config: &Self::TableConfig,
        num_fixed: usize,
        input: &Self::FixedInput,
    ) -> (usize, RowMajorMatrix<E::BaseField>);

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        input: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        let (valid_len, mut table) =
            Self::assign_instances_inner(config, num_witin, multiplicity, input)?;
        // Fill the padding with zeros, if any.
        table
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .skip(valid_len)
            .for_each(|row| {
                row.iter_mut()
                    .for_each(|r| *r = MaybeUninit::new(E::BaseField::ZERO));
            });
        Ok(table)
    }

    fn assign_instances_inner(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        input: &Self::WitnessInput,
    ) -> Result<(usize, RowMajorMatrix<E::BaseField>), ZKVMError>;
}
