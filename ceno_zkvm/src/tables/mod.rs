use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, scheme::constants::MIN_PAR_SIZE,
    witness::RowMajorMatrix,
};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
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
    ) -> RowMajorMatrix<E::BaseField>;

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        multiplicity: &[HashMap<u64, usize>],
        input: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError>;

    fn padding_zero(
        table: &mut RowMajorMatrix<E::BaseField>,
        num_witin: usize,
    ) -> Result<(), ZKVMError> {
        padding_zero(table, num_witin, None);
        Ok(())
    }
}

/// Fill the padding with zeros. Start after the given `num_instances`, or detect it from the table.
pub fn padding_zero<F: SmallField>(
    table: &mut RowMajorMatrix<F>,
    num_cols: usize,
    num_instances: Option<usize>,
) {
    // Fill the padding with zeros, if any.
    let num_padding_instances = table.num_padding_instances();
    if num_padding_instances > 0 {
        let nthreads =
            std::env::var("RAYON_NUM_THREADS").map_or(8, |s| s.parse::<usize>().unwrap_or(8));
        let padding_instance = vec![MaybeUninit::new(F::ZERO); num_cols];
        let num_padding_instance_per_batch = if num_padding_instances > 256 {
            num_padding_instances.div_ceil(nthreads)
        } else {
            num_padding_instances
        };
        table
            .par_batch_iter_padding_mut(num_instances, num_padding_instance_per_batch)
            .with_min_len(MIN_PAR_SIZE)
            .for_each(|row| {
                row.chunks_mut(num_cols)
                    .for_each(|instance| instance.copy_from_slice(padding_instance.as_slice()));
            });
    }
}
