use std::mem::MaybeUninit;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, witness::RowMajorMatrix};

pub mod riscv;

pub trait Instruction<E: ExtensionField> {
    type InstructionConfig: Send + Sync;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError>;

    // assign single instance giving step from trace
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E>],
        step: StepRecord,
    ) -> Result<(), ZKVMError>;

    fn assign_instances(
        config: &Self::InstructionConfig,
        num_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<RowMajorMatrix<E>, ZKVMError> {
        let mut raw_witin = RowMajorMatrix::<E>::new(steps.len(), num_witin);
        let raw_witin_iter = raw_witin.par_iter_mut();

        raw_witin_iter
            .zip_eq(steps.into_par_iter())
            .map(|(instance, step)| Self::assign_instance(config, instance, step))
            .collect::<Result<(), ZKVMError>>()?;

        Ok(raw_witin)
    }
}
