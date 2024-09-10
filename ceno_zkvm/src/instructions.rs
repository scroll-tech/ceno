use std::mem::MaybeUninit;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    witness::{LkMultiplicity, RowMajorMatrix},
};

pub mod riscv;

pub trait Instruction<E: ExtensionField> {
    type InstructionConfig: Send + Sync;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError>;

    // assign single instance giving step from trace
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: StepRecord,
    ) -> Result<(), ZKVMError>;

    fn assign_instances(
        config: &Self::InstructionConfig,
        num_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RowMajorMatrix<E::BaseField>, LkMultiplicity), ZKVMError> {
        let lk_multiplicity = LkMultiplicity::default();
        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(steps.len(), num_witin);
        let raw_witin_iter = raw_witin.par_iter_mut();

        raw_witin_iter
            .zip_eq(steps.into_par_iter())
            .map(|(instance, step)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                Self::assign_instance(config, instance, &mut lk_multiplicity, step)
            })
            .collect::<Result<(), ZKVMError>>()?;

        Ok((raw_witin, lk_multiplicity))
    }
}
