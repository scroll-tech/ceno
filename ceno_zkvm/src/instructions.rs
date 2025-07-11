use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use gkr_iop::gkr::GKRCircuit;
use multilinear_extensions::util::max_usable_threads;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, structs::ProgramParams,
    witness::LkMultiplicity,
};

use witness::{InstancePaddingStrategy, RowMajorMatrix};

pub mod riscv;

pub trait Instruction<E: ExtensionField> {
    type InstructionConfig: Send + Sync;

    fn padding_strategy() -> InstancePaddingStrategy {
        InstancePaddingStrategy::RepeatLast
    }

    fn name() -> String;

    /// construct circuit and manipulate circuit builder, then return the respective config
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError>;

    /// giving config, extract optional gkr circuit
    fn extract_gkr_iop_circuit(
        _config: &mut Self::InstructionConfig,
    ) -> Result<Option<GKRCircuit<E>>, ZKVMError> {
        Ok(None)
    }

    fn generate_fixed_traces(
        _config: &Self::InstructionConfig,
        _num_fixed: usize,
    ) -> Option<RowMajorMatrix<E::BaseField>> {
        None
    }

    // assign single instance giving step from trace
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError>;

    fn assign_instances(
        config: &Self::InstructionConfig,
        num_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RowMajorMatrix<E::BaseField>, LkMultiplicity), ZKVMError> {
        let nthreads = max_usable_threads();
        let num_instance_per_batch = if steps.len() > 256 {
            steps.len().div_ceil(nthreads)
        } else {
            steps.len()
        }
        .max(1);
        let lk_multiplicity = LkMultiplicity::default();
        let mut raw_witin =
            RowMajorMatrix::<E::BaseField>::new(steps.len(), num_witin, Self::padding_strategy());
        let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);

        raw_witin_iter
            .zip(steps.par_chunks(num_instance_per_batch))
            .flat_map(|(instances, steps)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                instances
                    .chunks_mut(num_witin)
                    .zip(steps)
                    .map(|(instance, step)| {
                        Self::assign_instance(config, instance, &mut lk_multiplicity, step)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        raw_witin.padding_by_strategy();
        Ok((raw_witin, lk_multiplicity))
    }
}
