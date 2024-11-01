use std::mem::MaybeUninit;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    scheme::constants::MIN_PAR_SIZE,
    witness::{LkMultiplicity, RowMajorMatrix},
};
use ff::Field;

pub mod riscv;

pub enum InstancePaddingStrategy {
    Zero,
    RepeatLast,
}

pub trait Instruction<E: ExtensionField> {
    type InstructionConfig: Send + Sync;

    fn padding_strategy() -> InstancePaddingStrategy {
        InstancePaddingStrategy::RepeatLast
    }

    fn name() -> String;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError>;

    // assign single instance giving step from trace
    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError>;

    fn assign_instances(
        config: &Self::InstructionConfig,
        num_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RowMajorMatrix<E::BaseField>, LkMultiplicity), ZKVMError> {
        let nthreads =
            std::env::var("RAYON_NUM_THREADS").map_or(8, |s| s.parse::<usize>().unwrap_or(8));
        let num_instance_per_batch = if steps.len() > 256 {
            steps.len().div_ceil(nthreads)
        } else {
            steps.len()
        }
        .max(1);
        let lk_multiplicity = LkMultiplicity::default();
        let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(steps.len(), num_witin);
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

        let num_padding_instances = raw_witin.num_padding_instances();
        if num_padding_instances > 0 {
            // Fill the padding based on strategy

            let padding_instance = match Self::padding_strategy() {
                InstancePaddingStrategy::Zero => {
                    vec![MaybeUninit::new(E::BaseField::ZERO); num_witin]
                }
                InstancePaddingStrategy::RepeatLast if steps.is_empty() => {
                    tracing::debug!("No {} steps to repeat, using zero padding", Self::name());
                    vec![MaybeUninit::new(E::BaseField::ZERO); num_witin]
                }
                InstancePaddingStrategy::RepeatLast => raw_witin[steps.len() - 1].to_vec(),
            };

            let num_padding_instance_per_batch = if num_padding_instances > 256 {
                num_padding_instances.div_ceil(nthreads)
            } else {
                num_padding_instances
            };
            raw_witin
                .par_batch_iter_padding_mut(num_padding_instance_per_batch)
                .with_min_len(MIN_PAR_SIZE)
                .for_each(|row| {
                    row.chunks_mut(num_witin)
                        .for_each(|instance| instance.copy_from_slice(padding_instance.as_slice()));
                });
        }

        Ok((raw_witin, lk_multiplicity))
    }
}
