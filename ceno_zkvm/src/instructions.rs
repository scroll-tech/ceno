use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use gkr_iop::{
    ProtocolBuilder, ProtocolWitnessGenerator,
    gkr::{GKRCircuitWitness, layer::LayerWitness},
    precompiles::KeccakLayout,
};
use itertools::Itertools;
use multilinear_extensions::util::max_usable_threads;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::{circuit_builder::CircuitBuilder, error::ZKVMError, witness::LkMultiplicity};

use witness::{InstancePaddingStrategy, RowMajorMatrix};

pub mod riscv;

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

pub trait GKRIOPInstruction<E: ExtensionField>
where
    Self: Instruction<E>,
{
    type Layout: ProtocolWitnessGenerator<E> + ProtocolBuilder;
    fn assign_instance_with_gkr_iop(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
        lookups: &[E::BaseField],
    ) -> Result<(), ZKVMError>;

    fn phase1_witness_from_steps(
        layout: &Self::Layout,
        steps: &[StepRecord],
    ) -> Vec<Vec<E::BaseField>>;

    fn assign_instances_with_gkr_iop(
        config: &Self::InstructionConfig,
        num_witin: usize,
        steps: Vec<StepRecord>,
        gkr_layout: &mut Self::Layout,
    ) -> Result<
        (
            RowMajorMatrix<E::BaseField>,
            GKRCircuitWitness<E>,
            LkMultiplicity,
        ),
        ZKVMError,
    > {
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

        let gkr_witness = gkr_layout.gkr_witness(
            &Self::phase1_witness_from_steps(gkr_layout, &steps),
            &vec![],
        );

        let lookups = {
            let mut lookups = vec![vec![]; steps.len()];
            for witness in gkr_witness
                .layers
                .last()
                .unwrap()
                .bases
                .iter()
                .skip(100)
                .cloned()
            {
                for i in 0..witness.len() {
                    lookups[i].push(witness[i]);
                }
            }
            lookups
        };

        // dbg!(&lookups);

        raw_witin_iter
            .zip(
                steps
                    .iter()
                    .enumerate()
                    .collect_vec()
                    .par_chunks(num_instance_per_batch),
            )
            .flat_map(|(instances, steps)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                instances
                    .chunks_mut(num_witin)
                    .zip(steps)
                    .map(|(instance, (i, step))| {
                        // dbg!(i, step);
                        Self::assign_instance_with_gkr_iop(
                            config,
                            instance,
                            &mut lk_multiplicity,
                            step,
                            &lookups[*i],
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        raw_witin.padding_by_strategy();
        Ok((raw_witin, gkr_witness, lk_multiplicity))
    }
}
