use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, structs::ProgramParams,
    tables::RMMCollections, witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::{
    chip::Chip,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
    utils::lk_multiplicity::Multiplicity,
};
use itertools::Itertools;
use multilinear_extensions::{ToExpr, WitIn, util::max_usable_threads};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_val};

pub mod riscv;

pub trait Instruction<E: ExtensionField> {
    type InstructionConfig: Send + Sync;

    fn padding_strategy() -> InstancePaddingStrategy {
        InstancePaddingStrategy::Default
    }

    fn name() -> String;

    /// construct circuit and manipulate circuit builder, then return the respective config
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError>;

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::InstructionConfig, GKRCircuit<E>), ZKVMError> {
        let config = Self::construct_circuit(cb, param)?;
        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();

        let selector = cb.create_structural_witin(|| "selector", 0, 0, 0, false);
        let selector_type = SelectorType::Prefix(E::BaseField::ZERO, selector.expr());

        // all shared the same selector
        let (out_evals, mut chip) = (
            [
                // r_record
                (selector_type.clone(), (0..r_len).collect_vec()),
                // w_record
                (selector_type.clone(), (r_len..r_len + w_len).collect_vec()),
                // lk_record
                (
                    selector_type.clone(),
                    (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                ),
                // zero_record
                (selector_type, (0..zero_len).collect_vec()),
            ],
            Chip::new_from_cb(cb, 0),
        );

        let layer = Layer::from_circuit_builder(cb, "Rounds".to_string(), 0, out_evals);
        chip.add_layer(layer);

        Ok((config, chip.gkr_circuit()))
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
        num_structural_witin: usize,
        steps: Vec<StepRecord>,
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        // FIXME selector is the only structural witness
        // this is workaround, as call `construct_circuit` will not initialized selector
        // we can remove this one all opcode unittest migrate to call `build_gkr_iop_circuit`
        assert!(num_structural_witin == 0 || num_structural_witin == 1);
        let num_structural_witin = num_structural_witin.max(1);
        let selector_witin = WitIn { id: 0 };

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
        let mut raw_structual_witin = RowMajorMatrix::<E::BaseField>::new(
            steps.len(),
            num_structural_witin,
            Self::padding_strategy(),
        );
        let raw_witin_iter = raw_witin.par_batch_iter_mut(num_instance_per_batch);
        let raw_structual_witin_iter =
            raw_structual_witin.par_batch_iter_mut(num_instance_per_batch);

        raw_witin_iter
            .zip_eq(raw_structual_witin_iter)
            .zip_eq(steps.par_chunks(num_instance_per_batch))
            .flat_map(|((instances, structural_instance), steps)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                instances
                    .chunks_mut(num_witin)
                    .zip_eq(structural_instance.chunks_mut(num_structural_witin))
                    .zip_eq(steps)
                    .map(|((instance, structural_instance), step)| {
                        set_val!(structural_instance, selector_witin, E::BaseField::ONE);
                        Self::assign_instance(config, instance, &mut lk_multiplicity, step)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<(), ZKVMError>>()?;

        raw_witin.padding_by_strategy();
        raw_structual_witin.padding_by_strategy();
        Ok((
            [raw_witin, raw_structual_witin],
            lk_multiplicity.into_finalize_result(),
        ))
    }
}
