use std::marker::PhantomData;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, general::PublicValuesQuery},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::Instruction,
    structs::ProgramParams,
    tables::RMMCollections,
};
use ceno_emul::{InsnKind, StepIndex, StepRecord};
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use multilinear_extensions::ToExpr;
use p3::field::FieldAlgebra;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

pub struct GlobalStateConfig;

pub struct GlobalState<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for GlobalState<E> {
    type InstructionConfig = GlobalStateConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

    fn name() -> String {
        "ECALL_STATE_CONTINUATION".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let init_pc = cb.query_init_pc()?.expr();
        let init_cycle = cb.query_init_cycle()?.expr();
        cb.state_out(init_pc, init_cycle)?;

        let end_pc = cb.query_end_pc()?.expr();
        let end_cycle = cb.query_end_cycle()?.expr();
        cb.state_in(end_pc, end_cycle)?;

        Ok(GlobalStateConfig)
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut crate::e2e::ShardContext,
        instance: &mut [E::BaseField],
        _lk_multiplicity: &mut crate::witness::LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        if let Some(selector) = instance.last_mut() {
            *selector = E::BaseField::ONE;
        }
        Ok(())
    }

    fn assign_instances(
        _config: &Self::InstructionConfig,
        _shard_ctx: &mut crate::e2e::ShardContext,
        _num_witin: usize,
        num_structural_witin: usize,
        _shard_steps: &[StepRecord],
        step_indices: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        assert!(
            step_indices.is_empty(),
            "GlobalState should not be manually invoked with step indices"
        );
        let mut raw_structural = RowMajorMatrix::<E::BaseField>::new(
            1,
            num_structural_witin.max(1),
            InstancePaddingStrategy::Default,
        );

        if let Some(selector) = raw_structural.row_mut(0).last_mut() {
            *selector = E::BaseField::ONE;
        }

        raw_structural.padding_by_strategy();
        Ok((
            [RowMajorMatrix::empty(), raw_structural],
            Multiplicity::default(),
        ))
    }
}
