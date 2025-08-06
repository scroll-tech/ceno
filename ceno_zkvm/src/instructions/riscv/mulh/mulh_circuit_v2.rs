use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{Instruction, riscv::RIVInstruction},
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;

use std::marker::PhantomData;

pub struct MulhInstructionBase<E, I>(PhantomData<(E, I)>);

pub struct MulhConfig<E: ExtensionField> {
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstructionBase<E, I> {
    type InstructionConfig = MulhConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        _circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<MulhConfig<E>, ZKVMError> {
        unimplemented!()
    }

    fn assign_instance(
        _config: &Self::InstructionConfig,
        _instance: &mut [<E as ExtensionField>::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        unimplemented!()
    }
}
