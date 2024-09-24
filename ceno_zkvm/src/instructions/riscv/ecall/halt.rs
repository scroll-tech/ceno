use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{riscv::ecall_insn::EcallInstructionConfig, Instruction},
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};
use crate::chip_handler::GlobalStateRegisterMachineChipOperations;

pub struct HaltConfig {
    ecall_cfg: EcallInstructionConfig,
}

pub struct HaltCircuit<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for HaltCircuit<E> {
    type InstructionConfig = HaltConfig;

    fn name() -> String {
        "ECALL_HALT".into()
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        let ecall_cfg = EcallInstructionConfig::construct_circuit(cb)?;

        // next pc is zero
        cb.state_out(0.into(), ecall_cfg.ts.into())?;

        Ok(HaltConfig { ecall_cfg })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        todo!()
    }
}
