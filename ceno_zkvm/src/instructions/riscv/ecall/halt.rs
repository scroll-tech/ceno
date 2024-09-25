use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::ECALL_HALT, ecall_insn::EcallInstructionConfig},
        Instruction,
    },
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

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
        let ecall_cfg = EcallInstructionConfig::construct_circuit(
            cb,
            [ECALL_HALT[0].into(), ECALL_HALT[1].into()],
            None,
            Some(0.into()),
        )?;

        // TODO: read exit_code from arg1 and write it to global state

        Ok(HaltConfig { ecall_cfg })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        assert_eq!(
            step.rs1().unwrap().value,
            (ECALL_HALT[0] + (ECALL_HALT[1] << 16)) as u32
        );
        assert_eq!(step.pc().after.0, 0);

        config
            .ecall_cfg
            .assign_instance::<E>(instance, lk_multiplicity, step)?;

        Ok(())
    }
}
