use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::UInt, u_insn::UInstructionConfig, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};

pub struct LuiConfig<E: ExtensionField> {
    pub u_insn: UInstructionConfig<E>,
    pub rd_written: UInt<E>,
}

pub struct LuiCircuit<E, I>(PhantomData<(E, I)>);

/// LUI instruction circuit
impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for LuiCircuit<E, I> {
    type InstructionConfig = LuiConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<LuiConfig<E>, ZKVMError> {
        let rd_written = UInt::new(|| "rd_limbs", circuit_builder)?;

        // rd_written = imm, so just enforce that U-type immediate from program
        // table is equal to rd_written value
        let u_insn = UInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &rd_written.value(), // instruction immediate for program table lookup
            rd_written.register_expr(),
        )?;

        Ok(LuiConfig { u_insn, rd_written })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .u_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rd = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
        config.rd_written.assign_limbs(instance, rd.as_u16_limbs());

        Ok(())
    }
}
