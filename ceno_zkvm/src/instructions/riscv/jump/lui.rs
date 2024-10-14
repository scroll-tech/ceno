use std::mem::MaybeUninit;

use ceno_emul::InsnKind;
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::UInt, u_insn::UInstructionConfig},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};

pub struct LuiInstruction<E: ExtensionField> {
    pub u_insn: UInstructionConfig<E>,
    pub rd_written: UInt<E>,
}

/// LUI instruction circuit
impl<E: ExtensionField> Instruction<E> for LuiInstruction<E> {
    fn name() -> String {
        format!("{:?}", InsnKind::LUI)
    }

    fn construct_circuit(circuit_builder: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        let rd_written = UInt::new(|| "rd_limbs", circuit_builder)?;

        // rd_written = imm, so just enforce that U-type immediate from program
        // table is equal to rd_written value
        let u_insn = UInstructionConfig::construct_circuit(
            circuit_builder,
            InsnKind::LUI,
            &rd_written.value(), // instruction immediate for program table lookup
            rd_written.register_expr(),
        )?;

        Ok(Self { u_insn, rd_written })
    }

    fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        self.u_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rd = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
        self.rd_written.assign_limbs(instance, rd.as_u16_limbs());

        Ok(())
    }
}
