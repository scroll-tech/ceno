use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::ToExpr,
    instructions::{
        riscv::{constants::UInt, j_insn::JInstructionConfig, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::PC_STEP_SIZE;

pub struct JalInstruction<E, I>(PhantomData<(E, I)>);

pub struct InstructionConfig<E: ExtensionField> {
    pub j_insn: JInstructionConfig<E>,
    pub rd_written: UInt<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for JalInstruction<E, I> {
    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    type InstructionConfig = InstructionConfig<E>;

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        let rd_written = UInt::new_unchecked(|| "rd_limbs", circuit_builder)?;

        let j_insn = JInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rd_written.register_expr(),
        )?;

        // constrain next_pc
        let jump_delta = j_insn.imm.expr() * 2.into();
        circuit_builder.require_equal(
            || "jump next_pc",
            j_insn.vm_state.next_pc.unwrap().expr(),
            j_insn.vm_state.pc.expr() + jump_delta,
        )?;

        // constrain return address written to rd
        let return_addr = j_insn.vm_state.pc.expr() + PC_STEP_SIZE.into();
        circuit_builder.require_equal(|| "jump rd", rd_written.value(), return_addr)?;

        Ok(InstructionConfig { j_insn, rd_written })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .j_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rd = Value::new_unchecked(step.rd().unwrap().value.after);
        config.rd_written.assign_limbs(instance, rd.as_u16_limbs());

        Ok(())
    }
}
