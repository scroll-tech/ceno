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

pub struct JalConfig<E: ExtensionField> {
    pub j_insn: JInstructionConfig<E>,
    pub rd_written: UInt<E>,
}

pub struct JalCircuit<E, I>(PhantomData<(E, I)>);

/// JAL instruction circuit
///
/// Note: does not validate that next_pc is aligned by 4-byte increments, which
///   should be verified by lookup argument of the next execution step against
///   the program table
///
/// Assumption: values for valid initial program counter must lie between
///   2^20 and 2^32 - 2^20 + 2 inclusive, probably enforced by the static
///   program lookup table. If this assumption does not hold, then resulting
///   value for next_pc may not correctly wrap mod 2^32 because of the use
///   of native WitIn values for address space arithmetic.
impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for JalCircuit<E, I> {
    type InstructionConfig = JalConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<JalConfig<E>, ZKVMError> {
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let j_insn = JInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rd_written.register_expr(),
        )?;

        circuit_builder.require_equal(
            || "jal rd_written",
            rd_written.value(),
            j_insn.vm_state.pc.expr() + PC_STEP_SIZE.into(),
        )?;

        Ok(JalConfig { j_insn, rd_written })
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

        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
        config.rd_written.assign_value(instance, rd_written);

        Ok(())
    }
}
