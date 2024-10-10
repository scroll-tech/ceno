use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        riscv::{constants::UInt, j_insn::JInstructionConfig, RIVInstruction},
        Instruction,
    },
    set_val,
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::PC_STEP_SIZE;

use goldilocks::SmallField;

pub struct JalConfig<E: ExtensionField> {
    pub j_insn: JInstructionConfig<E>,
    pub imm: WitIn,
    pub rd_written: UInt<E>,
}

pub struct JalCircuit<E, I>(PhantomData<(E, I)>);

/// JAL instruction circuit
/// Note: does not validate that next_pc is aligned by 4-byte increments, which
///   should be verified by lookup argument of the next execution step against
///   the program table
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
        // immediate needs to be interpreted from signed value to corresponding
        // signed element in BaseField, e.g. -1 maps to p-1 mod p
        let imm = circuit_builder.create_witin(|| "imm")?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let j_insn = JInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.expr(),
            rd_written.register_expr(),
        )?;

        circuit_builder.require_equal(
            || "jal next_pc",
            j_insn.vm_state.next_pc.unwrap().expr(),
            j_insn.vm_state.pc.expr() + imm.expr(),
        )?;

        circuit_builder.require_equal(
            || "jal rd_written",
            rd_written.value(),
            j_insn.vm_state.pc.expr() + PC_STEP_SIZE.into(),
        )?;

        Ok(JalConfig {
            j_insn,
            imm,
            rd_written,
        })
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

        // negative signed immediate -val is represented as p-val for WitIn
        // over base field with modulus p
        let imm_signed = step.insn().imm_or_funct7() as i32;
        let imm = if imm_signed < 0 {
            E::BaseField::MODULUS_U64.wrapping_add_signed(imm_signed as i64)
        } else {
            imm_signed as u64
        };
        set_val!(instance, config.imm, imm);

        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
        config.rd_written.assign_value(instance, rd_written);

        Ok(())
    }
}
