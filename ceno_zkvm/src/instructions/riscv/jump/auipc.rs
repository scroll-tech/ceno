use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::InsnKind;
use ff_ext::ExtensionField;

use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        Instruction,
        riscv::{constants::UInt, u_insn::UInstructionConfig},
    },
    set_val,
    witness::LkMultiplicity,
};

pub struct AuipcConfig<E: ExtensionField> {
    pub u_insn: UInstructionConfig<E>,
    pub imm: WitIn,
    pub overflow_bit: WitIn,
    pub rd_written: UInt<E>,
}

pub struct AuipcInstruction<E>(PhantomData<E>);

/// AUIPC instruction circuit
impl<E: ExtensionField> Instruction<E> for AuipcInstruction<E> {
    type InstructionConfig = AuipcConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::AUIPC)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<AuipcConfig<E>, ZKVMError> {
        let imm = circuit_builder.create_witin(|| "imm");
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let u_insn = UInstructionConfig::construct_circuit(
            circuit_builder,
            InsnKind::AUIPC,
            &imm.expr(),
            rd_written.register_expr(),
        )?;

        let overflow_bit = circuit_builder.create_witin(|| "overflow_bit");
        circuit_builder.assert_bit(|| "is_bit", overflow_bit.expr())?;

        // assert: imm + pc = rd_written + overflow_bit * 2^32
        // valid formulation of mod 2^32 arithmetic because:
        // - imm and pc are constrained to 4 bytes by instruction table lookup
        // - rd_written is constrained to 4 bytes by UInt checked limbs
        circuit_builder.require_equal(
            || "imm+pc = rd_written+2^32*overflow",
            imm.expr() + u_insn.vm_state.pc.expr(),
            rd_written.value() + overflow_bit.expr() * (1u64 << 32),
        )?;

        Ok(AuipcConfig {
            u_insn,
            imm,
            overflow_bit,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        let pc: u32 = step.pc().before.0;
        let imm: u32 = step.insn().imm_or_funct7();
        let (sum, overflow) = pc.overflowing_add(imm);

        set_val!(instance, config.imm, imm as u64);
        set_val!(instance, config.overflow_bit, overflow as u64);

        let sum_limbs = Value::new(sum, lk_multiplicity);
        config.rd_written.assign_value(instance, sum_limbs);

        config
            .u_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}
