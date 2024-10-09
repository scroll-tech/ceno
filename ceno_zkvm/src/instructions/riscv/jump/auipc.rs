use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::ToExpr,
    instructions::{
        riscv::{constants::UInt, u_insn::UInstructionConfig, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};

pub struct AuipcConfig<E: ExtensionField> {
    pub u_insn: UInstructionConfig<E>,
    pub pc_uint: UInt<E>,
    pub imm: UInt<E>,
    pub rd_written: UInt<E>,
}

pub struct AuipcCircuit<E, I>(PhantomData<(E, I)>);

/// AUIPC instruction circuit
impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for AuipcCircuit<E, I> {
    type InstructionConfig = AuipcConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<AuipcConfig<E>, ZKVMError> {
        let pc_uint = UInt::new(|| "pc_limbs", circuit_builder)?;
        let imm = UInt::new(|| "imm", circuit_builder)?;
        let rd_written = pc_uint.add(|| "pc_limbs + imm", circuit_builder, &imm, true)?;

        let u_insn = UInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.value(),
            rd_written.register_expr(),
        )?;

        // constrain pc UInt to equal UInstruction pc WitIn
        // A separate UInt representation is needed here because the AUIPC
        // instruction does mod 2^32 arithmetic on pc
        circuit_builder.require_equal(
            || "auipc pc_limbs = pc",
            pc_uint.value(),
            u_insn.vm_state.pc.expr(),
        )?;

        Ok(AuipcConfig {
            u_insn,
            pc_uint,
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
        let pc = Value::new(step.pc().before.0, lk_multiplicity);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);

        let sum_pc_imm = pc.add(&imm, lk_multiplicity, true);

        config
            .u_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        config.pc_uint.assign_value(instance, pc);
        config.imm.assign_value(instance, imm);

        config.rd_written.assign_add_outcome(instance, &sum_pc_imm);

        Ok(())
    }
}
