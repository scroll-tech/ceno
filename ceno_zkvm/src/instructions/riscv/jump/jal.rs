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
    pub pc_uint: UInt<E>,
    pub next_pc_uint: UInt<E>,
    pub imm: UInt<E>,
    pub rd_written: UInt<E>,
}

pub struct JalCircuit<E, I>(PhantomData<(E, I)>);

/// JAL instruction circuit
/// NOTE: does not validate that next_pc is aligned by 4-byte increments, which
///   should be verified by lookup argument of the next execution step against
///   the program table
impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for JalCircuit<E, I> {
    type InstructionConfig = JalConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<JalConfig<E>, ZKVMError> {
        // TODO determine whether any of these UInt values can be constructed
        //   using UInt::new_unchecked
        let pc_uint = UInt::new(|| "next_pc_limbs", circuit_builder)?;
        let imm = UInt::new(|| "imm_limbs", circuit_builder)?;
        let next_pc_uint = pc_uint.add(|| "pc_uint + imm", circuit_builder, &imm, true)?;
        let rd_written =
            pc_uint.add_const(|| "rd_written", circuit_builder, PC_STEP_SIZE.into(), true)?;

        let j_insn = JInstructionConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.value(),
            rd_written.register_expr(),
        )?;

        // constrain next_pc UInt to equal internal WitIn value
        circuit_builder.require_equal(
            || "next_pc_limbs",
            next_pc_uint.value(),
            j_insn.vm_state.next_pc.unwrap().expr(),
        )?;

        Ok(JalConfig {
            j_insn,
            pc_uint,
            next_pc_uint,
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

        // TODO determine whether any of these Value objects can be constructed
        //  using Value::new_unchecked
        let pc = Value::new(step.pc().before.0, lk_multiplicity);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);
        let pc_step = Value::new_unchecked(PC_STEP_SIZE as u32);

        config.pc_uint.assign_limbs(instance, pc.as_u16_limbs());
        config.imm.assign_limbs(instance, imm.as_u16_limbs());

        let result = pc.add(&imm, lk_multiplicity, true);
        config.next_pc_uint.assign_add_outcome(instance, &result);

        let result = pc.add(&pc_step, lk_multiplicity, true);
        config.rd_written.assign_add_outcome(instance, &result);

        Ok(())
    }
}
