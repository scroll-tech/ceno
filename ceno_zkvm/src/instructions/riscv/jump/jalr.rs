use std::{marker::PhantomData, mem::MaybeUninit};

use ff::Field;
use ff_ext::ExtensionField;

use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        Instruction,
        riscv::{constants::UInt, i_insn::IInstructionConfig, insn_base::MemAddr},
    },
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, PC_STEP_SIZE};

pub struct JalrConfig<E: ExtensionField> {
    pub i_insn: IInstructionConfig<E>,
    pub rs1_read: UInt<E>,
    pub imm: WitIn,
    pub next_pc_addr: MemAddr<E>,
    pub overflow: WitIn,
    pub rd_written: UInt<E>,
}

pub struct JalrInstruction<E>(PhantomData<E>);

/// JALR instruction circuit
/// NOTE: does not validate that next_pc is aligned by 4-byte increments, which
///   should be verified by lookup argument of the next execution step against
///   the program table
impl<E: ExtensionField> Instruction<E> for JalrInstruction<E> {
    type InstructionConfig = JalrConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::JALR)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<JalrConfig<E>, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?; // unsigned 32-bit value
        let imm = circuit_builder.create_witin(|| "imm"); // signed 12-bit value
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let i_insn = IInstructionConfig::construct_circuit(
            circuit_builder,
            InsnKind::JALR,
            &imm.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            true,
        )?;

        // Next pc is obtained by rounding rs1+imm down to an even value.
        // To implement this, check three conditions:
        //  1. rs1 + imm = next_pc_addr + overflow*2^32
        //  2. overflow in {-1, 0, 1}
        //  3. next_pc = next_pc_addr aligned to even value (round down)

        let next_pc_addr = MemAddr::<E>::construct_unaligned(circuit_builder)?;
        let overflow = circuit_builder.create_witin(|| "overflow");

        circuit_builder.require_equal(
            || "rs1+imm = next_pc_unrounded + overflow*2^32",
            rs1_read.value() + imm.expr(),
            next_pc_addr.expr_unaligned() + overflow.expr() * (1u64 << 32),
        )?;

        circuit_builder.require_zero(
            || "overflow_0_or_pm1",
            overflow.expr() * (overflow.expr() - 1) * (overflow.expr() + 1),
        )?;

        circuit_builder.require_equal(
            || "next_pc_addr = next_pc",
            next_pc_addr.expr_align2(),
            i_insn.vm_state.next_pc.unwrap().expr(),
        )?;

        // write pc+4 to rd
        circuit_builder.require_equal(
            || "rd_written = pc+4",
            rd_written.value(),
            i_insn.vm_state.pc.expr() + PC_STEP_SIZE,
        )?;

        Ok(JalrConfig {
            i_insn,
            rs1_read,
            imm,
            next_pc_addr,
            overflow,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        let insn = step.insn();

        let rs1 = step.rs1().unwrap().value;
        let imm: i32 = insn.imm_or_funct7() as i32;
        let rd = step.rd().unwrap().value.after;

        let (sum, overflowing) = rs1.overflowing_add_signed(imm);

        config
            .rs1_read
            .assign_value(instance, Value::new_unchecked(rs1));
        config
            .rd_written
            .assign_value(instance, Value::new(rd, lk_multiplicity));

        let imm_field = InsnRecord::imm_or_funct7_field::<E::BaseField>(&insn);
        set_val!(instance, config.imm, imm_field);

        config
            .next_pc_addr
            .assign_instance(instance, lk_multiplicity, sum)?;
        let overflow: E::BaseField = match (overflowing, imm < 0) {
            (false, _) => E::BaseField::ZERO,
            (true, false) => E::BaseField::ONE,
            (true, true) => -E::BaseField::ONE,
        };
        set_val!(instance, config.overflow, overflow);

        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}
