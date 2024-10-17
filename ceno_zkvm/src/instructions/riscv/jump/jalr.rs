use std::{marker::PhantomData, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        Instruction,
        riscv::{constants::UInt, i_insn::IInstructionConfig},
    },
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, PC_STEP_SIZE};

pub struct JalrConfig<E: ExtensionField> {
    pub i_insn: IInstructionConfig<E>,
    pub rs1_read: UInt<E>,
    pub imm: WitIn,
    pub next_pc_uint: UInt<E>,
    pub overflow: WitIn,
    pub parity: WitIn,
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
        let next_pc_uint = UInt::new(|| "next_pc_uint", circuit_builder)?;
        let rs1_read = UInt::new(|| "rs1_read", circuit_builder)?; // unsigned 32-bit value
        let imm = circuit_builder.create_witin(|| "imm")?; // signed 12-bit value
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        // Next pc is obtained by rounding rs1+imm down to an even value.
        // To implement this, check three conditions:
        //  1. rs1 + imm = next_pc + overflow*2^32 + parity_bit
        //  2. next_pc low limb is even 16-bits (new table of size 2^15)
        //  3. overflow in {-1, 0, 1}, parity_bit in {0, 1}

        let overflow = circuit_builder.create_witin(|| "overflow")?;
        circuit_builder.require_zero(
            || "overflow_0_or_pm1",
            overflow.expr() * (overflow.expr() + (-1).into()) * (overflow.expr() + 1.into()),
        )?;

        let parity = circuit_builder.create_witin(|| "parity")?;
        circuit_builder.assert_bit(|| "parity_is_bit", parity.expr())?;

        circuit_builder.require_equal(
            || "rs1+imm = next_pc + overflow*2^32 + parity",
            rs1_read.value() + imm.expr(),
            next_pc_uint.value() + overflow.expr() * (1u64 << 32).into() + parity.expr(),
        )?;

        // TODO check low order limb of next_pc_uint is even
        //  Option 1: 1 witness limb_div_two, table lookup to restrict to u16, assert low limb = 2*limb_div_two
        //  Option 2: new table for "even u16" values, table lookup for low limb of next_pc_uint

        let i_insn = IInstructionConfig::construct_circuit(
            circuit_builder,
            InsnKind::JALR,
            &imm.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            true,
        )?;

        // equate next_pc witin with uint version
        circuit_builder.require_equal(
            || "next_pc_uint = next_pc",
            next_pc_uint.value(),
            i_insn.vm_state.next_pc.unwrap().expr(),
        )?;

        // write pc+4 to rd
        circuit_builder.require_equal(
            || "rd_written = pc+4",
            rd_written.value(),
            i_insn.vm_state.pc.expr() + PC_STEP_SIZE.into(),
        )?;

        Ok(JalrConfig {
            i_insn,
            rs1_read,
            imm,
            next_pc_uint,
            overflow,
            parity,
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
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        // TODO

        Ok(())
    }
}
