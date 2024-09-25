use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::UInt, i_insn::IInstructionConfig, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};

pub struct ShiftImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct InstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    imm: UInt<E>,
    rd_written: UInt<E>,
    remainder: UInt<E>,
    rd_imm_mul: UInt<E>,
    rd_imm_rem_add: UInt<E>,
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftImmInstruction<E, I> {
    type InstructionConfig = InstructionConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let mut imm = UInt::new(|| "imm", circuit_builder)?;
        let mut rd_written = UInt::new_unchecked(|| "rd_written", circuit_builder)?;

        // Note: `imm` is set to 2**imm (upto 32 bit) just for SRLI for efficient verification
        // Goal is to constrain:
        // rs1_read == rd_written * imm + remainder
        let remainder = UInt::new(|| "remainder", circuit_builder)?;
        let (rd_imm_mul, rd_imm_rem_add) = rd_written.mul_add(
            || "rd_written * imm +remainder ",
            circuit_builder,
            &mut imm,
            &remainder,
            true,
        )?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.value(),
            rd_imm_rem_add.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(InstructionConfig {
            i_insn,
            imm,
            rd_written,
            remainder,
            rd_imm_mul,
            rd_imm_rem_add,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // We need to calculate result and remainder.
        let rs1_read = step.rs1().unwrap().value;
        let rd_written = step.rd().unwrap().value.after;
        let imm = step.insn().imm_or_funct7();
        let result = rs1_read.wrapping_div(imm);
        let remainder = rs1_read.wrapping_sub(result * imm);
        assert_eq!(result, rd_written, "SRLI: result mismatch");

        // Assignment.
        let rd_written = Value::new_unchecked(rd_written);
        let imm = Value::new(imm, lk_multiplicity);
        let remainder = Value::new(remainder, lk_multiplicity);

        let rd_imm_mul = rd_written.mul(&imm, lk_multiplicity, true);
        let rd_imm = Value::from_limb_slice_unchecked(&rd_imm_mul.0);
        config
            .rd_imm_mul
            .assign_limb_with_carry(instance, &rd_imm_mul);

        let rd_imm_rem_add = rd_imm.add(&remainder, lk_multiplicity, true);
        debug_assert_eq!(
            Value::<u32>::from_limb_slice_unchecked(&rd_imm_rem_add.0).as_u64(),
            rs1_read as u64,
            "SRLI: rd_imm_rem_add mismatch"
        );
        config
            .rd_imm_rem_add
            .assign_limb_with_carry(instance, &rd_imm_rem_add);

        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.imm.assign_value(instance, imm);
        config.rd_written.assign_value(instance, rd_written);
        config.remainder.assign_value(instance, remainder);

        Ok(())
    }
}
