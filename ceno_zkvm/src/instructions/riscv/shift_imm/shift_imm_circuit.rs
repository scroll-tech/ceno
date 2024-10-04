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

    rs1: UInt<E>,
    imm: UInt<E>,
    pub(crate) rd_written: UInt<E>,
    remainder: UInt<E>,
    rd_imm_mul: UInt<E>,
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
        let mut rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        // Note: `imm` is set to 2**imm (upto 32 bit) just for SRLI for efficient verification
        // Goal is to constrain:
        // rs1 == rd_written * imm + remainder
        let remainder = UInt::new(|| "remainder", circuit_builder)?;
        let (rs1, rd_imm_mul) = rd_written.mul_add(
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
            rs1.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(InstructionConfig {
            i_insn,
            imm,
            rd_written,
            remainder,
            rd_imm_mul,
            rs1,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);

        let (remainder, imm) = {
            let rs1_read = step.rs1().unwrap().value;
            let imm = step.insn().imm_or_funct7();
            (
                Value::new(rs1_read % imm, lk_multiplicity),
                Value::new(imm, lk_multiplicity),
            )
        };

        let (rs1, rd_imm_mul) = rd_written.mul_add(&imm, &remainder, lk_multiplicity, true);
        config.rd_imm_mul.assign_limb_with_carry_auxiliary(
            instance,
            lk_multiplicity,
            &rd_imm_mul,
        )?;

        config.rs1.assign_limb_with_carry(instance, &rs1);
        config.imm.assign_value(instance, imm);
        config.rd_written.assign_value(instance, rd_written);
        config.remainder.assign_value(instance, remainder);

        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}
