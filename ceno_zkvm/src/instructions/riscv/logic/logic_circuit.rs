//! The circuit implementation of logic instructions.

use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::UInt8, r_insn::RInstructionConfig},
        Instruction,
    },
    uint::Value,
    witness::LkMultiplicity,
    ROMType,
};
use core::mem::MaybeUninit;

/// This trait defines a logic instruction, connecting an instruction type to a lookup table.
pub trait LogicOp {
    const INST_KIND: InsnKind;
    const ROM_TYPE: ROMType;
}

/// The Instruction circuit for a given LogicOp.
pub struct LogicInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: LogicOp> Instruction<E> for LogicInstruction<E, I> {
    type InstructionConfig = LogicConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        let config = LogicConfig::construct_circuit(cb, I::INST_KIND)?;

        // Constrain the registers based on the given lookup table.
        UInt8::logic(
            cb,
            I::ROM_TYPE,
            &config.rs1_read,
            &config.rs2_read,
            &config.rd_written,
        )?;

        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.assign_instance(instance, lk_multiplicity, step)
    }
}

/// This config implements R-Instructions that represent registers values as 4 * u8.
/// Non-generic code shared by several circuits.
#[derive(Debug)]
pub struct LogicConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt8<E>,
    rs2_read: UInt8<E>,
    rd_written: UInt8<E>,
}

impl<E: ExtensionField> LogicConfig<E> {
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
    ) -> Result<Self, ZKVMError> {
        let rs1_read = UInt8::new_unchecked(|| "rs1_read", cb)?;
        let rs2_read = UInt8::new_unchecked(|| "rs2_read", cb)?;
        let rd_written = UInt8::new_unchecked(|| "rd_written", cb)?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            cb,
            insn_kind,
            &rs1_read,
            &rs2_read,
            &rd_written,
        )?;

        Ok(Self {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        self.rs1_read.assign_limbs(instance, rs1_read.u16_fields());

        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        self.rs2_read.assign_limbs(instance, rs2_read.u16_fields());

        let rd_written = Value::new_unchecked(step.rd().unwrap().value.after);
        self.rd_written
            .assign_limbs(instance, rd_written.u16_fields());

        Ok(())
    }
}
