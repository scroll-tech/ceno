//! The circuit implementation of logic instructions.

use core::mem::MaybeUninit;
use ff_ext::ExtensionField;
use std::marker::PhantomData;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::UInt8, i_insn::IInstructionConfig},
        Instruction,
    },
    tables::OpsTable,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};

/// This trait defines a logic instruction, connecting an instruction type to a lookup table.
pub trait LogicOp {
    const INST_KIND: InsnKind;
    type OpsTable: OpsTable;
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
            I::OpsTable::ROM_TYPE,
            &config.rs1_read,
            &config.imm,
            &config.rd_written,
        )?;

        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        UInt8::<E>::logic_assign::<I::OpsTable>(
            lkm,
            step.rs1().unwrap().value as u64,
            step.insn().imm_or_funct7().into(),
        );

        config.assign_instance(instance, lkm, step)
    }
}

/// This config implements R-Instructions that represent registers values as 4 * u8.
/// Non-generic code shared by several circuits.
#[derive(Debug)]
pub struct LogicConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt8<E>,
    pub(crate) rd_written: UInt8<E>,
    imm: UInt8<E>,
}

impl<E: ExtensionField> LogicConfig<E> {
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
    ) -> Result<Self, ZKVMError> {
        let rs1_read = UInt8::new_unchecked(|| "rs1_read", cb)?;
        let rd_written = UInt8::new_unchecked(|| "rd_written", cb)?;
        let imm = UInt8::new(|| "imm", cb)?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            insn_kind,
            &imm.value(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(Self {
            i_insn,
            rs1_read,
            imm,
            rd_written,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.i_insn.assign_instance(instance, lkm, step)?;

        let rs1_read = split_to_u8(step.rs1().unwrap().value);
        self.rs1_read.assign_limbs(instance, &rs1_read);

        let imm = split_to_u8::<u16>(step.insn().imm_or_funct7());
        self.imm.assign_limbs(instance, &imm);

        let rd_written = split_to_u8(step.rd().unwrap().value.after);
        self.rd_written.assign_limbs(instance, &rd_written);

        Ok(())
    }
}
