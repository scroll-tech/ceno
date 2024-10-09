use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::UInt, s_insn::SInstructionConfig, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

struct StoreConfig<E: ExtensionField> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    imm: UInt<E>,
}

pub struct StoreInstruction<E, I>(PhantomData<(E, I)>);

pub struct SWOp;

impl RIVInstruction for SWOp {
    const INST_KIND: InsnKind = InsnKind::SW;
}

pub type StoreWord<E> = StoreInstruction<E, SWOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for StoreInstruction<E, I> {
    type InstructionConfig = StoreConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_red", circuit_builder)?;
        let imm = UInt::new_unchecked(|| "imm", circuit_builder)?;

        let memory_addr = rs1_read.add(|| "memory_addr", circuit_builder, &imm, true)?;

        let memory_value = match I::INST_KIND {
            InsnKind::SW => rs2_read.memory_expr(),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let s_insn = SInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            memory_addr.memory_expr(),
            memory_value,
        )?;

        Ok(StoreConfig {
            s_insn,
            rs1_read,
            rs2_read,
            imm,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);

        config
            .s_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs1_read.assign_limbs(instance, rs1.as_u16_limbs());
        config.rs2_read.assign_limbs(instance, rs2.as_u16_limbs());
        config.imm.assign_value(instance, imm);

        Ok(())
    }
}
