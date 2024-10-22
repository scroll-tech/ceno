use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{RIVInstruction, constants::UInt, im_insn::IMInstructionConfig},
    },
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct LoadConfig<E: ExtensionField> {
    im_insn: IMInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: UInt<E>,
    memory_read: UInt<E>,
}

pub struct LoadInstruction<E, I>(PhantomData<(E, I)>);

pub struct LWOp;

impl RIVInstruction for LWOp {
    const INST_KIND: InsnKind = InsnKind::LW;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for LoadInstruction<E, I> {
    type InstructionConfig = LoadConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let imm = UInt::new(|| "imm", circuit_builder)?;
        let memory_read = UInt::new(|| "memory_read", circuit_builder)?;

        let (memory_addr, memory_value) = match I::INST_KIND {
            InsnKind::LW => (
                rs1_read.add(|| "memory_addr", circuit_builder, &imm, true)?,
                memory_read.register_expr(),
            ),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let im_insn = IMInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.value(),
            rs1_read.register_expr(),
            memory_read.memory_expr(),
            memory_addr.address_expr(),
            memory_value,
        )?;

        Ok(LoadConfig {
            im_insn,
            rs1_read,
            memory_read,
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
        let memory_read = Value::new(step.memory_op().unwrap().value.before, lk_multiplicity);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);

        config
            .im_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs1_read.assign_value(instance, rs1);
        config.memory_read.assign_value(instance, memory_read);
        config.imm.assign_value(instance, imm);

        Ok(())
    }
}
