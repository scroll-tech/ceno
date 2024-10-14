use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{
            constants::UInt, im_insn::IMInstructionConfig, s_insn::SInstructionConfig,
            RIVInstruction,
        },
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct StoreInstruction<E: ExtensionField, I: RIVInstruction> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    imm: UInt<E>,

    _phantom: PhantomData<I>,
}

pub struct SWOp;

impl RIVInstruction for SWOp {
    const INST_KIND: InsnKind = InsnKind::SW;
}

#[allow(dead_code)]
pub type StoreWord<E> = StoreInstruction<E, SWOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for StoreInstruction<E, I> {
    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(circuit_builder: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let imm = UInt::new(|| "imm", circuit_builder)?;

        let memory_addr = rs1_read.add(|| "memory_addr", circuit_builder, &imm, true)?;

        let memory_value = match I::INST_KIND {
            InsnKind::SW => rs2_read.memory_expr(),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let s_insn = SInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.value(),
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            memory_addr.memory_expr(),
            memory_value,
        )?;

        Ok(Self {
            s_insn,
            rs1_read,
            rs2_read,
            imm,
            _phantom: PhantomData,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2 = Value::new_unchecked(step.rs2().unwrap().value);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);

        self.s_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        self.rs1_read.assign_value(instance, rs1);
        self.rs2_read.assign_value(instance, rs2);
        self.imm.assign_value(instance, imm);

        Ok(())
    }
}

pub struct LoadInstruction<E: ExtensionField, I: RIVInstruction> {
    im_insn: IMInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: UInt<E>,
    memory_read: UInt<E>,

    _phantom: PhantomData<I>,
}

pub struct LWOp;

impl RIVInstruction for LWOp {
    const INST_KIND: InsnKind = InsnKind::LW;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for LoadInstruction<E, I> {
    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(circuit_builder: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let imm = UInt::new(|| "imm", circuit_builder)?;
        let memory_read = UInt::new_unchecked(|| "memory_read", circuit_builder)?;

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
            memory_addr.memory_expr(),
            memory_value,
        )?;

        Ok(Self {
            im_insn,
            rs1_read,
            memory_read,
            imm,
            _phantom: PhantomData,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = Value::new_unchecked(step.rs1().unwrap().value);
        let memory_read = Value::new_unchecked(step.memory_op().unwrap().value.before);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);

        self.im_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        self.rs1_read.assign_value(instance, rs1);
        self.memory_read.assign_value(instance, memory_read);
        self.imm.assign_value(instance, imm);

        Ok(())
    }
}
