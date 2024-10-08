use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        riscv::{constants::UInt, constants::UInt8, s_insn::SInstructionConfig, RIVInstruction},
        Instruction,
    },
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::mem::MaybeUninit;

// `sw` opcode
struct SWConfig<E: ExtensionField> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    imm: UInt<E>,
}
pub struct SWOp;

impl RIVInstruction for SWOp {
    const INST_KIND: InsnKind = InsnKind::SW;
}

impl<E: ExtensionField> Instruction<E> for SWOp {
    type InstructionConfig = SWConfig<E>;

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_red", circuit_builder)?;
        let imm = UInt::new_unchecked(|| "imm", circuit_builder)?;

        // TODO: feels like this is the responsibility of the s_insn
        let memory_addr = rs1_read.add(|| "memory_addr", circuit_builder, &imm, true)?;

        let s_insn = SInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            &imm.value(),
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            memory_addr.memory_expr(),
        )?;

        Ok(SWConfig {
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
        config.rs1_read.assign_limbs(instance, rs1.u16_fields());
        config.rs2_read.assign_limbs(instance, rs2.u16_fields());
        config.imm.assign_value(instance, imm);

        Ok(())
    }
}

// `sb` opcode
struct SBConfig<E: ExtensionField> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    // one byte per limb
    imm: UInt8<E>,
}
pub struct SBOp;

impl RIVInstruction for SBOp {
    const INST_KIND: InsnKind = InsnKind::SB;
}

impl<E: ExtensionField> Instruction<E> for SBOp {
    type InstructionConfig = SBConfig<E>;

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let imm = UInt8::new_unchecked(|| "imm", circuit_builder)?;
        

        let imm_uint16 = UInt::<E>::from_u8_limbs(&imm).expect("converting to u8 limbs type failed");

        // TODO: make imm_uint16's first limb == imm.limbs[0] and other limbs are zeros
        // so that take first byte of imm to calculate memory addr
        let memory_addr = rs1_read.add(|| "memory_addr", circuit_builder, &imm_uint16, true)?;

        let s_insn = SInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            &imm.value(),
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            memory_addr.memory_expr(),
        )?;

        Ok(SBConfig {
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
        config.rs1_read.assign_limbs(instance, rs1.u16_fields());
        config.rs2_read.assign_limbs(instance, rs2.u16_fields());
        config.imm.assign_value(instance, imm);

        Ok(())
    }
}
