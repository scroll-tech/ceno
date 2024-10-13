use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::ToExpr,
    instructions::{
        riscv::{
            constants::{UInt, UInt8},
            im_insn::IMInstructionConfig,
            s_insn::SInstructionConfig,
            RIVInstruction,
        },
        Instruction,
    },
    witness::LkMultiplicity,
    ROMType, Value,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct StoreConfig<E: ExtensionField> {
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

#[allow(dead_code)]
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
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let imm = UInt::new_unchecked(|| "imm", circuit_builder)?;

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
        let imm = Value::new_unchecked(step.insn().imm_or_funct7());

        config
            .s_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs1_read.assign_value(instance, rs1);
        config.rs2_read.assign_value(instance, rs2);
        config.imm.assign_value(instance, imm);

        Ok(())
    }
}

// store_byte
pub struct StoreByteConfig<E: ExtensionField> {
    s_insn: SInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    imm: UInt<E>,

    // aligned memory word value before write
    memory_value_old: UInt8<E>,
    // aligned memory word value after write
    memory_value_new: UInt8<E>,
    // 4 selectors indicate which byte is selected to update
    // e.g. [ 0, 1, 0, 0 ] means the second byte is updated.
    memory_byte_selectors: UInt8<E>,
}

pub struct StoreByteInstruction<E, I>(PhantomData<(E, I)>);

pub struct SBOp;

impl RIVInstruction for SBOp {
    const INST_KIND: InsnKind = InsnKind::SB;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for StoreByteInstruction<E, I> {
    type InstructionConfig = StoreByteConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let imm = UInt::new_unchecked(|| "imm", circuit_builder)?;

        let memory_addr = rs1_read.add(|| "memory_addr", circuit_builder, &imm, true)?;
        let memory_addr_u8 = UInt::to_u8_limbs(circuit_builder, memory_addr.clone());
        let addr_offset = UInt8::new_unchecked(|| "addr_offset", circuit_builder)?;
        let memory_addr_limb0 =
            UInt8::from_exprs_unchecked(vec![memory_addr_u8.expr()[0].clone()])?;
        let const_num_3 = UInt8::from_const_unchecked(vec![3u64, 0, 0, 0]);

        let aligned_memory_addr = UInt8::new_unchecked(|| "aligned_memory_addr", circuit_builder)?;

        // constrain addr_off = addr[0] & 0x03
        UInt8::logic(
            circuit_builder,
            ROMType::And,
            &memory_addr_limb0,
            &const_num_3,
            &addr_offset,
        )?;

        // constrain addr[0] = aligned_addr[0] + addr_off
        let aligned_memory_addr_limb0 =
            UInt8::from_exprs_unchecked(vec![aligned_memory_addr.expr()[0].clone()])?;

        let addr_sum_to_check = addr_offset.add(
            || "addr_offset + aligned_addr[0]",
            circuit_builder,
            &aligned_memory_addr_limb0,
            true,
        )?;
        memory_addr_limb0.require_equal(
            || "addr[0] = aligned_addr[0] + addr_off",
            circuit_builder,
            &addr_sum_to_check,
        )?;

        // byte selecting indicator
        let memory_byte_selectors =
            UInt8::new_unchecked(|| "memory_byte_selectors", circuit_builder)?;
        // constrain: each selector are bool
        let byte_selectors = memory_byte_selectors.expr();

        let const_num_1 = UInt8::from_const_unchecked(vec![1u64, 0, 0, 0]).expr()[0].clone();
        let const_num_zero = UInt8::from_const_unchecked(vec![0u64, 0, 0, 0]);

        let mut selectors_sum = const_num_zero.expr()[0].clone();
        for idx in 0..4 {
            let sel = byte_selectors[idx].clone();
            // let sel_uint = UInt8::from_exprs_unchecked(vec![sel])?;
            circuit_builder.require_zero(
                || " sel * (1 - sel) = 0",
                sel.clone() * (const_num_1.clone() - sel.clone()),
            )?;
            selectors_sum = selectors_sum + sel;
        }

        // constrain: sum of selectors equals 1.
        circuit_builder.require_one(|| "selectors_sum = 1", selectors_sum)?;

        // aligned memory word value before write
        let memory_value_old = UInt8::new_unchecked(|| "memory_value_old", circuit_builder)?;
        // aligned memory word value after write
        let memory_value_new = UInt8::new_unchecked(|| "memory_value_old", circuit_builder)?;

        // memory_value_old transition to memory_value_new by replacing one byte.
        // memory_value_new[i] = memory_value_old[i] * (1 - byte_selectors[i]) + rs2[0] * byte_selectors[i]
        let old_value_bytes = memory_value_old.expr();
        let new_value_bytes = memory_value_new.expr();

        let rs2_first_byte = UInt::to_u8_limbs(circuit_builder, rs2_read.clone()).expr()[0].clone();

        for idx in 0..4 {
            let sel = byte_selectors[idx].clone();
            // calculate old_mem_value[i] * (1 - byte_selectors[i]
            let old_mem_val = old_value_bytes[idx].clone() * (const_num_1.clone() - sel.clone());

            circuit_builder.require_equal(|| "new_mem_value[i] = old_mem_value[i] * (1 - byte_selectors[i]) + rs2[0] * byte_selectors[i]", 
            new_value_bytes[idx].clone(), 
            old_mem_val + rs2_first_byte.clone() * sel)?;
        }

        let memory_value = match I::INST_KIND {
            InsnKind::SB => rs2_read.memory_expr(),
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

        Ok(StoreByteConfig {
            s_insn,
            rs1_read,
            rs2_read,
            imm,
            memory_value_old,
            memory_value_new,
            memory_byte_selectors,
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
        let imm = Value::new_unchecked(step.insn().imm_or_funct7());

        config
            .s_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs1_read.assign_value(instance, rs1);
        config.rs2_read.assign_value(instance, rs2);
        config.imm.assign_value(instance, imm);

        // TODO: assign other fields

        Ok(())
    }
}

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
        let imm = UInt::new_unchecked(|| "imm", circuit_builder)?;
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
        let memory_read = Value::new_unchecked(step.memory_op().unwrap().value.before);
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
