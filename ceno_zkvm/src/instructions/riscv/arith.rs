use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{
    RIVInstruction,
    constants::{UInt, UInt32},
    r_insn::RInstructionConfig,
};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction, uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles R-Instructions that represent registers values as 2 * u16.
#[derive(Debug)]
pub struct ArithConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt32<E>,
    rs2_read: UInt32<E>,
    rd_written: UInt32<E>,
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

pub struct AddOp;
impl RIVInstruction for AddOp {
    const INST_KIND: InsnKind = InsnKind::ADD;
}
pub type AddInstruction<E> = ArithInstruction<E, AddOp>;

pub struct SubOp;
impl RIVInstruction for SubOp {
    const INST_KIND: InsnKind = InsnKind::SUB;
}
pub type SubInstruction<E> = ArithInstruction<E, SubOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = ArithConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        let (rs1_read, rs2_read, rd_written) = match I::INST_KIND {
            InsnKind::ADD => {
                // rd_written = rs1_read + rs2_read
                let rs1_read = UInt32::new_unchecked(|| "rs1_read", cb)?;
                let rs2_read = UInt32::new_unchecked(|| "rs2_read", cb)?;
                let rd_written = rs1_read.add(|| "rd_written", cb, &rs2_read, true)?;
                (rs1_read, rs2_read, rd_written)
            }

            InsnKind::SUB => {
                // rd_written + rs2_read = rs1_read
                // rd_written is the new value to be updated in register so we need to constrain its range.
                let rd_written = UInt32::new_unchecked(|| "rd_written", cb)?;
                let rs2_read = UInt32::new_unchecked(|| "rs2_read", cb)?;
                let rs1_read =
                    rs2_read
                        .clone()
                        .add(|| "rs1_read", cb, &rd_written.clone(), true)?;
                (rs1_read, rs2_read, rd_written)
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        let r_insn = RInstructionConfig::construct_circuit(
            cb,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(ArithConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rs2_value = step.rs2().unwrap().value;
        let rs2_read = Value::new_unchecked(rs2_value);
        config.rs2_read.assign(instance, &rs2_value);

        match I::INST_KIND {
            InsnKind::ADD => {
                // rs1_read + rs2_read = rd_written
                let rs1_value = step.rs1().unwrap().value;
                config.rs1_read.assign(instance, &rs1_value);
                let (ret, overflow) = rs1_value.overflowing_add(rs2_value);
                config.rd_written.assign(instance, &ret);
                config.rd_written.assign_carries(instance, &[overflow]);
            }

            InsnKind::SUB => {
                // rs1_read = rd_written + rs2_read
                let rd_written = step.rd().unwrap().value.after;
                config.rd_written.assign(instance, &rd_written);
                let (ret, overflow) = rs2_value.overflowing_add(rd_written);
                config.rs1_read.assign(instance, &ret);
                config.rs1_read.assign_carries(instance, &[overflow]);
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    fn verify<I: RIVInstruction>(
        name: &'static str,
        rs1_read: u32,
        rs2_read: u32,
        expected_rd_written: u32,
    ) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let (prefix, insn_code, outcome) = match I::INST_KIND {
            InsnKind::ADD => (
                "ADD",
                encode_rv32(InsnKind::ADD, 2, 3, 4, 0),
                rs1_read.wrapping_add(rs2_read),
            ),
            InsnKind::SUB => (
                "SUB",
                encode_rv32(InsnKind::SUB, 2, 3, 4, 0),
                rs1_read.wrapping_sub(rs2_read),
            ),
            InsnKind::MUL => (
                "MUL",
                encode_rv32(InsnKind::MUL, 2, 3, 4, 0),
                rs1_read.wrapping_mul(rs2_read),
            ),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                |cb| {
                    let config = AddInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, lkm) = ArithInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1_read,
                rs2_read,
                Change::new(0, outcome),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt32::from_const_unchecked(vec![expected_rd_written]);
        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_opcode_add() {
        verify::<AddOp>("basic", 11, 22, 33);
        verify::<AddOp>(
            "overflow",
            u32::MAX - 1,
            u32::MAX - 1,
            (u32::MAX - 1).wrapping_add(u32::MAX - 1),
        );
    }

    #[test]
    fn test_opcode_sub() {
        verify::<SubOp>("basic", 11, 2, 9);
        verify::<SubOp>("overflow", 3, 11, 3_u32.wrapping_sub(11));
    }
}
