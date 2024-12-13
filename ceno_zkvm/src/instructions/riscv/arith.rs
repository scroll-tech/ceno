use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{RIVInstruction, constants::UInt, r_insn::RInstructionConfig};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction, uint::Value,
    witness::LkMultiplicity,
};

/// This config handles R-Instructions that represent registers values as 2 * u16.
#[derive(Debug)]
pub struct ArithConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UInt<E>,
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

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let (rs1_read, rs2_read, rd_written) = match I::INST_KIND {
            InsnKind::ADD => {
                // rd_written = rs1_read + rs2_read
                let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
                let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
                let rd_written = rs1_read.add(|| "rd_written", circuit_builder, &rs2_read, true)?;
                (rs1_read, rs2_read, rd_written)
            }

            InsnKind::SUB => {
                // rd_written + rs2_read = rs1_read
                // rd_written is the new value to be updated in register so we need to constrain its range.
                let rd_written = UInt::new(|| "rd_written", circuit_builder)?;
                let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
                let rs1_read = rs2_read.clone().add(
                    || "rs1_read",
                    circuit_builder,
                    &rd_written.clone(),
                    true,
                )?;
                (rs1_read, rs2_read, rd_written)
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        let r_insn = RInstructionConfig::construct_circuit(
            circuit_builder,
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
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        config
            .rs2_read
            .assign_limbs(instance, rs2_read.as_u16_limbs());

        match I::INST_KIND {
            InsnKind::ADD => {
                // rs1_read + rs2_read = rd_written
                let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
                config
                    .rs1_read
                    .assign_limbs(instance, rs1_read.as_u16_limbs());
                let result = rs1_read.add(&rs2_read, lk_multiplicity, true);
                config.rd_written.assign_carries(instance, &result.carries);
            }

            InsnKind::SUB => {
                // rs1_read = rd_written + rs2_read
                let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
                config
                    .rd_written
                    .assign_limbs(instance, rd_written.as_u16_limbs());
                let result = rs2_read.add(&rd_written, lk_multiplicity, true);
                config.rs1_read.assign_carries(instance, &result.carries);
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
        chip_handler::test::DebugIndex,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    #[test]
    fn test_opcode_add() {
        verify::<AddOp>("basic", 11, 2);
        verify::<AddOp>("0 + 0", 0, 0);
        verify::<AddOp>("0 + 1", 0, 1);
        verify::<AddOp>("u16::MAX", u16::MAX as u32, 2);
        verify::<AddOp>("overflow: u32::MAX", u32::MAX - 1, 2);
        verify::<AddOp>("overflow: u32::MAX x 2", u32::MAX - 1, u32::MAX - 1);
    }

    #[test]
    fn test_opcode_sub() {
        verify::<SubOp>("basic", 11, 2);
        verify::<SubOp>("0 - 0", 0, 0);
        verify::<SubOp>("1 - 0", 1, 0);
        verify::<SubOp>("1 - 1", 1, 1);
        verify::<SubOp>("underflow", 3, 11);
    }

    fn verify<I: RIVInstruction>(name: &'static str, rs1: u32, rs2: u32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("{:?}_({name})", I::INST_KIND),
                |cb| Ok(ArithInstruction::<GoldilocksExt2, I>::construct_circuit(cb)),
            )
            .unwrap()
            .unwrap();

        let outcome = match I::INST_KIND {
            InsnKind::ADD => rs1.wrapping_add(rs2),
            InsnKind::SUB => rs1.wrapping_sub(rs2),
            _ => unreachable!("Unsupported instruction kind"),
        };

        // values assignment
        let insn_code = encode_rv32(I::INST_KIND, 2, 3, 4, 0);
        let (raw_witin, lkm) = ArithInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1,
                rs2,
                Change::new(0, outcome),
                0,
            )],
        )
        .unwrap();

        // verify rd_written
        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(outcome).as_u16_limbs().to_vec());
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            expected_rd_written.value(),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
