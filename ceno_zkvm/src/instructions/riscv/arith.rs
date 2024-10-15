use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{constants::UInt, r_insn::RInstructionConfig, RIVInstruction};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::Instruction,
    uint::{Value, ValueMul},
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

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

pub struct MulOp;
impl RIVInstruction for MulOp {
    const INST_KIND: InsnKind = InsnKind::MUL;
}
pub type MulInstruction<E> = ArithInstruction<E, MulOp>;

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

            InsnKind::MUL => {
                // rs1_read * rs2_read = rd_written
                let mut rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
                let mut rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
                let rd_written =
                    rs1_read.mul(|| "rd_written", circuit_builder, &mut rs2_read, true)?;
                (rs1_read, rs2_read, rd_written)
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
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
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
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

            InsnKind::MUL => {
                // rs1_read * rs2_read = rd_written
                let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
                let rd_written = Value::new_unchecked(step.rd().unwrap().value.after);

                config
                    .rs1_read
                    .assign_limbs(instance, rs1_read.as_u16_limbs());

                let result = rs1_read.mul(&rs2_read, lk_multiplicity, true);

                config.rd_written.assign_mul_outcome(
                    instance,
                    lk_multiplicity,
                    &ValueMul {
                        limbs: rd_written.limbs.to_vec(),
                        carries: result.carries,
                        max_carry_value: result.max_carry_value,
                    },
                )?;
            }

            _ => unreachable!("Unsupported instruction kind"),
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MockProver, MOCK_PC_ADD, MOCK_PC_MUL, MOCK_PC_SUB, MOCK_PROGRAM},
    };

    #[test]
    fn test_opcode_add() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "add",
                |cb| {
                    let config = AddInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_ADD,
                MOCK_PROGRAM[0],
                11,
                0xfffffffe,
                Change::new(0, 11_u32.wrapping_add(0xfffffffe)),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt::from_const_unchecked(
            Value::new_unchecked(11_u32.wrapping_add(0xfffffffe))
                .as_u16_limbs()
                .to_vec(),
        );

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    fn test_opcode_add_overflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "add",
                |cb| {
                    let config = AddInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = AddInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_ADD,
                MOCK_PROGRAM[0],
                u32::MAX - 1,
                u32::MAX - 1,
                Change::new(0, (u32::MAX - 1).wrapping_add(u32::MAX - 1)),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt::from_const_unchecked(
            Value::new_unchecked((u32::MAX - 1).wrapping_add(u32::MAX - 1))
                .as_u16_limbs()
                .to_vec(),
        );

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    fn test_opcode_sub() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sub",
                |cb| {
                    let config = SubInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = SubInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SUB,
                MOCK_PROGRAM[1],
                11,
                2,
                Change::new(0, 11_u32.wrapping_sub(2)),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt::from_const_unchecked(
            Value::new_unchecked(11_u32.wrapping_sub(2))
                .as_u16_limbs()
                .to_vec(),
        );

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    fn test_opcode_sub_underflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sub",
                |cb| {
                    let config = SubInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = SubInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SUB,
                MOCK_PROGRAM[1],
                3,
                11,
                Change::new(0, 3_u32.wrapping_sub(11)),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt::from_const_unchecked(
            Value::new_unchecked(3_u32.wrapping_sub(11))
                .as_u16_limbs()
                .to_vec(),
        );

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    fn test_opcode_mul() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_MUL,
                MOCK_PROGRAM[2],
                11,
                2,
                Change::new(0, 22),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(22u32).as_u16_limbs().to_vec());

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    fn test_opcode_mul_overflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        // values assignment
        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_MUL,
                MOCK_PROGRAM[2],
                u32::MAX / 2 + 1,
                2,
                Change::new(0, 0),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt::from_const_unchecked(vec![0u64, 0]);

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }

    #[test]
    fn test_opcode_mul_overflow2() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(|| "mul", |cb| Ok(MulInstruction::construct_circuit(cb)))
            .unwrap()
            .unwrap();

        let a = Value::<'_, u32>::new_unchecked(u32::MAX);
        let b = Value::<'_, u32>::new_unchecked(u32::MAX);
        let ret = a.mul(&b, &mut LkMultiplicity::default(), true);
        let c_limb = ret.limbs;

        // values assignment
        let (raw_witin, _) = MulInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_MUL,
                MOCK_PROGRAM[2],
                a.as_u64() as u32,
                b.as_u64() as u32,
                Change::new(
                    0,
                    Value::<u32>::from_limb_unchecked(c_limb.clone()).as_u64() as u32,
                ),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt::from_const_unchecked(c_limb.clone());

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        );
    }
}
