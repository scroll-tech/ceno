use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::InsnKind;
use ff_ext::ExtensionField;

use crate::{
    expression::{ToExpr, WitIn},
    instructions::Instruction,
    set_val, Value,
};

use super::{constants::UInt, r_insn::RInstructionConfig, RIVInstruction};

pub struct ShiftConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UInt<E>,

    rs2_high: UInt<E>,
    rs2_low5: WitIn,
    pow2_rs2_low5: UInt<E>,

    intermediate: Option<UInt<E>>,
    remainder: Option<UInt<E>>,
}

pub struct ShiftLogicalInstruction<E, I>(PhantomData<(E, I)>);

struct SllOp;
impl RIVInstruction for SllOp {
    const INST_KIND: InsnKind = InsnKind::SLL;
}

struct SrlOp;
impl RIVInstruction for SrlOp {
    const INST_KIND: InsnKind = InsnKind::SRL;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftLogicalInstruction<E, I> {
    type InstructionConfig = ShiftConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, crate::error::ZKVMError> {
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let rs2_low5 = circuit_builder.create_witin(|| "rs2_low5")?;
        // pow2_rs2_low5 is unchecked because it's assignment will be constrained due it's use in lookup_pow2 below
        let mut pow2_rs2_low5 = UInt::new_unchecked(|| "pow2_rs2_low5", circuit_builder)?;
        // rs2 = rs2_high | rs2_low5
        let rs2_high = UInt::new(|| "rs2_high", circuit_builder)?;

        let (rs1_read, rd_written, intermediate, remainder) = if I::INST_KIND == InsnKind::SLL {
            let mut rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
            let rd_written = rs1_read.mul(
                || "rd_written = rs1_read * pow2_rs2_low5",
                circuit_builder,
                &mut pow2_rs2_low5,
                true,
            )?;
            (rs1_read, rd_written, None, None)
        } else if I::INST_KIND == InsnKind::SRL {
            let mut rd_written = UInt::new(|| "rd_written", circuit_builder)?;
            let remainder = UInt::new(|| "remainder", circuit_builder)?;
            let (rs1_read, intermediate) = rd_written.mul_add(
                || "rs1_read = rd_written * pow2_rs2_low5 + remainder",
                circuit_builder,
                &mut pow2_rs2_low5,
                &remainder,
                true,
            )?;
            (rs1_read, rd_written, Some(intermediate), Some(remainder))
        } else {
            unreachable!()
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        circuit_builder.lookup_pow2(rs2_low5.expr(), pow2_rs2_low5.value())?;
        circuit_builder.assert_ux::<_, _, 5>(|| "rs2_low5 in u5", rs2_low5.expr())?;
        circuit_builder.require_equal(
            || "rs2 == rs2_high * 2^5 + rs2_low5",
            rs2_read.value(),
            rs2_high.value() * (1 << 5).into() + rs2_low5.expr(),
        )?;

        Ok(ShiftConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
            rs2_high,
            rs2_low5,
            pow2_rs2_low5,
            intermediate,
            remainder,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [std::mem::MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut crate::witness::LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), crate::error::ZKVMError> {
        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        let rs2_low5 = rs2_read.as_u64() & 0b11111;
        let pow2_rs2_low5 = Value::new_unchecked((1 << rs2_low5) as u32);
        let rs2_high = Value::new(
            ((rs2_read.as_u64() - rs2_low5) >> 5) as u32,
            lk_multiplicity,
        );

        if I::INST_KIND == InsnKind::SLL {
            let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
            let rd_written = rs1_read.mul(&pow2_rs2_low5, lk_multiplicity, true);
            config.rs1_read.assign_value(instance, rs1_read);
            config.rd_written.assign_limb_with_carry_auxiliary(
                instance,
                lk_multiplicity,
                &rd_written,
            )?;
        } else if I::INST_KIND == InsnKind::SRL {
            let rd_written = Value::new_unchecked(step.rd().unwrap().value.after);
            let remainder = Value::new(
                // rs1 - rd * pow2_rs2_low5
                step.rs1()
                    .unwrap()
                    .value
                    .wrapping_sub((rd_written.as_u64() * pow2_rs2_low5.as_u64()) as u32),
                lk_multiplicity,
            );
            let (rs1_read, intermediate) =
                rd_written.mul_add(&pow2_rs2_low5, &remainder, lk_multiplicity, true);
            config.rs1_read.assign_limb_with_carry(instance, &rs1_read);
            config.rd_written.assign_value(instance, rd_written);
            config
                .remainder
                .as_ref()
                .unwrap()
                .assign_value(instance, remainder);
            config
                .intermediate
                .as_ref()
                .unwrap()
                .assign_limb_with_carry_auxiliary(instance, lk_multiplicity, &intermediate)?;
        } else {
            unreachable!()
        };

        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.rs2_read.assign_value(instance, rs2_read);
        set_val!(instance, config.rs2_low5, rs2_low5);
        config.rs2_high.assign_value(instance, rs2_high);
        config.pow2_rs2_low5.assign_value(instance, pow2_rs2_low5);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ceno_emul::{Change, InsnKind, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            riscv::{constants::UInt, RIVInstruction},
            Instruction,
        },
        scheme::mock_prover::{MockProver, MOCK_PC_SLL, MOCK_PC_SRL, MOCK_PROGRAM},
        Value,
    };

    use super::{ShiftLogicalInstruction, SllOp, SrlOp};

    #[test]
    fn test_opcode_sll_1() {
        test::<SllOp>(32, 3, 32 << 3);
    }

    #[test]
    fn test_opcode_sll_2_overflow() {
        test::<SllOp>(33, 33, 33 << (33 - 32));
    }

    #[test]
    fn test_opcode_srl_1() {
        test::<SrlOp>(33, 3, 33 >> 3);
    }

    #[test]
    fn test_opcode_srl_2_overflow() {
        test::<SrlOp>(32, 33, 0);
    }

    fn test<I: RIVInstruction>(rs1_read: u32, rs2_read: u32, expected_rd_written: u32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let (name, mock_pc, mock_program_op) = if I::INST_KIND == InsnKind::SLL {
            ("SLL", MOCK_PC_SLL, MOCK_PROGRAM[18])
        } else {
            ("SRL", MOCK_PC_SRL, MOCK_PROGRAM[19])
        };

        let config = cb
            .namespace(
                || name,
                |cb| {
                    let config =
                        ShiftLogicalInstruction::<GoldilocksExt2, I>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        config
            .rd_written
            .require_equal(
                || "assert_rd_written",
                &mut cb,
                &UInt::from_const_unchecked(
                    Value::new_unchecked(expected_rd_written)
                        .as_u16_limbs()
                        .to_vec(),
                ),
            )
            .unwrap();

        let (raw_witin, _) = ShiftLogicalInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                mock_pc,
                mock_program_op,
                rs1_read,
                rs2_read,
                Change::new(0, expected_rd_written),
                0,
            )],
        )
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
