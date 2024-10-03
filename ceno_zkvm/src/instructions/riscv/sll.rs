use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::InsnKind;
use ff_ext::ExtensionField;

use crate::{
    expression::{ToExpr, WitIn},
    instructions::Instruction,
    set_val, Value,
};

use super::{constants::UInt, r_insn::RInstructionConfig, RIVInstruction};

pub struct ShiftLeftConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UInt<E>,

    quotient: UInt<E>,
    rs2_low5: WitIn,
    multiplier: UInt<E>,
}

pub struct ShiftLeftLogicalInstruction<E>(PhantomData<E>);

impl<E> RIVInstruction for ShiftLeftLogicalInstruction<E> {
    const INST_KIND: InsnKind = InsnKind::SLL;
}

impl<E: ExtensionField> Instruction<E> for ShiftLeftLogicalInstruction<E> {
    type InstructionConfig = ShiftLeftConfig<E>;

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, crate::error::ZKVMError> {
        // rs1_read * rs2_read = rd_written
        let mut rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;

        let rs2_low5 = circuit_builder.create_witin(|| "rs2_low5")?;
        let quotient = UInt::new(|| "quotient", circuit_builder)?;
        let mut multiplier = UInt::new_unchecked(|| "multiplier", circuit_builder)?;

        let rd_written = rs1_read.mul(|| "rd_written", circuit_builder, &mut multiplier, true)?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        circuit_builder.lookup_pow(2.into(), rs2_low5.expr(), multiplier.value())?;
        circuit_builder.assert_ux::<_, _, 5>(|| "rs2_low5 in u5", rs2_low5.expr())?;
        circuit_builder.require_equal(
            || "rs2 == quotient * 2^5 + rs2_low5",
            rs2_read.value(),
            quotient.value() * (1 << 5).into() + rs2_low5.expr(),
        )?;

        Ok(ShiftLeftConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
            quotient,
            rs2_low5,
            multiplier,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [std::mem::MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut crate::witness::LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), crate::error::ZKVMError> {
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);

        let rs2_low5 = rs2_read.as_u64() & 0b11111;
        let quotient = Value::new_unchecked(((rs2_read.as_u64() - rs2_low5) >> 5) as u32);
        let multiplier = Value::new_unchecked((1 << rs2_low5) as u32);

        let rd_written = rs1_read.mul(&multiplier, lk_multiplicity, true);

        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        config.rs1_read.assign_value(instance, rs1_read);
        config.rs2_read.assign_value(instance, rs2_read);

        set_val!(instance, config.rs2_low5, rs2_low5);
        config.quotient.assign_value(instance, quotient);
        config.multiplier.assign_value(instance, multiplier);
        config.rd_written.assign_limb_with_carry_auxiliary(
            instance,
            lk_multiplicity,
            &rd_written,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ceno_emul::{Change, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MockProver, MOCK_PC_SLL, MOCK_PROGRAM},
    };

    use super::ShiftLeftLogicalInstruction;

    #[test]
    fn test_opcode_sll_1() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sll",
                |cb| {
                    let config =
                        ShiftLeftLogicalInstruction::<GoldilocksExt2>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = ShiftLeftLogicalInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SLL,
                MOCK_PROGRAM[18],
                32,
                3,
                Change::new(0, 32 << 3),
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

    #[test]
    fn test_opcode_sll_2_overflow() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "sll",
                |cb| {
                    let config =
                        ShiftLeftLogicalInstruction::<GoldilocksExt2>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, _) = ShiftLeftLogicalInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SLL,
                MOCK_PROGRAM[18],
                32,
                33,
                Change::new(0, 32 << 3),
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
