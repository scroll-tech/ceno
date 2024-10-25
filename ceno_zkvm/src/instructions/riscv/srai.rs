use super::{
    RIVInstruction,
    config::{MsbConfig, MsbInput},
};
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::DivConfig,
    instructions::{
        Instruction,
        riscv::{constants::UInt, i_insn::IInstructionConfig},
    },
    set_val,
    utils::i64_to_base,
    witness::LkMultiplicity,
};
use ceno_emul::StepRecord;
use ff::Field;
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct InstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: UInt<E>,
    rd_written: UInt<E>,
    msb_config: MsbConfig,
    remainder: UInt<E>,
    remainder_is_zero: WitIn,
    remainder_diff_inverse: WitIn,
    div_config: DivConfig<E>,
    unsigned_result: UInt<E>,
}

pub struct ShiftImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SraiOp;
impl RIVInstruction for SraiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRAI;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftImmInstruction<E, I> {
    type InstructionConfig = InstructionConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let mut imm = UInt::new(|| "imm", circuit_builder)?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        // 1. Get the MSB.
        // 2. Convert to unsigned number based on MSB
        // 3. Shift on the unsigned number to get unsigned result
        // 4. Convert to rd_written based on MSB

        let mut unsigned_result = UInt::new(|| "unsigned_result", circuit_builder)?;
        let remainder = UInt::new(|| "remainder", circuit_builder)?;
        let (remainder_is_zero, remainder_diff_inverse) =
            circuit_builder.is_equal(remainder.value(), Expression::ZERO)?;

        // Note: `imm` is set to 2**imm (upto 32 bit) just for efficient verification
        // Goal is to constrain:
        // unsigned_number == rd_written * imm + remainder
        let div_config = DivConfig::construct_circuit(
            circuit_builder,
            || "srai_div",
            &mut imm,
            &mut unsigned_result,
            &remainder,
        )?;
        let unsigned_number = &div_config.dividend;

        let msb_config = rs1_read.msb_decompose(circuit_builder)?;
        let msb_expr: Expression<E> = msb_config.msb.expr();

        circuit_builder.require_zero(
            || "srai pre shift",
            // if msb == 1 then unsigned_number = two_compliment(rs1_read)
            msb_expr.clone() * (unsigned_number.value() + rs1_read.value() - Expression::Constant((1 << 32).into()))
            // else unsigned_number = rs1_read
                + (Expression::ONE - msb_expr.clone()) * (unsigned_number.value() - rs1_read.value()),
        )?;

        circuit_builder.require_zero(
            || "srai post shift",
            // if msb == 1 then rd_written = two_compliment(div_config.dividend) + !rem_is_zero
            msb_expr.clone() * (rd_written.value() + unsigned_result.value() - Expression::Constant((1 << 32).into()) + (Expression::ONE - remainder_is_zero.expr()))
            // else rd_written = div_config.dividend
                + (Expression::ONE - msb_expr) * (rd_written.value() - unsigned_result.value()),
        )?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.value(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(InstructionConfig {
            i_insn,
            rs1_read,
            imm,
            rd_written,
            msb_config,
            remainder,
            remainder_is_zero,
            remainder_diff_inverse,
            div_config,
            unsigned_result,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);
        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);

        let (msb, _) = MsbInput {
            limbs: &rs1_read.limbs,
        }
        .assign(instance, &config.msb_config, lk_multiplicity);

        let unsigned_number = if msb == 1 {
            Value::new_unchecked((-(rs1_read.as_u32() as i32)) as u32)
        } else {
            Value::new_unchecked(rs1_read.as_u32())
        };

        let unsigned_result = Value::new(unsigned_number.as_u32() / imm.as_u32(), lk_multiplicity);

        let remainder = Value::new(unsigned_number.as_u32() % imm.as_u32(), lk_multiplicity);

        config.div_config.assign_instance(
            instance,
            lk_multiplicity,
            &imm,
            &unsigned_result,
            &remainder,
        )?;

        config.rs1_read.assign_value(instance, rs1_read);
        config.imm.assign_value(instance, imm);
        config.rd_written.assign_value(instance, rd_written);

        set_val!(
            instance,
            config.remainder_is_zero,
            (remainder.as_u64() == 0) as u64
        );
        let remainder_f = i64_to_base::<E::BaseField>(remainder.as_u64() as i64);
        set_val!(
            instance,
            config.remainder_diff_inverse,
            remainder_f.invert().unwrap_or(E::BaseField::ZERO)
        );
        config.remainder.assign_value(instance, remainder);

        config
            .unsigned_result
            .assign_value(instance, unsigned_result);

        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::constants::UInt},
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    use super::{ShiftImmInstruction, SraiOp};

    #[test]
    fn test_opcode_srai() {
        // positive rs1
        // imm = 3
        verify_srai(3, 32, 32 >> 3);
        verify_srai(3, 33, 33 >> 3);
        // imm = 31
        verify_srai(31, 32, 32 >> 31);
        verify_srai(31, 33, 33 >> 31);

        // negative rs1
        // imm = 3
        verify_srai(3, (-32_i32) as u32, (-32_i32 >> 3) as u32);
        verify_srai(3, (-33_i32) as u32, ((-33_i32) >> 3) as u32);
        // imm = 31
        verify_srai(31, (-32_i32) as u32, (-32_i32 >> 31) as u32);
        verify_srai(31, (-33_i32) as u32, (-33_i32 >> 31) as u32);
    }

    fn verify_srai(imm: u32, rs1_read: u32, expected_rd_written: u32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "srai",
                |cb| {
                    let config =
                        ShiftImmInstruction::<GoldilocksExt2, SraiOp>::construct_circuit(cb);
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

        let insn_code = encode_rv32(InsnKind::SRAI, 2, 0, 4, imm);
        let (raw_witin, lkm) = ShiftImmInstruction::<GoldilocksExt2, SraiOp>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                rs1_read,
                Change::new(0, ((rs1_read as i32) >> (imm as i32)) as u32),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written = UInt::from_const_unchecked(
            Value::new_unchecked(expected_rd_written)
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
            &[insn_code],
            None,
            Some(lkm),
        );
    }
}
