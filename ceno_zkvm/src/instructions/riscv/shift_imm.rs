use super::{RIVInstruction, config::MsbConfig};
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::DivConfig,
    instructions::{
        Instruction,
        riscv::{config::MsbInput, constants::UInt, i_insn::IInstructionConfig},
    },
    set_val,
    utils::i64_to_base,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff::Field;
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct ShiftImmConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    imm: UInt<E>,
    rd_written: UInt<E>,

    // SRAI
    rs1_read: Option<UInt<E>>,
    msb_config: Option<MsbConfig>,
    remainder_is_zero: Option<WitIn>,
    remainder_diff_inverse: Option<WitIn>,
    unsigned_result: Option<UInt<E>>,

    // SRLI
    remainder: Option<UInt<E>>,
    div_config: Option<DivConfig<E>>,
}

pub struct ShiftImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SlliOp;
impl RIVInstruction for SlliOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLLI;
}

pub struct SraiOp;
impl RIVInstruction for SraiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRAI;
}

pub struct SrliOp;
impl RIVInstruction for SrliOp {
    const INST_KIND: ceno_emul::InsnKind = InsnKind::SRLI;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftImmInstruction<E, I> {
    type InstructionConfig = ShiftImmConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // Note: `imm` wtns is set to 2**imm (upto 32 bit) just for efficient verification.
        let mut imm = UInt::new(|| "imm", circuit_builder)?;

        match I::INST_KIND {
            InsnKind::SLLI => {
                let mut rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
                let rd_written = rs1_read.mul(
                    || "rd_written = rs1_read * imm",
                    circuit_builder,
                    &mut imm,
                    true,
                )?;

                let i_insn = IInstructionConfig::<E>::construct_circuit(
                    circuit_builder,
                    I::INST_KIND,
                    &imm.value(),
                    rs1_read.register_expr(),
                    rd_written.register_expr(),
                    false,
                )?;

                Ok(ShiftImmConfig {
                    i_insn,
                    imm,
                    rd_written,
                    rs1_read: Some(rs1_read),
                    remainder: None,
                    div_config: None,
                    msb_config: None,
                    remainder_is_zero: None,
                    remainder_diff_inverse: None,
                    unsigned_result: None,
                })
            }
            InsnKind::SRAI => {
                // 1. Get the MSB.
                // 2. Convert to unsigned number based on MSB
                // 3. Shift on the unsigned number to get unsigned result
                // 4. Convert to rd_written based on MSB
                let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
                let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

                let remainder = UInt::new(|| "remainder", circuit_builder)?;

                let mut unsigned_result = UInt::new(|| "unsigned_result", circuit_builder)?;

                let (remainder_is_zero, remainder_diff_inverse) =
                    circuit_builder.is_equal(remainder.value(), Expression::ZERO)?;

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

                // if msb == 1 then unsigned_number = two_compliment(rs1_read)
                // else unsigned_number = rs1_read
                circuit_builder.condition_require_zero(
                    || "srai pre shift",
                    msb_expr.clone(),
                    unsigned_number.value() + rs1_read.value()
                        - Expression::Constant((1 << 32).into()),
                    unsigned_number.value() - rs1_read.value(),
                )?;

                // if msb == 1 then rd_written = two_compliment(div_config.dividend) + !rem_is_zero
                // else rd_written = div_config.dividend
                circuit_builder.condition_require_zero(
                    || "srai pre shift",
                    msb_expr,
                    rd_written.value() + unsigned_result.value()
                        - Expression::Constant((1 << 32).into())
                        + (Expression::ONE - remainder_is_zero.expr()),
                    rd_written.value() - unsigned_result.value(),
                )?;

                let i_insn = IInstructionConfig::<E>::construct_circuit(
                    circuit_builder,
                    I::INST_KIND,
                    &imm.value(),
                    rs1_read.register_expr(),
                    rd_written.register_expr(),
                    false,
                )?;

                Ok(ShiftImmConfig {
                    i_insn,
                    imm,
                    rd_written,
                    remainder: Some(remainder),
                    div_config: Some(div_config),
                    rs1_read: Some(rs1_read),
                    msb_config: Some(msb_config),
                    remainder_is_zero: Some(remainder_is_zero),
                    remainder_diff_inverse: Some(remainder_diff_inverse),
                    unsigned_result: Some(unsigned_result),
                })
            }
            InsnKind::SRLI => {
                // rs1 == rd_written * imm + remainder
                let mut rd_written = UInt::new(|| "rd_written", circuit_builder)?;
                let remainder = UInt::new(|| "remainder", circuit_builder)?;

                let div_config = DivConfig::construct_circuit(
                    circuit_builder,
                    || "srli_div",
                    &mut imm,
                    &mut rd_written,
                    &remainder,
                )?;

                let i_insn = IInstructionConfig::<E>::construct_circuit(
                    circuit_builder,
                    I::INST_KIND,
                    &imm.value(),
                    div_config.dividend.register_expr(),
                    rd_written.register_expr(),
                    false,
                )?;

                Ok(ShiftImmConfig {
                    i_insn,
                    imm,
                    rd_written,
                    remainder: Some(remainder),
                    div_config: Some(div_config),
                    rs1_read: None,
                    msb_config: None,
                    remainder_is_zero: None,
                    remainder_diff_inverse: None,
                    unsigned_result: None,
                })
            }

            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);

        config.imm.assign_value(instance, imm.clone());
        match I::INST_KIND {
            InsnKind::SLLI => {
                let rd_written = rs1_read.mul(&imm, lk_multiplicity, true);
                config
                    .rs1_read
                    .as_ref()
                    .unwrap()
                    .assign_value(instance, rs1_read);
                config
                    .rd_written
                    .assign_mul_outcome(instance, lk_multiplicity, &rd_written)?;
            }
            InsnKind::SRAI => {
                let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
                let (msb, _) = MsbInput {
                    limbs: &rs1_read.limbs,
                }
                .assign(
                    instance,
                    config.msb_config.as_ref().unwrap(),
                    lk_multiplicity,
                );

                let unsigned_number = if msb == 1 {
                    Value::new_unchecked((-(rs1_read.as_u32() as i32)) as u32)
                } else {
                    Value::new_unchecked(rs1_read.as_u32())
                };

                let unsigned_result =
                    Value::new(unsigned_number.as_u32() / imm.as_u32(), lk_multiplicity);

                let remainder =
                    Value::new(unsigned_number.as_u32() % imm.as_u32(), lk_multiplicity);

                config.div_config.as_ref().unwrap().assign_instance(
                    instance,
                    lk_multiplicity,
                    &imm,
                    &unsigned_result,
                    &remainder,
                )?;

                config
                    .rs1_read
                    .as_ref()
                    .unwrap()
                    .assign_value(instance, rs1_read);
                config.rd_written.assign_value(instance, rd_written);

                set_val!(
                    instance,
                    config.remainder_is_zero.as_ref().unwrap(),
                    (remainder.as_u64() == 0) as u64
                );
                let remainder_f = i64_to_base::<E::BaseField>(remainder.as_u64() as i64);
                set_val!(
                    instance,
                    config.remainder_diff_inverse.as_ref().unwrap(),
                    remainder_f.invert().unwrap_or(E::BaseField::ZERO)
                );
                config
                    .remainder
                    .as_ref()
                    .unwrap()
                    .assign_value(instance, remainder);

                config
                    .unsigned_result
                    .as_ref()
                    .unwrap()
                    .assign_value(instance, unsigned_result);
            }
            InsnKind::SRLI => {
                let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
                let remainder = Value::new(rs1_read.as_u32() % imm.as_u32(), lk_multiplicity);

                config.div_config.as_ref().unwrap().assign_instance(
                    instance,
                    lk_multiplicity,
                    &imm,
                    &rd_written,
                    &remainder,
                )?;
                config.rd_written.assign_value(instance, rd_written);
                config
                    .remainder
                    .as_ref()
                    .unwrap()
                    .assign_value(instance, remainder);
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }

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

    use super::{ShiftImmInstruction, SlliOp, SraiOp, SrliOp};
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::{RIVInstruction, constants::UInt},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    #[test]
    fn test_opcode_slli() {
        // imm = 3
        verify::<SlliOp>("32 << 3", 32, 3, 32 << 3);
        verify::<SlliOp>("33 << 3", 33, 3, 33 << 3);
        // imm = 31
        verify::<SlliOp>("32 << 31", 32, 31, 32 << 31);
        verify::<SlliOp>("33 << 31", 33, 31, 33 << 31);
    }

    #[test]
    fn test_opcode_srai() {
        // positive rs1
        // imm = 3
        verify::<SraiOp>("32 >> 3", 32, 3, 32 >> 3);
        verify::<SraiOp>("33 >> 3", 33, 3, 33 >> 3);
        // imm = 31
        verify::<SraiOp>("32 >> 31", 32, 31, 32 >> 31);
        verify::<SraiOp>("33 >> 31", 33, 31, 33 >> 31);

        // negative rs1
        // imm = 3
        verify::<SraiOp>("-32 >> 3", (-32_i32) as u32, 3, (-32_i32 >> 3) as u32);
        verify::<SraiOp>("-33 >> 3", (-33_i32) as u32, 3, (-33_i32 >> 3) as u32);
        // imm = 31
        verify::<SraiOp>("-32 >> 31", (-32_i32) as u32, 31, (-32_i32 >> 31) as u32);
        verify::<SraiOp>("-33 >> 31", (-33_i32) as u32, 31, (-33_i32 >> 31) as u32);
    }

    #[test]
    fn test_opcode_srli() {
        // imm = 3
        verify::<SrliOp>("32 >> 3", 32, 3, 32 >> 3);
        verify::<SrliOp>("33 >> 3", 33, 3, 33 >> 3);
        // imm = 31
        verify::<SrliOp>("32 >> 31", 32, 31, 32 >> 31);
        verify::<SrliOp>("33 >> 31", 33, 31, 33 >> 31);
    }

    fn verify<I: RIVInstruction>(
        name: &'static str,
        rs1_read: u32,
        imm: u32,
        expected_rd_written: u32,
    ) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let (prefix, insn_code, rd_written) = match I::INST_KIND {
            InsnKind::SLLI => (
                "SLLI",
                encode_rv32(InsnKind::SLLI, 2, 0, 4, imm),
                rs1_read << imm,
            ),
            InsnKind::SRLI => (
                "SRLI",
                encode_rv32(InsnKind::SRLI, 2, 3, 4, 0),
                rs1_read >> imm,
            ),
            InsnKind::SRAI => (
                "SRAI",
                encode_rv32(InsnKind::SRAI, 2, 0, 4, imm),
                (rs1_read as i32 >> imm as i32) as u32,
            ),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                |cb| {
                    let config = ShiftImmInstruction::<GoldilocksExt2, I>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        config
            .rd_written
            .require_equal(
                || format!("{prefix}_({name})_assert_rd_written"),
                &mut cb,
                &UInt::from_const_unchecked(
                    Value::new_unchecked(expected_rd_written)
                        .as_u16_limbs()
                        .to_vec(),
                ),
            )
            .unwrap();

        let (raw_witin, lkm) = ShiftImmInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                rs1_read,
                Change::new(0, rd_written),
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
            &[insn_code],
            None,
            Some(lkm),
        );
    }
}
