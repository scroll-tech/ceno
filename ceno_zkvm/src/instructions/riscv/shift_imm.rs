use super::RIVInstruction;
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::DivConfig,
    instructions::{
        Instruction,
        riscv::{constants::UInt, i_insn::IInstructionConfig},
    },
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct ShiftImmConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: UInt<E>,
    rd_written: UInt<E>,

    // for SRLI division arithmetics
    remainder: Option<UInt<E>>,
    div_config: Option<DivConfig<E>>,
}

pub struct ShiftImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SlliOp;
impl RIVInstruction for SlliOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLLI;
}

pub struct SrliOp;
impl RIVInstruction for SrliOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRLI;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftImmInstruction<E, I> {
    type InstructionConfig = ShiftImmConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let mut imm = UInt::new(|| "imm", circuit_builder)?;

        // Note: `imm` is set to 2**imm (upto 32 bit) just for efficient verification
        // Goal is to constrain:
        // rs1 == rd_written * imm + remainder
        let (rs1_read, rd_written, remainder, div_config) = match I::INST_KIND {
            InsnKind::SLLI => {
                let mut rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
                let rd_written = rs1_read.mul(
                    || "rd_written = rs1_read * imm",
                    circuit_builder,
                    &mut imm,
                    true,
                )?;

                (rs1_read, rd_written, None, None)
            }
            InsnKind::SRLI => {
                let mut rd_written = UInt::new(|| "rd_written", circuit_builder)?;
                let remainder = UInt::new(|| "remainder", circuit_builder)?;
                let div_config = DivConfig::construct_circuit(
                    circuit_builder,
                    || "srli_div",
                    &mut imm,
                    &mut rd_written,
                    &remainder,
                )?;
                (
                    div_config.dividend.clone(),
                    rd_written,
                    Some(remainder),
                    Some(div_config),
                )
            }
            _ => unreachable!(),
        };

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
            rs1_read,
            remainder,
            div_config,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let imm = Value::new(step.insn().imm_or_funct7(), lk_multiplicity);
        match I::INST_KIND {
            InsnKind::SLLI => {
                let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
                let rd_written = rs1_read.mul(&imm, lk_multiplicity, true);
                config.rs1_read.assign_value(instance, rs1_read);
                config
                    .rd_written
                    .assign_mul_outcome(instance, lk_multiplicity, &rd_written)?;
            }
            InsnKind::SRLI => {
                let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
                let rs1_read = step.rs1().unwrap().value;
                let remainder = Value::new(rs1_read % imm.as_u32(), lk_multiplicity);
                config.div_config.as_ref().unwrap().assign_instance(
                    instance,
                    lk_multiplicity,
                    &imm,
                    &rd_written,
                    &remainder,
                )?;
                config
                    .remainder
                    .as_ref()
                    .unwrap()
                    .assign_value(instance, remainder);
                config.rd_written.assign_value(instance, rd_written);
            }
            _ => unreachable!(),
        };

        config.imm.assign_value(instance, imm);

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
        instructions::{
            Instruction,
            riscv::{RIVInstruction, constants::UInt},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    use super::{ShiftImmInstruction, SlliOp, SrliOp};

    #[test]
    fn test_opcode_slli() {
        verify::<SlliOp>("imm = 3, rs1 = 32", 3, 32, 32 << 3);
        verify::<SlliOp>("imm = 3, rs1 = 33", 3, 33, 33 << 3);

        verify::<SlliOp>("imm = 31, rs1 = 32", 31, 32, 32 << 31);
        verify::<SlliOp>("imm = 31, rs1 = 33", 31, 33, 33 << 31);
    }

    #[test]
    fn test_opcode_srli() {
        verify::<SrliOp>("imm = 3, rs1 = 32", 3, 32, 32 >> 3);
        verify::<SrliOp>("imm = 3, rs1 = 33", 3, 33, 33 >> 3);

        verify::<SrliOp>("imm = 31, rs1 = 32", 31, 32, 32 >> 31);
        verify::<SrliOp>("imm = 31, rs1 = 33", 31, 33, 33 >> 31);
    }

    fn verify<I: RIVInstruction>(
        name: &'static str,
        imm: u32,
        rs1_read: u32,
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
                encode_rv32(InsnKind::SRLI, 2, 0, 4, imm),
                rs1_read >> imm,
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
                || "assert_rd_written",
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
