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
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct InstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    imm: UInt<E>,
    rd_written: UInt<E>,
    remainder: UInt<E>,
    div_config: DivConfig<E>,
}

pub struct ShiftImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SrliOp;
impl RIVInstruction for SrliOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRLI;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftImmInstruction<E, I> {
    type InstructionConfig = InstructionConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let mut imm = UInt::new(|| "imm", circuit_builder)?;
        let mut rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        // Note: `imm` is set to 2**imm (upto 32 bit) just for SRLI for efficient verification
        // Goal is to constrain:
        // rs1 == rd_written * imm + remainder
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
        )?;

        Ok(InstructionConfig {
            i_insn,
            imm,
            rd_written,
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
        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);

        let (remainder, imm) = {
            let rs1_read = step.rs1().unwrap().value;
            let imm = step.insn().imm_or_funct7();
            (
                Value::new(rs1_read % imm, lk_multiplicity),
                Value::new(imm, lk_multiplicity),
            )
        };
        config.div_config.assign_instance(
            instance,
            lk_multiplicity,
            &imm,
            &rd_written,
            &remainder,
        )?;
        config.imm.assign_value(instance, imm);
        config.rd_written.assign_value(instance, rd_written);
        config.remainder.assign_value(instance, remainder);

        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, InsnKind, StepRecord, encode_rv32};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::constants::UInt},
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    use super::{ShiftImmInstruction, SrliOp};

    #[test]
    fn test_opcode_srli() {
        // imm = 3
        verify_srli(3, 32, 32 >> 3);
        verify_srli(3, 33, 33 >> 3);
        // imm = 31
        verify_srli(31, 32, 32 >> 31);
        verify_srli(31, 33, 33 >> 31);
    }

    fn verify_srli(imm: u32, rs1_read: u32, expected_rd_written: u32) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "srli",
                |cb| {
                    let config =
                        ShiftImmInstruction::<GoldilocksExt2, SrliOp>::construct_circuit(cb);
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

        let insn_code = encode_rv32(InsnKind::SRLI, 2, 0, 4, imm);
        let (raw_witin, lkm) = ShiftImmInstruction::<GoldilocksExt2, SrliOp>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1_read,
                Change::new(0, rs1_read >> imm),
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
