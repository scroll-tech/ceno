use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;

use crate::{
    Value, circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction,
    witness::LkMultiplicity,
};

use super::{RIVInstruction, constants::UInt, i_insn::IInstructionConfig};

pub struct AddiInstruction<E>(PhantomData<E>);

impl<E> RIVInstruction for AddiInstruction<E> {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::ADDI;
}

pub struct InstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: UInt<E>,
    rd_written: UInt<E>,
}

impl<E: ExtensionField> Instruction<E> for AddiInstruction<E> {
    type InstructionConfig = InstructionConfig<E>;

    fn name() -> String {
        format!("{:?}", Self::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let imm = UInt::new(|| "imm", circuit_builder)?;
        let rd_written = rs1_read.add(|| "rs1_read + imm", circuit_builder, &imm, true)?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            &imm.value(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(InstructionConfig {
            i_insn,
            rs1_read,
            imm,
            rd_written,
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

        let result = rs1_read.add(&imm, lk_multiplicity, true);

        config.rs1_read.assign_value(instance, rs1_read);
        config.imm.assign_value(instance, imm);

        config.rd_written.assign_add_outcome(instance, &result);

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
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    use super::AddiInstruction;

    fn imm(imm: i32) -> u32 {
        // imm is 12 bits in B-type
        const IMM_MAX: i32 = 2i32.pow(12);
        if imm.is_negative() {
            (IMM_MAX + imm) as u32
        } else {
            imm as u32
        }
    }
    #[test]
    fn test_opcode_addi() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "addi",
                |cb| {
                    let config = AddiInstruction::<GoldilocksExt2>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::ADDI, 2, 0, 4, imm(3));
        let (raw_witin, lkm) = AddiInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                1000,
                Change::new(0, 1003),
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

    #[test]
    fn test_opcode_addi_sub() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "addi",
                |cb| {
                    let config = AddiInstruction::<GoldilocksExt2>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::ADDI, 2, 0, 4, imm(-3));
        let (raw_witin, lkm) = AddiInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                1000,
                Change::new(0, 997),
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
