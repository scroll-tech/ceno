use std::marker::PhantomData;

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;

use crate::{
    Value, circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction,
    structs::ProgramParams, tables::InsnRecord, witness::LkMultiplicity,
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
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let imm = UInt::new(|| "imm", circuit_builder)?;
        let rd_written = rs1_read.add(|| "rs1_read + imm", circuit_builder, &imm, true)?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            Self::INST_KIND,
            imm.value(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
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
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        let imm = Value::new(
            InsnRecord::imm_internal(&step.insn()) as u32,
            lk_multiplicity,
        );

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
    use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
    use ff_ext::GoldilocksExt2;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };

    use super::AddiInstruction;

    #[test]
    fn test_opcode_addi() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "addi",
                |cb| {
                    let config = AddiInstruction::<GoldilocksExt2>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    );
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::ADDI, 2, 0, 4, 3);
        let (raw_witin, lkm) = AddiInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                1000,
                Change::new(0, 1003),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_opcode_addi_sub() {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "addi",
                |cb| {
                    let config = AddiInstruction::<GoldilocksExt2>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    );
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::ADDI, 2, 0, 4, -3);

        let (raw_witin, lkm) = AddiInstruction::<GoldilocksExt2>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                1000,
                Change::new(0, 997),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
