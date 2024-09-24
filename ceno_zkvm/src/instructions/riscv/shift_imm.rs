use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::StepRecord;
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, instructions::Instruction,
    witness::LkMultiplicity, Value,
};

use super::{constants::UInt, i_insn::IInstructionConfig, RIVInstruction};

pub struct ShiftImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SrliOp;

impl RIVInstruction for SrliOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRLI;
}

pub struct InstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    imm: UInt<E>,
    rd_written: UInt<E>,
    remainder: UInt<E>,
    rd_imm_mul: UInt<E>,
    rd_imm_rem_add: UInt<E>,
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
        let mut rd_written = UInt::new_unchecked(|| "rd_written", circuit_builder)?;

        // Note: `imm` is set to 2**imm (upto 32 bit) just for SRLI for efficient verification
        // Goal is to constrain:
        // rs1_read == rd_written * imm + remainder
        let remainder = UInt::new(|| "remainder", circuit_builder)?;
        let rd_imm_mul = rd_written.mul(|| "rd_written * imm", circuit_builder, &mut imm, true)?;
        let rd_imm_rem_add =
            rd_imm_mul.add(|| "rm_imm + remainder", circuit_builder, &remainder, true)?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.value(),
            rd_imm_rem_add.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(InstructionConfig {
            i_insn,
            imm,
            rd_written,
            remainder,
            rd_imm_mul,
            rd_imm_rem_add,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // We need to calculate result and remainder.
        let rs1_read = step.rs1().unwrap().value;
        let rd_written = step.rd().unwrap().value.after;
        let imm = step.insn().imm_or_funct7();
        let result = rs1_read.wrapping_div(imm);
        let remainder = rs1_read.wrapping_sub(result * imm);
        assert_eq!(result, rd_written, "SRLI: result mismatch");

        // Assignment.
        let rd_written = Value::new_unchecked(rd_written);
        let imm = Value::new(imm, lk_multiplicity);
        let remainder = Value::new(remainder, lk_multiplicity);

        let rd_imm_mul = rd_written.mul(&imm, lk_multiplicity, true);
        let rd_imm = Value::new_from_slice_unchecked(rd_imm_mul.0.as_slice());

        let rd_imm_rem_add = rd_imm.add(&remainder, lk_multiplicity, true);
        assert_eq!(
            Value::new_from_slice_unchecked(&rd_imm_rem_add.0).as_u64(),
            rs1_read as u64,
            "SRLI: rd_imm_rem_add mismatch"
        );

        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;
        config.imm.assign_value(instance, imm);
        config.rd_written.assign_value(instance, rd_written);
        config.remainder.assign_value(instance, remainder);

        config
            .rd_imm_mul
            .assign_value_with_carry(instance, rd_imm_mul);

        config
            .rd_imm_rem_add
            .assign_value_with_carry(instance, rd_imm_rem_add);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MockProver, MOCK_PC_SRLI, MOCK_PROGRAM},
    };

    use super::{ShiftImmInstruction, SrliOp};

    #[test]
    fn test_opcode_srli() {
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

        let (raw_witin, _) = ShiftImmInstruction::<GoldilocksExt2, SrliOp>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                MOCK_PC_SRLI,
                MOCK_PROGRAM[8],
                32,
                Change::new(0, 32 >> 3),
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
