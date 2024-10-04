use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{
    constants::{UInt, UINT_LIMBS},
    r_insn::RInstructionConfig,
    RIVInstruction,
};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, gadgets::IsLtConfig,
    instructions::Instruction, uint::Value, witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles R-Instructions that represent registers values as 2 * u16.
#[derive(Debug)]
pub struct ArithConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    #[allow(dead_code)]
    rd_written: UInt<E>,

    is_lt: IsLtConfig,
}

pub struct ArithInstruction<E, I>(PhantomData<(E, I)>);

pub struct SLTUOp;
impl RIVInstruction for SLTUOp {
    const INST_KIND: InsnKind = InsnKind::SLTU;
}
pub type SltuInstruction<E> = ArithInstruction<E, SLTUOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ArithInstruction<E, I> {
    type InstructionConfig = ArithConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        // If rs1_read < rs2_read, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;

        let lt = IsLtConfig::construct_circuit(
            circuit_builder,
            || "rs1 < rs2",
            rs1_read.value(),
            rs2_read.value(),
            None,
            UINT_LIMBS,
        )?;
        let rd_written = UInt::from_exprs_unchecked(vec![lt.expr()])?;

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
            is_lt: lt,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.r_insn.assign_instance(instance, lkm, step)?;

        let rs1 = step.rs1().unwrap().value;
        let rs2 = step.rs2().unwrap().value;

        let rs1_read = Value::new_unchecked(rs1);
        let rs2_read = Value::new_unchecked(rs2);
        config
            .rs1_read
            .assign_limbs(instance, rs1_read.as_u16_limbs());
        config
            .rs2_read
            .assign_limbs(instance, rs2_read.as_u16_limbs());
        config
            .is_lt
            .assign_instance(instance, lkm, rs1.into(), rs2.into())?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::u32;

    use ceno_emul::{Change, StepRecord, Word, CENO_PLATFORM};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;
    use rand::Rng;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MockProver, MOCK_PC_SLTU, MOCK_PROGRAM},
    };

    fn verify(name: &'static str, rs1: Word, rs2: Word, rd: Word) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("SLTU/{name}"),
                |cb| {
                    let config = SltuInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let idx = (MOCK_PC_SLTU.0 - CENO_PLATFORM.pc_start()) / 4;
        let (raw_witin, _) = SltuInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_SLTU,
                MOCK_PROGRAM[idx as usize],
                rs1,
                rs2,
                Change::new(0, rd),
                0,
            )],
        )
        .unwrap();

        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());

        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &mut cb,
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
    fn test_sltu_simple() {
        verify("lt = true, 0 < 1", 0, 1, 1);
        verify("lt = true, 1 < 2", 1, 2, 1);
        verify("lt = true, 0 < u32::MAX", 0, u32::MAX, 1);
        verify("lt = true, u32::MAX - 1", u32::MAX - 1, u32::MAX, 1);
        verify("lt = false, u32::MAX", u32::MAX, u32::MAX, 0);
        verify("lt = false, u32::MAX - 1", u32::MAX, u32::MAX - 1, 0);
        verify("lt = false, u32::MAX > 0", u32::MAX, 0, 0);
        verify("lt = false, 2 > 1", 2, 1, 0);
    }

    #[test]
    fn test_sltu_random() {
        let mut rng = rand::thread_rng();
        let a: u32 = rng.gen();
        let b: u32 = rng.gen();
        println!("random: {}, {}", a, b);
        verify("random 1", a, b, (a < b) as u32);
        verify("random 2", b, a, !(a < b) as u32);
    }
}
