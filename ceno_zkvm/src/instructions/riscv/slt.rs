use std::marker::PhantomData;

use ceno_emul::{InsnKind, SWord, StepRecord};
use ff_ext::ExtensionField;

use super::{constants::UInt, r_insn::RInstructionConfig};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, gadgets::SignedLtConfig,
    instructions::Instruction, uint::Value, witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// This config handles R-Instructions that represent registers values as 2 * u16.
#[derive(Debug)]
pub struct SltConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    #[allow(dead_code)]
    rd_written: UInt<E>,

    signed_lt: SignedLtConfig,
}

pub struct SltInstruction<E>(PhantomData<E>);

// TODO combine with SLTU
impl<E: ExtensionField> Instruction<E> for SltInstruction<E> {
    type InstructionConfig = SltConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::SLT)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // If rs1_read < rs2_read, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", cb)?;

        let lt = SignedLtConfig::construct_circuit(cb, || "rs1 < rs2", &rs1_read, &rs2_read)?;
        let rd_written = UInt::from_exprs_unchecked(vec![lt.expr()]);

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            cb,
            InsnKind::SLT,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(SltConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
            signed_lt: lt,
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
            .signed_lt
            .assign_instance::<E>(instance, lkm, rs1 as SWord, rs2 as SWord)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord, Word, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;
    use rand::Rng;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    fn verify(name: &'static str, rs1: i32, rs2: i32, rd: Word) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("SLT/{name}"),
                |cb| {
                    let config = SltInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::SLT, 2, 3, 4, 0);
        let (raw_witin, lkm) =
            SltInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
                StepRecord::new_r_instruction(
                    3,
                    MOCK_PC_START,
                    insn_code,
                    rs1 as Word,
                    rs2 as Word,
                    Change::new(0, rd),
                    0,
                ),
            ])
            .unwrap();

        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());
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

    #[test]
    fn test_slt_true() {
        verify("lt = true, 0 < 1", 0, 1, 1);
        verify("lt = true, 1 < 2", 1, 2, 1);
        verify("lt = true, -1 < 0", -1, 0, 1);
        verify("lt = true, -1 < 1", -1, 1, 1);
        verify("lt = true, -2 < -1", -2, -1, 1);
        verify("lt = true, large number", i32::MIN, i32::MAX, 1);
    }

    #[test]
    fn test_slt_false() {
        verify("lt = false, 1 < 0", 1, 0, 0);
        verify("lt = false, 2 < 1", 2, 1, 0);
        verify("lt = false, 0 < -1", 0, -1, 0);
        verify("lt = false, 1 < -1", 1, -1, 0);
        verify("lt = false, -1 < -2", -1, -2, 0);
        verify("lt = false, 0 == 0", 0, 0, 0);
        verify("lt = false, 1 == 1", 1, 1, 0);
        verify("lt = false, -1 == -1", -1, -1, 0);
        // This case causes subtract overflow in `assign_instance_signed`
        verify("lt = false, large number", i32::MAX, i32::MIN, 0);
    }

    #[test]
    fn test_slt_random() {
        let mut rng = rand::thread_rng();
        let a: i32 = rng.gen();
        let b: i32 = rng.gen();
        println!("random: {} <? {}", a, b); // For debugging, do not delete.
        verify("random 1", a, b, (a < b) as u32);
        verify("random 2", b, a, (a >= b) as u32);
    }
}
