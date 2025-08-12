#[cfg(feature = "u16limb_circuit")]
mod slti_circuit_v2;

#[cfg(not(feature = "u16limb_circuit"))]
mod slti_circuit;

#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmInstruction;

#[cfg(not(feature = "u16limb_circuit"))]
use crate::instructions::riscv::slti::slti_circuit::SetLessThanImmInstruction;

use super::{RIVInstruction, constants::UInt};
use crate::{structs::ProgramParams, uint::Value};

pub struct SltiOp;
impl RIVInstruction for SltiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLTI;
}
pub type SltiInstruction<E> = SetLessThanImmInstruction<E, SltiOp>;

pub struct SltiuOp;
impl RIVInstruction for SltiuOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLTIU;
}
pub type SltiuInstruction<E> = SetLessThanImmInstruction<E, SltiuOp>;

#[cfg(test)]
mod test {
    use ceno_emul::{Change, PC_STEP_SIZE, StepRecord, encode_rv32};
    use ff_ext::GoldilocksExt2;

    use proptest::proptest;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::test_utils::{i32_extra, imm_extra, immu_extra, u32_extra},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    #[test]
    fn test_sltiu_true() {
        let verify = |name, a, imm| verify::<SltiuOp>(name, a, imm, true);
        verify("lt = true, 0 < 1", 0, 1);
        verify("lt = true, 1 < 2", 1, 2);
        verify("lt = true, 10 < 20", 10, 20);
        verify("lt = true, 0 < imm upper boundary", 0, 2047);
        // negative imm is treated as positive
        verify("lt = true, 0 < u32::MAX-1", 0, -1);
        verify("lt = true, 1 < u32::MAX-1", 1, -1);
        verify("lt = true, 0 < imm lower bondary", 0, -2048);
        verify("lt = true, 65535 < imm lower bondary", 65535, -1);
    }

    #[test]
    fn test_sltiu_false() {
        let verify = |name, a, imm| verify::<SltiuOp>(name, a, imm, false);
        verify("lt = false, 1 < 0", 1, 0);
        verify("lt = false, 2 < 1", 2, 1);
        verify("lt = false, 100 < 50", 100, 50);
        verify("lt = false, 500 < 100", 500, 100);
        verify("lt = false, 100000 < 2047", 100000, 2047);
        verify("lt = false, 100000 < 0", 100000, 0);
        verify("lt = false, 0 == 0", 0, 0);
        verify("lt = false, 1 == 1", 1, 1);
        verify("lt = false, imm upper bondary", u32::MAX, 2047);
        // negative imm is treated as positive
        verify("lt = false, imm lower bondary", u32::MAX, -2048);
    }

    proptest! {
        #[test]
        fn test_sltiu_prop(
            a in u32_extra(),
            imm in immu_extra(12),
        ) {
            verify::<SltiuOp>("random SltiuOp", a, imm as i32, a < imm);
        }
    }

    #[test]
    fn test_slti_true() {
        let verify = |name, a: i32, imm| verify::<SltiOp>(name, a as u32, imm, true);
        verify("lt = true, 0 < 1", 0, 1);
        verify("lt = true, 1 < 2", 1, 2);
        verify("lt = true, -1 < 0", -1, 0);
        verify("lt = true, -1 < 1", -1, 1);
        verify("lt = true, -2 < -1", -2, -1);
        // -2048 <= imm <= 2047
        verify("lt = true, imm upper bondary", i32::MIN, 2047);
        verify("lt = true, imm lower bondary", i32::MIN, -2048);
    }

    #[test]
    fn test_slti_false() {
        let verify = |name, a: i32, imm| verify::<SltiOp>(name, a as u32, imm, false);
        verify("lt = false, 1 < 0", 1, 0);
        verify("lt = false, 2 < 1", 2, 1);
        verify("lt = false, 0 < -1", 0, -1);
        verify("lt = false, 1 < -1", 1, -1);
        verify("lt = false, -1 < -2", -1, -2);
        verify("lt = false, 0 == 0", 0, 0);
        verify("lt = false, 1 == 1", 1, 1);
        verify("lt = false, -1 == -1", -1, -1);
        // -2048 <= imm <= 2047
        verify("lt = false, imm upper bondary", i32::MAX, 2047);
        verify("lt = false, imm lower bondary", i32::MAX, -2048);
    }

    proptest! {
        #[test]
        fn test_slti_prop(
            a in i32_extra(),
            imm in imm_extra(12),
        ) {
            verify::<SltiOp>("random SltiOp", a as u32, imm, a < imm);
        }
    }

    fn verify<I: RIVInstruction>(name: &'static str, rs1_read: u32, imm: i32, expected_rd: bool) {
        let expected_rd = expected_rd as u32;
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let insn_code = encode_rv32(I::INST_KIND, 2, 0, 4, imm);

        let config = cb
            .namespace(
                || format!("{:?}_({name})", I::INST_KIND),
                |cb| {
                    Ok(
                        SetLessThanImmInstruction::<GoldilocksExt2, I>::construct_circuit(
                            cb,
                            &ProgramParams::default(),
                        ),
                    )
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, lkm) = SetLessThanImmInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                rs1_read,
                Change::new(0, expected_rd),
                0,
            )],
        )
        .unwrap();

        let expected_rd =
            UInt::from_const_unchecked(Value::new_unchecked(expected_rd).as_u16_limbs().to_vec());
        config
            .rd_written
            .require_equal(
                || format!("{:?}_({name})_assert_rd_written", I::INST_KIND),
                &mut cb,
                &expected_rd,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
