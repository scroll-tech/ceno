#[cfg(feature = "u16limb_circuit")]
mod slti_circuit_v2;

#[cfg(not(feature = "u16limb_circuit"))]
mod slti_circuit;

#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmInstruction;

#[cfg(not(feature = "u16limb_circuit"))]
use crate::instructions::riscv::slti::slti_circuit::SetLessThanImmInstruction;

use super::RIVInstruction;

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
    use ff_ext::{ExtensionField, GoldilocksExt2};

    use proptest::proptest;

    use super::*;
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{
            Instruction,
            riscv::{
                constants::UInt,
                test_utils::{i32_extra, imm_extra, immu_extra, u32_extra},
            },
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };
    #[cfg(feature = "u16limb_circuit")]
    use ff_ext::BabyBearExt4;

    #[test]
    fn test_sltiu_true() {
        let cases = vec![
            ("lt = true, 0 < 1", 0, 1i32),
            ("lt = true, 1 < 2", 1, 2),
            ("lt = true, 10 < 20", 10, 20),
            ("lt = true, 0 < imm upper boundary", 0, 2047),
            // negative imm is treated as positive
            ("lt = true, 0 < u32::MAX-1", 0, -1),
            ("lt = true, 1 < u32::MAX-1", 1, -1),
            ("lt = true, 0 < imm lower boundary", 0, -2048),
            ("lt = true, 65535 < imm lower boundary", 65535, -1),
        ];

        for &(name, a, imm) in &cases {
            verify::<SltiuOp, GoldilocksExt2>(name, a, imm, true);
            #[cfg(feature = "u16limb_circuit")]
            verify::<SltiuOp, BabyBearExt4>(name, a, imm, true);
        }
    }

    #[test]
    fn test_sltiu_false() {
        let cases = vec![
            ("lt = false, 1 < 0", 1, 0i32),
            ("lt = false, 2 < 1", 2, 1),
            ("lt = false, 100 < 50", 100, 50),
            ("lt = false, 500 < 100", 500, 100),
            ("lt = false, 100000 < 2047", 100_000, 2047),
            ("lt = false, 100000 < 0", 100_000, 0),
            ("lt = false, 0 == 0", 0, 0),
            ("lt = false, 1 == 1", 1, 1),
            ("lt = false, imm upper boundary", u32::MAX, 2047),
            ("lt = false, imm lower boundary", u32::MAX, -2048), /* negative imm treated as positive */
        ];

        for &(name, a, imm) in &cases {
            verify::<SltiuOp, GoldilocksExt2>(name, a, imm, false);
            #[cfg(feature = "u16limb_circuit")]
            verify::<SltiuOp, BabyBearExt4>(name, a, imm, false);
        }
    }

    proptest! {
        #[test]
        fn test_sltiu_prop(
            a in u32_extra(),
            imm in immu_extra(12),
        ) {
            verify::<SltiuOp, GoldilocksExt2>("random SltiuOp", a, imm as i32, a < imm);
            #[cfg(feature = "u16limb_circuit")]
            verify::<SltiuOp, BabyBearExt4>("random SltiuOp", a, imm as i32, a < imm);
        }
    }

    #[test]
    fn test_slti_true() {
        let cases = vec![
            ("lt = true, 0 < 1", 0, 1),
            ("lt = true, 1 < 2", 1, 2),
            ("lt = true, -1 < 0", -1, 0),
            ("lt = true, -1 < 1", -1, 1),
            ("lt = true, -2 < -1", -2, -1),
            // -2048 <= imm <= 2047
            ("lt = true, imm upper boundary", i32::MIN, 2047),
            ("lt = true, imm lower boundary", i32::MIN, -2048),
        ];

        for &(name, a, imm) in &cases {
            verify::<SltiOp, GoldilocksExt2>(name, a as u32, imm, true);
            #[cfg(feature = "u16limb_circuit")]
            verify::<SltiOp, BabyBearExt4>(name, a as u32, imm, true);
        }
    }

    #[test]
    fn test_slti_false() {
        let cases = vec![
            ("lt = false, 1 < 0", 1, 0),
            ("lt = false, 2 < 1", 2, 1),
            ("lt = false, 0 < -1", 0, -1),
            ("lt = false, 1 < -1", 1, -1),
            ("lt = false, -1 < -2", -1, -2),
            ("lt = false, 0 == 0", 0, 0),
            ("lt = false, 1 == 1", 1, 1),
            ("lt = false, -1 == -1", -1, -1),
            // -2048 <= imm <= 2047
            ("lt = false, imm upper boundary", i32::MAX, 2047),
            ("lt = false, imm lower boundary", i32::MAX, -2048),
        ];

        for &(name, a, imm) in &cases {
            verify::<SltiOp, GoldilocksExt2>(name, a as u32, imm, false);
            #[cfg(feature = "u16limb_circuit")]
            verify::<SltiOp, BabyBearExt4>(name, a as u32, imm, false);
        }
    }

    proptest! {
        #[test]
        fn test_slti_prop(
            a in i32_extra(),
            imm in imm_extra(12),
        ) {
            verify::<SltiOp, GoldilocksExt2>("random SltiOp", a as u32, imm, a < imm);
            #[cfg(feature = "u16limb_circuit")]
            verify::<SltiOp, BabyBearExt4>("random SltiOp", a as u32, imm, a < imm);
        }
    }

    fn verify<I: RIVInstruction, E: ExtensionField>(
        name: &'static str,
        rs1_read: u32,
        imm: i32,
        expected_rd: bool,
    ) {
        let expected_rd = expected_rd as u32;
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let insn_code = encode_rv32(I::INST_KIND, 2, 0, 4, imm);

        let config = cb
            .namespace(
                || format!("{:?}_({name})", I::INST_KIND),
                |cb| {
                    Ok(SetLessThanImmInstruction::<E, I>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    ))
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, lkm) = SetLessThanImmInstruction::<E, I>::assign_instances_from_steps(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &[StepRecord::new_i_instruction(
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
