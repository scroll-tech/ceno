use crate::instructions::riscv::RIVInstruction;
use ceno_emul::InsnKind;

mod mulh_circuit;
mod mulh_circuit_v2;

pub struct MulOp;
impl RIVInstruction for MulOp {
    const INST_KIND: InsnKind = InsnKind::MUL;
}
#[cfg(feature = "u16limb_circuit")]
pub type MulInstruction<E> = mulh_circuit_v2::MulhInstructionBase<E, MulOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type MulInstruction<E> = mulh_circuit::MulhInstructionBase<E, MulOp>;

pub struct MulhOp;
impl RIVInstruction for MulhOp {
    const INST_KIND: InsnKind = InsnKind::MULH;
}
#[cfg(feature = "u16limb_circuit")]
pub type MulhInstruction<E> = mulh_circuit_v2::MulhInstructionBase<E, MulhOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type MulhInstruction<E> = mulh_circuit::MulhInstructionBase<E, MulhOp>;

pub struct MulhuOp;
impl RIVInstruction for MulhuOp {
    const INST_KIND: InsnKind = InsnKind::MULHU;
}

#[cfg(feature = "u16limb_circuit")]
pub type MulhuInstruction<E> = mulh_circuit_v2::MulhInstructionBase<E, MulhuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type MulhuInstruction<E> = mulh_circuit::MulhInstructionBase<E, MulhuOp>;

pub struct MulhsuOp;
impl RIVInstruction for MulhsuOp {
    const INST_KIND: InsnKind = InsnKind::MULHSU;
}
#[cfg(feature = "u16limb_circuit")]
pub type MulhsuInstruction<E> = mulh_circuit_v2::MulhInstructionBase<E, MulhsuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type MulhsuInstruction<E> = mulh_circuit::MulhInstructionBase<E, MulhsuOp>;

#[cfg(test)]
mod test {
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::{
                RIVInstruction,
                constants::UInt,
                mulh::{MulOp, MulhInstruction, MulhsuInstruction, MulhuOp},
            },
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
        witness::LkMultiplicity,
    };
    use ceno_emul::{Change, InsnKind, StepRecord, encode_rv32};
    use ff_ext::{ExtensionField, GoldilocksExt2};
    use gkr_iop::circuit_builder::DebugIndex;
    use multilinear_extensions::Expression;

    #[test]
    fn test_opcode_mul() {
        verify_mulu::<MulOp, GoldilocksExt2>("basic", 2, 11);
        verify_mulu::<MulOp, GoldilocksExt2>("2 * 0", 2, 0);
        verify_mulu::<MulOp, GoldilocksExt2>("0 * 0", 0, 0);
        verify_mulu::<MulOp, GoldilocksExt2>("0 * 2", 0, 2);
        verify_mulu::<MulOp, GoldilocksExt2>("0 * u32::MAX", 0, u32::MAX);
        // verify_mulu::<MulOp, GoldilocksExt2>("u32::MAX", u32::MAX, u32::MAX);
        verify_mulu::<MulOp, GoldilocksExt2>("u16::MAX", u16::MAX as u32, u16::MAX as u32);

        // verify_mulu::<MulOp, BabyBearExt4>("basic", 2, 11);
        // verify_mulu::<MulOp, BabyBearExt4>("2 * 0", 2, 0);
        // verify_mulu::<MulOp, BabyBearExt4>("0 * 0", 0, 0);
        // verify_mulu::<MulOp, BabyBearExt4>("0 * 2", 0, 2);
        // verify_mulu::<MulOp, BabyBearExt4>("0 * u32::MAX", 0, u32::MAX);
        // verify_mulu::<MulOp, BabyBearExt4>("u32::MAX", u32::MAX, u32::MAX);
        // verify_mulu::<MulOp, BabyBearExt4>("u16::MAX", u16::MAX as u32, u16::MAX as u32);
    }

    #[test]
    fn test_opcode_mulhu() {
        verify_mulu::<MulhuOp, GoldilocksExt2>("basic", 2, 11);
        verify_mulu::<MulhuOp, GoldilocksExt2>("2 * 0", 2, 0);
        verify_mulu::<MulhuOp, GoldilocksExt2>("0 * 0", 0, 0);
        verify_mulu::<MulhuOp, GoldilocksExt2>("0 * 2", 0, 2);
        verify_mulu::<MulhuOp, GoldilocksExt2>("0 * u32::MAX", 0, u32::MAX);
        // verify_mulu::<MulhuOp, GoldilocksExt2>("u32::MAX", u32::MAX, u32::MAX);
        verify_mulu::<MulhuOp, GoldilocksExt2>("u16::MAX", u16::MAX as u32, u16::MAX as u32);

        // verify_mulu::<MulhuOp, BabyBearExt4>("basic", 2, 11);
        // verify_mulu::<MulhuOp, BabyBearExt4>("2 * 0", 2, 0);
        // verify_mulu::<MulhuOp, BabyBearExt4>("0 * 0", 0, 0);
        // verify_mulu::<MulhuOp, BabyBearExt4>("0 * 2", 0, 2);
        // verify_mulu::<MulhuOp, BabyBearExt4>("0 * u32::MAX", 0, u32::MAX);
        // verify_mulu::<MulhuOp, BabyBearExt4>("u32::MAX", u32::MAX, u32::MAX);
        // verify_mulu::<MulhuOp, BabyBearExt4>("u16::MAX", u16::MAX as u32, u16::MAX as u32);
    }

    fn verify_mulu<I: RIVInstruction, E: ExtensionField>(name: &'static str, rs1: u32, rs2: u32) {
        #[cfg(not(feature = "u16limb_circuit"))]
        use super::mulh_circuit::MulhInstructionBase;
        #[cfg(feature = "u16limb_circuit")]
        use super::mulh_circuit_v2::MulhInstructionBase;

        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("{:?}_({name})", I::INST_KIND),
                |cb| {
                    Ok(MulhInstructionBase::<E, I>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    ))
                },
            )
            .unwrap()
            .unwrap();

        let outcome = match I::INST_KIND {
            InsnKind::MUL => rs1.wrapping_mul(rs2),
            InsnKind::MULHU => {
                let a = Value::<'_, u32>::new_unchecked(rs1);
                let b = Value::<'_, u32>::new_unchecked(rs2);
                let value_mul = a.mul_hi(&b, &mut LkMultiplicity::default(), true);
                value_mul.as_hi_value::<u32>().as_u32()
            }
            _ => unreachable!("Unsupported instruction kind"),
        };

        // values assignment
        let insn_code = encode_rv32(I::INST_KIND, 2, 3, 4, 0);
        let (raw_witin, lkm) = MulhInstructionBase::<E, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1,
                rs2,
                Change::new(0, outcome),
                0,
            )],
        )
        .unwrap();

        // verify value write to register, which is only hi
        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(outcome).as_u16_limbs().to_vec());
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            expected_rd_written.value(),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_opcode_mulh() {
        let test_cases = vec![
            (2, 11),
            (7, 0),
            (0, 5),
            // (0, -3),
            // (-19, 0),
            (0, 0),
            // (-12, -31),
            // (2, -1),
            // (1, i32::MIN),
            // (i32::MAX, -1),
            // (i32::MAX, i32::MIN),
            // (i32::MAX, i32::MAX),
            // (i32::MIN, i32::MIN),
        ];
        test_cases
            .iter()
            .for_each(|(rs1, rs2)| verify_mulh::<GoldilocksExt2>(*rs1, *rs2));
        // test_cases
        //     .iter()
        //     .for_each(|(rs1, rs2)| verify_mulh::<BabyBearExt4>(*rs1, *rs2));
    }

    fn verify_mulh<E: ExtensionField>(rs1: i32, rs2: i32) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "mulh",
                |cb| {
                    Ok(MulhInstruction::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    ))
                },
            )
            .unwrap()
            .unwrap();

        let signed_prod_high = ((rs1 as i64).wrapping_mul(rs2 as i64) >> 32) as u32;

        // values assignment
        let insn_code = encode_rv32(InsnKind::MULH, 2, 3, 4, 0);
        let (raw_witin, lkm) = MulhInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1 as u32,
                rs2 as u32,
                Change::new(0, signed_prod_high),
                0,
            )],
        )
        .unwrap();

        // verify value written to register
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            Expression::from(signed_prod_high),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_opcode_mulhsu() {
        let test_cases = vec![
            (0, 0),
            (0, 5),
            (0, u32::MAX),
            (7, 0),
            (2, 11),
            (91, u32::MAX),
            (i32::MAX, 0),
            (i32::MAX, 2),
            // (i32::MAX, u32::MAX), TODO: this causes carry exceed 16 bits, fix later
            // (-4, 0),
            // (-1, 3),
            // (-1000, u32::MAX), TODO: this causes carry exceed 16 bits, fix later
            (i32::MIN, 0),
            (i32::MIN, 21),
            // (i32::MIN, u32::MAX),
        ];
        test_cases
            .iter()
            .for_each(|(rs1, rs2)| verify_mulhsu::<GoldilocksExt2>(*rs1, *rs2));
        // test_cases
        //     .iter()
        //     .for_each(|(rs1, rs2)| verify_mulhsu::<BabyBearExt4>(*rs1, *rs2));
    }

    fn verify_mulhsu<E: ExtensionField>(rs1: i32, rs2: u32) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "mulhsu",
                |cb| {
                    Ok(MulhsuInstruction::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    ))
                },
            )
            .unwrap()
            .unwrap();

        let signed_unsigned_prod_high = ((rs1 as i64).wrapping_mul(rs2 as i64) >> 32) as u32;

        // values assignment
        let insn_code = encode_rv32(InsnKind::MULHSU, 2, 3, 4, 0);
        let (raw_witin, lkm) = MulhsuInstruction::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1 as u32,
                rs2,
                Change::new(0, signed_unsigned_prod_high),
                0,
            )],
        )
        .unwrap();

        // verify value written to register
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            Expression::from(signed_unsigned_prod_high),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
