#[cfg(not(feature = "u16limb_circuit"))]
mod slt_circuit;
#[cfg(feature = "u16limb_circuit")]
mod slt_circuit_v2;

use ceno_emul::InsnKind;

use super::RIVInstruction;

pub struct SltOp;
impl RIVInstruction for SltOp {
    const INST_KIND: InsnKind = InsnKind::SLT;
}
#[cfg(feature = "u16limb_circuit")]
pub type SltInstruction<E> = slt_circuit_v2::SetLessThanInstruction<E, SltOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type SltInstruction<E> = slt_circuit::SetLessThanInstruction<E, SltOp>;

pub struct SltuOp;
impl RIVInstruction for SltuOp {
    const INST_KIND: InsnKind = InsnKind::SLTU;
}
#[cfg(feature = "u16limb_circuit")]
pub type SltuInstruction<E> = slt_circuit_v2::SetLessThanInstruction<E, SltuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type SltuInstruction<E> = slt_circuit::SetLessThanInstruction<E, SltuOp>;

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord, Word, encode_rv32};
    #[cfg(feature = "u16limb_circuit")]
    use ff_ext::BabyBearExt4;
    use ff_ext::{ExtensionField, GoldilocksExt2};

    use rand::RngCore;

    use super::*;
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::constants::UInt},
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };
    #[cfg(not(feature = "u16limb_circuit"))]
    use slt_circuit::SetLessThanInstruction;
    #[cfg(feature = "u16limb_circuit")]
    use slt_circuit_v2::SetLessThanInstruction;

    fn verify<E: ExtensionField, I: RIVInstruction>(
        name: &'static str,
        rs1: Word,
        rs2: Word,
        rd: Word,
    ) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("{}/{name}", I::INST_KIND),
                |cb| {
                    let config = SetLessThanInstruction::<_, I>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    );
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(I::INST_KIND, 2, 3, 4, 0);
        let (raw_witin, lkm) = SetLessThanInstruction::<_, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
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

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_slt_true() {
        let cases = vec![
            ("lt = true, 0 < 1", 0, 1, 1),
            ("lt = true, 1 < 2", 1, 2, 1),
            ("lt = true, -1 < 0", -1i32 as Word, 0, 1),
            ("lt = true, -1 < 1", -1i32 as Word, 1, 1),
            ("lt = true, -2 < -1", -2i32 as Word, -1i32 as Word, 1),
            (
                "lt = true, large number",
                i32::MIN as Word,
                i32::MAX as Word,
                1,
            ),
        ];
        for &(name, a, b, expected) in &cases {
            verify::<GoldilocksExt2, SltOp>(name, a, b, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SltOp>(name, a, b, expected);
        }
    }

    #[test]
    fn test_slt_false() {
        let cases = vec![
            ("lt = false, 1 < 0", 1, 0, 0),
            ("lt = false, 2 < 1", 2, 1, 0),
            ("lt = false, 0 < -1", 0, -1i32 as Word, 0),
            ("lt = false, 1 < -1", 1, -1i32 as Word, 0),
            ("lt = false, -1 < -2", -1i32 as Word, -2i32 as Word, 0),
            ("lt = false, 0 == 0", 0, 0, 0),
            ("lt = false, 1 == 1", 1, 1, 0),
            ("lt = false, -1 == -1", -1i32 as Word, -1i32 as Word, 0),
            // This case causes subtract overflow in `assign_instance_signed`
            (
                "lt = false, large number",
                i32::MAX as Word,
                i32::MIN as Word,
                0,
            ),
        ];
        for &(name, a, b, expected) in &cases {
            verify::<GoldilocksExt2, SltOp>(name, a, b, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SltOp>(name, a, b, expected);
        }
    }

    #[test]
    fn test_slt_random() {
        let mut rng = rand::thread_rng();
        let a: i32 = rng.next_u32() as i32;
        let b: i32 = rng.next_u32() as i32;
        verify::<GoldilocksExt2, SltOp>("random 1", a as Word, b as Word, (a < b) as u32);
        verify::<GoldilocksExt2, SltOp>("random 2", b as Word, a as Word, (a >= b) as u32);
        #[cfg(feature = "u16limb_circuit")]
        verify::<BabyBearExt4, SltOp>("random 1", a as Word, b as Word, (a < b) as u32);
        #[cfg(feature = "u16limb_circuit")]
        verify::<BabyBearExt4, SltOp>("random 2", b as Word, a as Word, (a >= b) as u32);
    }

    #[test]
    fn test_sltu_simple() {
        let cases = vec![
            ("lt = true, 0 < 1", 0, 1, 1),
            ("lt = true, 1 < 2", 1, 2, 1),
            ("lt = true, 0 < u32::MAX", 0, u32::MAX, 1),
            ("lt = true, u32::MAX - 1", u32::MAX - 1, u32::MAX, 1),
            ("lt = false, u32::MAX", u32::MAX, u32::MAX, 0),
            ("lt = false, u32::MAX - 1", u32::MAX, u32::MAX - 1, 0),
            ("lt = false, u32::MAX > 0", u32::MAX, 0, 0),
            ("lt = false, 2 > 1", 2, 1, 0),
        ];
        for &(name, a, b, expected) in &cases {
            verify::<GoldilocksExt2, SltuOp>(name, a, b, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SltuOp>(name, a, b, expected);
        }
    }

    #[test]
    fn test_sltu_random() {
        let mut rng = rand::thread_rng();
        let a: u32 = rng.next_u32();
        let b: u32 = rng.next_u32();
        verify::<GoldilocksExt2, SltuOp>("random 1", a, b, (a < b) as u32);
        verify::<GoldilocksExt2, SltuOp>("random 2", b, a, (a >= b) as u32);
        #[cfg(feature = "u16limb_circuit")]
        verify::<BabyBearExt4, SltuOp>("random 1", a, b, (a < b) as u32);
        #[cfg(feature = "u16limb_circuit")]
        verify::<BabyBearExt4, SltuOp>("random 2", b, a, (a >= b) as u32);
    }
}
