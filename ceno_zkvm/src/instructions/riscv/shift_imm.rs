#[cfg(not(feature = "u16limb_circuit"))]
mod shift_imm_circuit;

use super::RIVInstruction;
use ceno_emul::InsnKind;

#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::shift::shift_circuit_v2::ShiftImmInstruction;
#[cfg(not(feature = "u16limb_circuit"))]
use crate::instructions::riscv::shift_imm::shift_imm_circuit::ShiftImmInstruction;

pub struct SlliOp;
impl RIVInstruction for SlliOp {
    const INST_KIND: InsnKind = InsnKind::SLLI;
}
pub type SlliInstruction<E> = ShiftImmInstruction<E, SlliOp>;

pub struct SraiOp;
impl RIVInstruction for SraiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRAI;
}
pub type SraiInstruction<E> = ShiftImmInstruction<E, SraiOp>;

pub struct SrliOp;
impl RIVInstruction for SrliOp {
    const INST_KIND: ceno_emul::InsnKind = InsnKind::SRLI;
}
pub type SrliInstruction<E> = ShiftImmInstruction<E, SrliOp>;

#[cfg(test)]
mod test {
    use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32u};
    use ff_ext::{ExtensionField, GoldilocksExt2};

    use super::{ShiftImmInstruction, SlliOp, SraiOp, SrliOp};
    #[cfg(not(feature = "u16limb_circuit"))]
    use crate::Value;
    #[cfg(not(feature = "u16limb_circuit"))]
    use crate::instructions::riscv::constants::UInt;
    #[cfg(feature = "u16limb_circuit")]
    use crate::instructions::riscv::constants::UInt8;
    #[cfg(feature = "u16limb_circuit")]
    use crate::utils::split_to_u8;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{Instruction, riscv::RIVInstruction},
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };
    #[cfg(feature = "u16limb_circuit")]
    use ff_ext::BabyBearExt4;

    #[test]
    fn test_opcode_slli() {
        let cases = [
            // imm = 3
            ("32 << 3", 32, 3, 32 << 3),
            ("33 << 3", 33, 3, 33 << 3),
            // imm = 31
            ("32 << 31", 32, 31, 32 << 31),
            ("33 << 31", 33, 31, 33 << 31),
        ];

        for (name, lhs, imm, expected) in cases {
            verify::<GoldilocksExt2, SlliOp>(name, lhs, imm, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SlliOp>(name, lhs, imm, expected);
        }
    }

    #[test]
    fn test_opcode_srai() {
        let cases = [
            // positive rs1
            ("32 >> 3", 32, 3, 32 >> 3),
            ("33 >> 3", 33, 3, 33 >> 3),
            ("32 >> 31", 32, 31, 32 >> 31),
            ("33 >> 31", 33, 31, 33 >> 31),
            // negative rs1
            ("-32 >> 3", (-32_i32) as u32, 3, (-32_i32 >> 3) as u32),
            ("-33 >> 3", (-33_i32) as u32, 3, (-33_i32 >> 3) as u32),
            ("-32 >> 31", (-32_i32) as u32, 31, (-32_i32 >> 31) as u32),
            ("-33 >> 31", (-33_i32) as u32, 31, (-33_i32 >> 31) as u32),
        ];

        for (name, lhs, imm, expected) in cases {
            verify::<GoldilocksExt2, SraiOp>(name, lhs, imm, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SraiOp>(name, lhs, imm, expected);
        }
    }

    #[test]
    fn test_opcode_srli() {
        let cases = [
            // imm = 3
            ("32 >> 3", 32, 3, 32 >> 3),
            ("33 >> 3", 33, 3, 33 >> 3),
            // imm = 31
            ("32 >> 31", 32, 31, 32 >> 31),
            ("33 >> 31", 33, 31, 33 >> 31),
            // rs1 top bit is 1
            ("-32 >> 3", (-32_i32) as u32, 3, ((-32_i32) as u32) >> 3),
        ];

        for (name, lhs, imm, expected) in cases {
            verify::<GoldilocksExt2, SrliOp>(name, lhs, imm, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SrliOp>(name, lhs, imm, expected);
        }
    }

    fn verify<E: ExtensionField, I: RIVInstruction>(
        name: &'static str,
        rs1_read: u32,
        imm: u32,
        expected_rd_written: u32,
    ) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let (prefix, insn_code, rd_written) = match I::INST_KIND {
            InsnKind::SLLI => (
                "SLLI",
                encode_rv32u(InsnKind::SLLI, 2, 0, 4, imm),
                rs1_read << imm,
            ),
            InsnKind::SRAI => (
                "SRAI",
                encode_rv32u(InsnKind::SRAI, 2, 0, 4, imm),
                (rs1_read as i32 >> imm as i32) as u32,
            ),
            InsnKind::SRLI => (
                "SRLI",
                encode_rv32u(InsnKind::SRLI, 2, 0, 4, imm),
                rs1_read >> imm,
            ),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                |cb| {
                    let config = ShiftImmInstruction::<E, I>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    );
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        config
            .rd_written
            .require_equal(
                || format!("{prefix}_({name})_assert_rd_written"),
                &mut cb,
                #[cfg(not(feature = "u16limb_circuit"))]
                &UInt::from_const_unchecked(
                    Value::new_unchecked(expected_rd_written)
                        .as_u16_limbs()
                        .to_vec(),
                ),
                #[cfg(feature = "u16limb_circuit")]
                &UInt8::from_const_unchecked(split_to_u8::<u8>(expected_rd_written)),
            )
            .unwrap();

        let (raw_witin, lkm) = ShiftImmInstruction::<E, I>::assign_instances(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                rs1_read,
                Change::new(0, rd_written),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
