#[cfg(not(feature = "u16limb_circuit"))]
pub mod shift_circuit;
#[cfg(feature = "u16limb_circuit")]
pub mod shift_circuit_v2;

use ceno_emul::InsnKind;

use super::RIVInstruction;
#[cfg(not(feature = "u16limb_circuit"))]
use crate::instructions::riscv::shift::shift_circuit::ShiftLogicalInstruction;
#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::shift::shift_circuit_v2::ShiftLogicalInstruction;

pub struct SllOp;
impl RIVInstruction for SllOp {
    const INST_KIND: InsnKind = InsnKind::SLL;
}
pub type SllInstruction<E> = ShiftLogicalInstruction<E, SllOp>;

pub struct SrlOp;
impl RIVInstruction for SrlOp {
    const INST_KIND: InsnKind = InsnKind::SRL;
}
pub type SrlInstruction<E> = ShiftLogicalInstruction<E, SrlOp>;

pub struct SraOp;
impl RIVInstruction for SraOp {
    const INST_KIND: InsnKind = InsnKind::SRA;
}
pub type SraInstruction<E> = ShiftLogicalInstruction<E, SraOp>;

#[cfg(test)]
mod tests {
    use ceno_emul::{Change, InsnKind, StepRecord, encode_rv32};
    use ff_ext::{ExtensionField, GoldilocksExt2};

    use super::{ShiftLogicalInstruction, SllOp, SraOp, SrlOp};
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
    fn test_opcode_sll() {
        let cases = [
            ("basic 1", 32, 3, 32 << 3),
            ("basic 2", 0b_0001, 3, 0b_1000),
            // 33 << 33 === 33 << 1
            ("rs2 over 5-bits", 0b_0001, 33, 0b_0010),
            ("bit loss", (1 << 31) | 1, 1, 0b_0010),
            ("zero shift", 0b_0001, 0, 0b_0001),
            ("all zeros", 0b_0000, 0, 0b_0000),
            ("base is zero", 0b_0000, 1, 0b_0000),
        ];

        for (name, lhs, rhs, expected) in cases {
            verify::<GoldilocksExt2, SllOp>(name, lhs, rhs, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SllOp>(name, lhs, rhs, expected);
        }
    }

    #[test]
    fn test_opcode_srl() {
        let cases = [
            ("basic", 0b_1000, 3, 0b_0001),
            // 33 >> 33 === 33 >> 1
            ("rs2 over 5-bits", 0b_1010, 33, 0b_0101),
            ("bit loss", 0b_1001, 1, 0b_0100),
            ("zero shift", 0b_1000, 0, 0b_1000),
            ("all zeros", 0b_0000, 0, 0b_0000),
            ("base is zero", 0b_0000, 1, 0b_0000),
        ];

        for (name, lhs, rhs, expected) in cases {
            verify::<GoldilocksExt2, SrlOp>(name, lhs, rhs, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SrlOp>(name, lhs, rhs, expected);
        }
    }

    #[test]
    fn test_opcode_sra() {
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

        for (name, lhs, rhs, expected) in cases {
            verify::<GoldilocksExt2, SraOp>(name, lhs, rhs, expected);
            #[cfg(feature = "u16limb_circuit")]
            verify::<BabyBearExt4, SraOp>(name, lhs, rhs, expected);
        }
    }

    fn verify<E: ExtensionField, I: RIVInstruction>(
        name: &'static str,
        rs1_read: u32,
        rs2_read: u32,
        expected_rd_written: u32,
    ) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let shift = rs2_read & 0b11111;
        let (prefix, insn_code, rd_written) = match I::INST_KIND {
            InsnKind::SLL => (
                "SLL",
                encode_rv32(InsnKind::SLL, 2, 3, 4, 0),
                rs1_read << shift,
            ),
            InsnKind::SRL => (
                "SRL",
                encode_rv32(InsnKind::SRL, 2, 3, 4, 0),
                rs1_read >> shift,
            ),
            InsnKind::SRA => (
                "SRA",
                encode_rv32(InsnKind::SRA, 2, 3, 4, 0),
                (rs1_read as i32 >> shift) as u32,
            ),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                |cb| {
                    Ok(ShiftLogicalInstruction::<E, I>::construct_circuit(
                        cb,
                        &ProgramParams::default(),
                    ))
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

        let (raw_witin, lkm) = ShiftLogicalInstruction::<E, I>::assign_instances(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            &[StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1_read,
                rs2_read,
                Change::new(0, rd_written),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], 1, None, Some(lkm));
    }
}
