#[cfg(not(feature = "u16limb_circuit"))]
mod shift_circuit;
#[cfg(feature = "u16limb_circuit")]
mod shift_circuit_v2;

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
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::{RIVInstruction, constants::UInt8},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
        utils::split_to_u8,
    };

    #[test]
    fn test_opcode_sll() {
        verify::<GoldilocksExt2, SllOp>("basic", 0b_0001, 3, 0b_1000);
        // 33 << 33 === 33 << 1
        verify::<GoldilocksExt2, SllOp>("rs2 over 5-bits", 0b_0001, 33, 0b_0010);
        verify::<GoldilocksExt2, SllOp>("bit loss", (1 << 31) | 1, 1, 0b_0010);
        verify::<GoldilocksExt2, SllOp>("zero shift", 0b_0001, 0, 0b_0001);
        verify::<GoldilocksExt2, SllOp>("all zeros", 0b_0000, 0, 0b_0000);
        verify::<GoldilocksExt2, SllOp>("base is zero", 0b_0000, 1, 0b_0000);
    }

    #[test]
    fn test_opcode_srl() {
        verify::<GoldilocksExt2, SrlOp>("basic", 0b_1000, 3, 0b_0001);
        // 33 >> 33 === 33 >> 1
        verify::<GoldilocksExt2, SrlOp>("rs2 over 5-bits", 0b_1010, 33, 0b_0101);
        verify::<GoldilocksExt2, SrlOp>("bit loss", 0b_1001, 1, 0b_0100);
        verify::<GoldilocksExt2, SrlOp>("zero shift", 0b_1000, 0, 0b_1000);
        verify::<GoldilocksExt2, SrlOp>("all zeros", 0b_0000, 0, 0b_0000);
        verify::<GoldilocksExt2, SrlOp>("base is zero", 0b_0000, 1, 0b_0000);
    }

    #[test]
    fn test_opcode_sra() {
        // positive rs1
        // rs2 = 3
        verify::<GoldilocksExt2, SraOp>("32 >> 3", 32, 3, 32 >> 3);
        verify::<GoldilocksExt2, SraOp>("33 >> 3", 33, 3, 33 >> 3);
        // rs2 = 31
        verify::<GoldilocksExt2, SraOp>("32 >> 31", 32, 31, 32 >> 31);
        verify::<GoldilocksExt2, SraOp>("33 >> 31", 33, 31, 33 >> 31);

        // negative rs1
        // rs2 = 3
        verify::<GoldilocksExt2, SraOp>("-32 >> 3", (-32_i32) as u32, 3, (-32_i32 >> 3) as u32);
        verify::<GoldilocksExt2, SraOp>("-33 >> 3", (-33_i32) as u32, 3, (-33_i32 >> 3) as u32);
        // rs2 = 31
        verify::<GoldilocksExt2, SraOp>("-32 >> 31", (-32_i32) as u32, 31, (-32_i32 >> 31) as u32);
        verify::<GoldilocksExt2, SraOp>("-33 >> 31", (-33_i32) as u32, 31, (-33_i32 >> 31) as u32);
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
                &UInt8::from_const_unchecked(split_to_u8::<u8>(expected_rd_written)),
            )
            .unwrap();

        let (raw_witin, lkm) = ShiftLogicalInstruction::<E, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_r_instruction(
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

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
