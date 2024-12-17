use ceno_emul::{Change, StepRecord, Word, encode_rv32};
use goldilocks::GoldilocksExt2;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{Instruction, riscv::constants::UInt8},
    scheme::mock_prover::{MOCK_PC_START, MockProver},
    utils::split_to_u8,
};

use super::*;

const A: Word = 0xbead1010;
const B: Word = 0xef552020;

#[test]
fn test_opcode_and() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "and",
            |cb| {
                let config = AndInstruction::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(InsnKind::AND, 2, 3, 4, 0);
    let (raw_witin, lkm) =
        AndInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                A,
                B,
                Change::new(0, A & B),
                0,
            ),
        ])
        .unwrap();

    let expected_rd_written = UInt8::from_const_unchecked(split_to_u8::<u64>(A & B));

    config
        .rd_written
        .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
        .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}

#[test]
fn test_opcode_or() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "or",
            |cb| {
                let config = OrInstruction::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(InsnKind::OR, 2, 3, 4, 0);
    let (raw_witin, lkm) =
        OrInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                A,
                B,
                Change::new(0, A | B),
                0,
            ),
        ])
        .unwrap();

    let expected_rd_written = UInt8::from_const_unchecked(split_to_u8::<u64>(A | B));

    config
        .rd_written
        .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
        .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}

#[test]
fn test_opcode_xor() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "xor",
            |cb| {
                let config = XorInstruction::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let insn_code = encode_rv32(InsnKind::XOR, 2, 3, 4, 0);
    let (raw_witin, lkm) =
        XorInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                A,
                B,
                Change::new(0, A ^ B),
                0,
            ),
        ])
        .unwrap();

    let expected_rd_written = UInt8::from_const_unchecked(split_to_u8::<u64>(A ^ B));

    config
        .rd_written
        .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
        .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}
