use ceno_emul::{Change, StepRecord, Word, encode_rv32};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

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
    let config = cb.namespace(|| "and", AndInstruction::construct_circuit);

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
        ]);

    let expected_rd_written = UInt8::from_const_unchecked(split_to_u8::<u64>(A & B));

    config
        .rd_written
        .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written);

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
fn test_opcode_or() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb.namespace(|| "or", OrInstruction::construct_circuit);

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
        ]);

    let expected_rd_written = UInt8::from_const_unchecked(split_to_u8::<u64>(A | B));

    config
        .rd_written
        .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written);

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
fn test_opcode_xor() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb.namespace(|| "xor", XorInstruction::construct_circuit);

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
        ]);

    let expected_rd_written = UInt8::from_const_unchecked(split_to_u8::<u64>(A ^ B));

    config
        .rd_written
        .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written);

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
