use ceno_emul::{Change, StepRecord, Word};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{Instruction, riscv::constants::UInt8},
    scheme::mock_prover::{MOCK_PC_AND, MOCK_PC_OR, MOCK_PC_XOR, MOCK_PROGRAM, MockProver},
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

    let (raw_witin, lkm) =
        AndInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_r_instruction(
                3,
                MOCK_PC_AND,
                MOCK_PROGRAM[3],
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

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
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

    let (raw_witin, lkm) =
        OrInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_r_instruction(
                3,
                MOCK_PC_OR,
                MOCK_PROGRAM[4],
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

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
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

    let (raw_witin, lkm) =
        XorInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_r_instruction(
                3,
                MOCK_PC_XOR,
                MOCK_PROGRAM[5],
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

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
}
