use ceno_emul::{Change, StepRecord, Word};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    scheme::mock_prover::{MockProver, MOCK_PC_AND, MOCK_PC_OR, MOCK_PC_XOR, MOCK_PROGRAM},
    ROMType,
};

use super::*;

const A: Word = 0xbead1010;
const B: Word = 0xef552020;
// The pair of bytes from A and B.
const LOOKUPS: &[(u64, usize)] = &[(0x2010, 2), (0x55ad, 1), (0xefbe, 1)];

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

    let (raw_witin, lkm) = AndInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_AND,
            MOCK_PROGRAM[3],
            A,
            B,
            Change::new(0, A & B),
            0,
        )],
    )
    .unwrap();

    let lkm = lkm.into_finalize_result()[ROMType::And as usize].clone();
    assert_eq!(&lkm.into_iter().sorted().collect_vec(), LOOKUPS);

    MockProver::assert_satisfied(
        &mut cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
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

    let (raw_witin, lkm) = OrInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_OR,
            MOCK_PROGRAM[4],
            A,
            B,
            Change::new(0, A | B),
            0,
        )],
    )
    .unwrap();

    let lkm = lkm.into_finalize_result()[ROMType::Or as usize].clone();
    assert_eq!(&lkm.into_iter().sorted().collect_vec(), LOOKUPS);

    MockProver::assert_satisfied(
        &mut cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
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

    let (raw_witin, lkm) = XorInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_XOR,
            MOCK_PROGRAM[5],
            A,
            B,
            Change::new(0, A ^ B),
            0,
        )],
    )
    .unwrap();

    let lkm = lkm.into_finalize_result()[ROMType::Xor as usize].clone();
    assert_eq!(&lkm.into_iter().sorted().collect_vec(), LOOKUPS);

    MockProver::assert_satisfied(
        &mut cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
    );
}
