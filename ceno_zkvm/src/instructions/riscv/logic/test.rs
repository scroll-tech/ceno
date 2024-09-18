use ceno_emul::{Change, StepRecord};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    scheme::mock_prover::{MockProver, MOCK_PC_AND, MOCK_PC_OR, MOCK_PC_XOR, MOCK_PROGRAM},
};

use super::*;

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

    let (raw_witin, _) = AndInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_AND,
            MOCK_PROGRAM[3],
            0xbead1234,
            0xef550123,
            Change::new(0, 0xbead1234 & 0xef550123),
            0,
        )],
    )
    .unwrap();

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

    let (raw_witin, _) = OrInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_OR,
            MOCK_PROGRAM[4],
            0xbead1234,
            0xef550123,
            Change::new(0, 0xbead1234 | 0xef550123),
            0,
        )],
    )
    .unwrap();

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

    let (raw_witin, _) = XorInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_XOR,
            MOCK_PROGRAM[5],
            0xbead1234,
            0xef550123,
            Change::new(0, 0xbead1234 ^ 0xef550123),
            0,
        )],
    )
    .unwrap();

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
