use ceno_emul::{Change, StepRecord, Word, PC_STEP_SIZE};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use super::*;
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::Instruction,
    scheme::mock_prover::{MockProver, MOCK_PC_BEQ, MOCK_PC_BNE, MOCK_PROGRAM},
};

const A: Word = 0xbead1010;
const B: Word = 0xef552020;

#[test]
fn test_opcode_beq() {
    impl_opcode_beq(false);
    impl_opcode_beq(true);
}

fn impl_opcode_beq(equal: bool) {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "beq",
            |cb| {
                let config = BeqInstruction::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let pc_offset = if equal { 8 } else { PC_STEP_SIZE };
    let (raw_witin, _lkm) = BeqInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_b_instruction(
            3,
            Change::new(MOCK_PC_BEQ, MOCK_PC_BEQ + pc_offset),
            MOCK_PROGRAM[6],
            A,
            if equal { A } else { B },
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
fn test_opcode_bne() {
    impl_opcode_bne(false);
    impl_opcode_bne(true);
}

fn impl_opcode_bne(equal: bool) {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "bne",
            |cb| {
                let config = BneInstruction::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let pc_offset = if equal { PC_STEP_SIZE } else { 8 };
    let (raw_witin, _lkm) = BneInstruction::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_b_instruction(
            3,
            Change::new(MOCK_PC_BNE, MOCK_PC_BNE + pc_offset),
            MOCK_PROGRAM[7],
            A,
            if equal { A } else { B },
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
