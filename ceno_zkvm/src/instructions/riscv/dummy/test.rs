use ceno_emul::{Change, StepRecord};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use super::*;
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{
        riscv::{arith::AddOp, branch::BeqOp},
        Instruction,
    },
    scheme::mock_prover::{MockProver, MOCK_PC_ADD, MOCK_PC_BEQ, MOCK_PROGRAM},
};

type AddDummy<E> = DummyInstruction<E, AddOp>;
type BeqDummy<E> = DummyInstruction<E, BeqOp>;

#[test]
fn test_dummy_r() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "add_dummy",
            |cb| {
                let config = AddDummy::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let (raw_witin, _) = AddDummy::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_r_instruction(
            3,
            MOCK_PC_ADD,
            MOCK_PROGRAM[0],
            11,
            0xfffffffe,
            Change::new(0, 11_u32.wrapping_add(0xfffffffe)),
            0,
        )],
    )
    .unwrap();

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(Into::into)
            .collect_vec(),
        None,
    );
}

#[test]
fn test_dummy_b() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "beq_dummy",
            |cb| {
                let config = BeqDummy::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let (raw_witin, _lkm) = BeqDummy::assign_instances(
        &config,
        cb.cs.num_witin as usize,
        vec![StepRecord::new_b_instruction(
            3,
            Change::new(MOCK_PC_BEQ, MOCK_PC_BEQ + 8_u32),
            MOCK_PROGRAM[6],
            0xbead1010,
            0xbead1010,
            0,
        )],
    )
    .unwrap();

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(Into::into)
            .collect_vec(),
        None,
    );
}
