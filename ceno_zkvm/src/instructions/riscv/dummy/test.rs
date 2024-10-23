use ceno_emul::{Change, InsnKind, StepRecord, encode_rv32};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use super::*;
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{
        Instruction,
        riscv::{arith::AddOp, branch::BeqOp},
    },
    scheme::mock_prover::{MOCK_PC_START, MockProver},
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

    let insn_code = encode_rv32(InsnKind::ADD, 2, 3, 4, 0);
    let (raw_witin, lkm) = AddDummy::assign_instances(&config, cb.cs.num_witin as usize, vec![
        StepRecord::new_r_instruction(
            3,
            MOCK_PC_START,
            insn_code,
            11,
            0xfffffffe,
            Change::new(0, 11_u32.wrapping_add(0xfffffffe)),
            0,
        ),
    ])
    .unwrap();

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(Into::into)
            .collect_vec(),
        &[insn_code],
        None,
        Some(lkm),
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

    let insn_code = encode_rv32(InsnKind::BEQ, 2, 3, 0, 8);
    let (raw_witin, lkm) = BeqDummy::assign_instances(&config, cb.cs.num_witin as usize, vec![
        StepRecord::new_b_instruction(
            3,
            Change::new(MOCK_PC_START, MOCK_PC_START + 8_usize),
            insn_code,
            0xbead1010,
            0xbead1010,
            0,
        ),
    ])
    .unwrap();

    MockProver::assert_satisfied(
        &cb,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(Into::into)
            .collect_vec(),
        &[insn_code],
        None,
        Some(lkm),
    );
}
