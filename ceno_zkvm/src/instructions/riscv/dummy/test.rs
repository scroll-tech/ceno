use ceno_emul::{Change, InsnKind, KeccakSpec, StepRecord, encode_rv32};
use goldilocks::GoldilocksExt2;

use super::*;
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{
        Instruction,
        riscv::{arith::AddOp, branch::BeqOp, ecall::EcallDummy},
    },
    scheme::mock_prover::{MOCK_PC_START, MockProver},
};

type AddDummy<E> = DummyInstruction<E, AddOp>;
type BeqDummy<E> = DummyInstruction<E, BeqOp>;

#[test]
fn test_dummy_ecall() {
    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "ecall_dummy",
            |cb| {
                let config = EcallDummy::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let step = StepRecord::new_ecall_any(4, MOCK_PC_START);
    let insn_code = step.insn();
    let (raw_witin, lkm) =
        EcallDummy::assign_instances(&config, cb.cs.num_witin as usize, vec![step]).unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}

#[test]
fn test_dummy_keccak() {
    type KeccakDummy = LargeEcallDummy<GoldilocksExt2, KeccakSpec>;

    let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config = cb
        .namespace(
            || "keccak_dummy",
            |cb| {
                let config = KeccakDummy::construct_circuit(cb);
                Ok(config)
            },
        )
        .unwrap()
        .unwrap();

    let (step, program) = ceno_emul::test_utils::keccak_step();
    let (raw_witin, lkm) =
        KeccakDummy::assign_instances(&config, cb.cs.num_witin as usize, vec![step]).unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &program, None, Some(lkm));
}

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

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
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

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
}
