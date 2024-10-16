use ceno_emul::{ByteAddr, Change, PC_STEP_SIZE, StepRecord, Word};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;

use super::*;
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    error::ZKVMError,
    instructions::Instruction,
    scheme::mock_prover::{
        MOCK_PC_BEQ, MOCK_PC_BGE, MOCK_PC_BGEU, MOCK_PC_BLT, MOCK_PC_BLTU, MOCK_PC_BNE,
        MOCK_PROGRAM, MockProver,
    },
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
    let (raw_witin, lkm) =
        BeqInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                3,
                Change::new(MOCK_PC_BEQ, MOCK_PC_BEQ + pc_offset),
                MOCK_PROGRAM[6],
                A,
                if equal { A } else { B },
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
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
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
    let (raw_witin, lkm) =
        BneInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                3,
                Change::new(MOCK_PC_BNE, MOCK_PC_BNE + pc_offset),
                MOCK_PROGRAM[7],
                A,
                if equal { A } else { B },
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
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
}

#[test]
fn test_bltu_circuit() -> Result<(), ZKVMError> {
    impl_bltu_circuit(false, 1, 0)?;
    impl_bltu_circuit(false, 0, 0)?;
    impl_bltu_circuit(false, 0xFFFF_FFFF, 0xFFFF_FFFF)?;

    impl_bltu_circuit(true, 0, 1)?;
    impl_bltu_circuit(true, 0xFFFF_FFFE, 0xFFFF_FFFF)?;
    impl_bltu_circuit(true, 0xEFFF_FFFF, 0xFFFF_FFFF)?;
    Ok(())
}

fn impl_bltu_circuit(taken: bool, a: u32, b: u32) -> Result<(), ZKVMError> {
    let mut cs = ConstraintSystem::new(|| "riscv");
    let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);
    let config = BltuInstruction::construct_circuit(&mut circuit_builder)?;

    let pc_after = if taken {
        ByteAddr(MOCK_PC_BLTU.0 - 8)
    } else {
        MOCK_PC_BLTU + PC_STEP_SIZE
    };

    let (raw_witin, lkm) =
        BltuInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_BLTU, pc_after),
                MOCK_PROGRAM[15],
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied(
        &circuit_builder,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
    Ok(())
}

#[test]
fn test_bgeu_circuit() -> Result<(), ZKVMError> {
    impl_bgeu_circuit(true, 1, 0)?;
    impl_bgeu_circuit(true, 0, 0)?;
    impl_bgeu_circuit(true, 0xFFFF_FFFF, 0xFFFF_FFFF)?;

    impl_bgeu_circuit(false, 0, 1)?;
    impl_bgeu_circuit(false, 0xFFFF_FFFE, 0xFFFF_FFFF)?;
    impl_bgeu_circuit(false, 0xEFFF_FFFF, 0xFFFF_FFFF)?;
    Ok(())
}

fn impl_bgeu_circuit(taken: bool, a: u32, b: u32) -> Result<(), ZKVMError> {
    let mut cs = ConstraintSystem::new(|| "riscv");
    let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);
    let config = BgeuInstruction::construct_circuit(&mut circuit_builder)?;

    let pc_after = if taken {
        ByteAddr(MOCK_PC_BGEU.0 - 8)
    } else {
        MOCK_PC_BGEU + PC_STEP_SIZE
    };

    let (raw_witin, lkm) =
        BgeuInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_BGEU, pc_after),
                MOCK_PROGRAM[16],
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied(
        &circuit_builder,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
    Ok(())
}

#[test]
fn test_blt_circuit() -> Result<(), ZKVMError> {
    impl_blt_circuit(false, 0, 0)?;
    impl_blt_circuit(true, 0, 1)?;

    impl_blt_circuit(false, 1, -10)?;
    impl_blt_circuit(false, -10, -10)?;
    impl_blt_circuit(false, -9, -10)?;
    impl_blt_circuit(true, -9, 1)?;
    impl_blt_circuit(true, -10, -9)?;
    Ok(())
}

fn impl_blt_circuit(taken: bool, a: i32, b: i32) -> Result<(), ZKVMError> {
    let mut cs = ConstraintSystem::new(|| "riscv");
    let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);
    let config = BltInstruction::construct_circuit(&mut circuit_builder)?;

    let pc_after = if taken {
        ByteAddr(MOCK_PC_BLT.0 - 8)
    } else {
        MOCK_PC_BLT + PC_STEP_SIZE
    };

    let (raw_witin, lkm) =
        BltInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_BLT, pc_after),
                MOCK_PROGRAM[8],
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied(
        &circuit_builder,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
    Ok(())
}

#[test]
fn test_bge_circuit() -> Result<(), ZKVMError> {
    impl_bge_circuit(true, 0, 0)?;
    impl_bge_circuit(false, 0, 1)?;

    impl_bge_circuit(true, 1, -10)?;
    impl_bge_circuit(true, -10, -10)?;
    impl_bge_circuit(true, -9, -10)?;
    impl_bge_circuit(false, -9, 1)?;
    impl_bge_circuit(false, -10, -9)?;
    Ok(())
}

fn impl_bge_circuit(taken: bool, a: i32, b: i32) -> Result<(), ZKVMError> {
    let mut cs = ConstraintSystem::new(|| "riscv");
    let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);
    let config = BgeInstruction::construct_circuit(&mut circuit_builder)?;

    let pc_after = if taken {
        ByteAddr(MOCK_PC_BGE.0 - 8)
    } else {
        MOCK_PC_BGE + PC_STEP_SIZE
    };

    let (raw_witin, lkm) =
        BgeInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_BGE, pc_after),
                MOCK_PROGRAM[17],
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied(
        &circuit_builder,
        &raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec(),
        None,
        Some(lkm),
    );
    Ok(())
}
