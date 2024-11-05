use ceno_emul::{ByteAddr, Change, PC_STEP_SIZE, StepRecord, Word, encode_rv32};
use goldilocks::GoldilocksExt2;

use super::*;
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    error::ZKVMError,
    instructions::{Instruction, riscv::test_utils::imm_b},
    scheme::mock_prover::{MOCK_PC_START, MockProver},
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

    let insn_code = encode_rv32(InsnKind::BEQ, 2, 3, 0, imm_b(8));
    let pc_offset = if equal { 8 } else { PC_STEP_SIZE };
    let (raw_witin, lkm) =
        BeqInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + pc_offset),
                insn_code,
                A,
                if equal { A } else { B },
                0,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
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

    let insn_code = encode_rv32(InsnKind::BNE, 2, 3, 0, imm_b(8));
    let pc_offset = if equal { PC_STEP_SIZE } else { 8 };
    let (raw_witin, lkm) =
        BneInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + pc_offset),
                insn_code,
                A,
                if equal { A } else { B },
                0,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
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
        ByteAddr(MOCK_PC_START.0 - 8)
    } else {
        MOCK_PC_START + PC_STEP_SIZE
    };

    let insn_code = encode_rv32(InsnKind::BLTU, 2, 3, 0, imm_b(-8));
    println!("{:#b}", insn_code);
    let (raw_witin, lkm) =
        BltuInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_START, pc_after),
                insn_code,
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied_raw(&circuit_builder, raw_witin, &[insn_code], None, Some(lkm));
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
        ByteAddr(MOCK_PC_START.0 - 8)
    } else {
        MOCK_PC_START + PC_STEP_SIZE
    };

    let insn_code = encode_rv32(InsnKind::BGEU, 2, 3, 0, imm_b(-8));
    let (raw_witin, lkm) =
        BgeuInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_START, pc_after),
                insn_code,
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied_raw(&circuit_builder, raw_witin, &[insn_code], None, Some(lkm));
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
        ByteAddr(MOCK_PC_START.0 - 8)
    } else {
        MOCK_PC_START + PC_STEP_SIZE
    };

    let insn_code = encode_rv32(InsnKind::BLT, 2, 3, 0, imm_b(-8));
    let (raw_witin, lkm) =
        BltInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_START, pc_after),
                insn_code,
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied_raw(&circuit_builder, raw_witin, &[insn_code], None, Some(lkm));
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
        ByteAddr(MOCK_PC_START.0 - 8)
    } else {
        MOCK_PC_START + PC_STEP_SIZE
    };

    let insn_code = encode_rv32(InsnKind::BGE, 2, 3, 0, imm_b(-8));
    let (raw_witin, lkm) =
        BgeInstruction::assign_instances(&config, circuit_builder.cs.num_witin as usize, vec![
            StepRecord::new_b_instruction(
                12,
                Change::new(MOCK_PC_START, pc_after),
                insn_code,
                a as Word,
                b as Word,
                10,
            ),
        ])
        .unwrap();

    MockProver::assert_satisfied_raw(&circuit_builder, raw_witin, &[insn_code], None, Some(lkm));
    Ok(())
}
