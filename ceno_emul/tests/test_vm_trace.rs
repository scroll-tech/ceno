#![allow(clippy::unusual_byte_groupings)]
use anyhow::Result;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use ceno_emul::{
    CENO_PLATFORM, Cycle, EmuContext, InsnKind, Instruction, Platform, Program, StepRecord, Tracer,
    VMState, WordAddr, encode_rv32,
};

#[test]
fn test_vm_trace() -> Result<()> {
    let program = Program::new(
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.heap.start,
        program_fibonacci_20(),
        Default::default(),
    );
    let mut ctx = VMState::new(CENO_PLATFORM, Arc::new(program));

    let steps = run(&mut ctx)?;

    let (x1, x2, x3) = expected_fibonacci_20();
    assert_eq!(ctx.peek_register(1), x1);
    assert_eq!(ctx.peek_register(2), x2);
    assert_eq!(ctx.peek_register(3), x3);

    let ops: Vec<InsnKind> = steps.iter().map(|step| step.insn().kind).collect();
    assert_eq!(ops, expected_ops_fibonacci_20());

    assert_eq!(
        ctx.tracer().final_accesses(),
        &expected_final_accesses_fibonacci_20()
    );

    Ok(())
}

#[test]
fn test_empty_program() -> Result<()> {
    let empty_program = Program::new(
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.heap.start,
        vec![],
        BTreeMap::new(),
    );
    let mut ctx = VMState::new(CENO_PLATFORM, Arc::new(empty_program));
    let res = run(&mut ctx);
    assert!(matches!(res, Err(e) if e.to_string().contains("InstructionAccessFault")),);
    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    state.iter_until_halt().collect()
}

/// Example in RISC-V bytecode and assembly.
pub fn program_fibonacci_20() -> Vec<Instruction> {
    vec![
        // x1 = 10;
        // x3 = 1;
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 10),
        encode_rv32(InsnKind::ADDI, 0, 0, 3, 1),
        // loop {
        //     x1 -= 1;
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        //     x2 += x3;
        //     x3 += x2;
        encode_rv32(InsnKind::ADD, 2, 3, 2, 0),
        encode_rv32(InsnKind::ADD, 2, 3, 3, 0),
        //     if x1 == 0 { break }
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        // ecall HALT, SUCCESS
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]
}

/// Rust version of the example. Reconstruct the output.
fn expected_fibonacci_20() -> (u32, u32, u32) {
    let mut x1 = 10;
    let mut x2 = 0; // Even.
    let mut x3 = 1; // Odd.

    loop {
        x1 -= 1;
        x2 += x3;
        x3 += x2;
        if x1 == 0 {
            break;
        }
    }

    assert_eq!(x2, 6765); // Fibonacci 20.
    assert_eq!(x3, 10946); // Fibonacci 21.
    (x1, x2, x3)
}

/// Reconstruct the sequence of opcodes.
fn expected_ops_fibonacci_20() -> Vec<InsnKind> {
    use InsnKind::*;
    let mut ops = vec![ADDI, ADDI];
    for _ in 0..10 {
        ops.extend(&[ADDI, ADD, ADD, BNE]);
    }
    ops.push(ECALL);
    ops
}

/// Reconstruct the last access of each register.
fn expected_final_accesses_fibonacci_20() -> HashMap<WordAddr, Cycle> {
    let mut accesses = HashMap::new();
    let x = |i| WordAddr::from(Platform::register_vma(i));
    const C: Cycle = Tracer::SUBCYCLES_PER_INSN;

    let mut cycle = C; // First cycle.
    cycle += 2 * C; // Set x1 and x3.
    for _ in 0..9 {
        // Loop except the last iteration.
        cycle += 4 * C; // ADDI, ADD, ADD, BNE.
    }
    cycle += 2 * C; // Last iteration ADDI and ADD.

    // Last ADD.
    accesses.insert(x(2), cycle + Tracer::SUBCYCLE_RS1);
    accesses.insert(x(3), cycle + Tracer::SUBCYCLE_RD);
    cycle += C;

    // Last BNE.
    accesses.insert(x(1), cycle + Tracer::SUBCYCLE_RS1);
    accesses.insert(x(0), cycle + Tracer::SUBCYCLE_RS2);
    cycle += C;

    // Now at the final ECALL cycle.
    accesses.insert(x(Platform::reg_ecall()), cycle + Tracer::SUBCYCLE_RS1);
    accesses.insert(x(Platform::reg_arg0()), cycle + Tracer::SUBCYCLE_RS2);

    accesses
}
