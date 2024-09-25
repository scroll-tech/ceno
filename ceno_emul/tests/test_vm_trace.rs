use anyhow::Result;
use std::collections::HashMap;

use ceno_emul::{
    ByteAddr, Cycle, EmuContext, InsnKind, StepRecord, Tracer, VMState, WordAddr, CENO_PLATFORM,
};

#[test]
fn test_vm_trace() -> Result<()> {
    let mut ctx = VMState::new(CENO_PLATFORM);

    let pc_start = ByteAddr(CENO_PLATFORM.pc_start()).waddr();
    for (i, &inst) in PROGRAM_FIBONACCI_20.iter().enumerate() {
        ctx.init_memory(pc_start + i as u32, inst);
    }

    let steps = run(&mut ctx)?;

    let (x1, x2, x3) = expected_fibonacci_20();
    assert_eq!(ctx.peek_register(1), x1);
    assert_eq!(ctx.peek_register(2), x2);
    assert_eq!(ctx.peek_register(3), x3);

    let ops: Vec<InsnKind> = steps.iter().map(|step| step.insn().kind().1).collect();
    assert_eq!(ops, expected_ops_fibonacci_20());

    assert_eq!(
        ctx.tracer().final_accesses(),
        &expected_final_accesses_fibonacci_20()
    );

    Ok(())
}

#[test]
fn test_empty_program() -> Result<()> {
    let mut ctx = VMState::new(CENO_PLATFORM);
    let res = run(&mut ctx);
    assert!(matches!(res, Err(e) if e.to_string().contains("IllegalInstruction(0)")));
    Ok(())
}

fn run(state: &mut VMState) -> Result<Vec<StepRecord>> {
    state.iter_until_halt().collect()
}

/// Example in RISC-V bytecode and assembly.
const PROGRAM_FIBONACCI_20: [u32; 7] = [
    // x1 = 10;
    // x3 = 1;
    // immediate    rs1  f3   rd   opcode
    0b_000000001010_00000_000_00001_0010011, // addi x1, x0, 10
    0b_000000000001_00000_000_00011_0010011, // addi x3, x0, 1
    // loop {
    //     x1 -= 1;
    // immediate    rs1  f3   rd   opcode
    0b_111111111111_00001_000_00001_0010011, // addi x1, x1, -1
    //     x2 += x3;
    //     x3 += x2;
    // zeros   rs2   rs1   f3  rd    opcode
    0b_0000000_00011_00010_000_00010_0110011, // add x2, x2, x3
    0b_0000000_00011_00010_000_00011_0110011, // add x3, x2, x3
    //     if x1 == 0 { break }
    // imm      rs2   rs1   f3  imm    opcode
    0b_1_111111_00000_00001_001_1010_1_1100011, // bne x1, x0, -12
    // ecall HALT, SUCCESS
    0b_000000000000_00000_000_00000_1110011,
];

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
    ops.push(EANY);
    ops
}

/// Reconstruct the last access of each register.
fn expected_final_accesses_fibonacci_20() -> HashMap<WordAddr, Cycle> {
    let mut accesses = HashMap::new();
    let x = |i| WordAddr::from(CENO_PLATFORM.register_vma(i));
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
    accesses.insert(x(CENO_PLATFORM.reg_ecall()), cycle + Tracer::SUBCYCLE_RS1);
    accesses.insert(x(CENO_PLATFORM.reg_arg0()), cycle + Tracer::SUBCYCLE_RS2);

    accesses
}
