use crate::{
    CENO_PLATFORM, InsnKind, Instruction, Platform, Program, StepRecord, VMState, encode_rv32,
    encode_rv32u,
    syscalls::{KECCAK_PERMUTE, SyscallWitness},
    tracer::FullTracerConfig,
};
use anyhow::Result;

pub fn keccak_step() -> (StepRecord, Vec<Instruction>, Vec<SyscallWitness>) {
    let instructions = vec![
        // Call Keccak-f.
        load_immediate(Platform::reg_arg0() as u32, CENO_PLATFORM.heap.start),
        load_immediate(Platform::reg_ecall() as u32, KECCAK_PERMUTE),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        // Halt.
        load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt()),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];

    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(
        pc,
        pc,
        CENO_PLATFORM.heap.start,
        instructions.clone(),
        Default::default(),
    );
    let mut vm: VMState = VMState::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.into(),
        FullTracerConfig {
            max_step_shard: 10,
        },
    );
    vm.iter_until_halt().collect::<Result<Vec<_>>>().unwrap();
    let steps = vm.tracer().recorded_steps();
    let syscall_witnesses = vm.tracer().syscall_witnesses().to_vec();

    (steps[2], instructions, syscall_witnesses)
}

const fn load_immediate(rd: u32, imm: u32) -> Instruction {
    encode_rv32u(InsnKind::ADDI, 0, 0, rd, imm)
}
