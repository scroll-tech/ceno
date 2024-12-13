use crate::{
    CENO_PLATFORM, InsnKind, Instruction, Platform, Program, StepRecord, VMState, encode_rv32,
    rv32im_encode::load_immediate, syscalls::KECCAK_PERMUTE,
};
use anyhow::Result;

pub const fn load_immediate(rd: u32, imm: u32) -> [u32; 2] {
    [
        encode_rv32(InsnKind::LUI, 0, 0, rd, imm),
        encode_rv32(InsnKind::ORI, rd, 0, rd, imm),
    ]
}

pub fn keccak_step() -> (StepRecord, Vec<Instruction>) {
    let instructions = [
        // Call Keccak-f.
        &load_immediate(Platform::reg_arg0() as u32, CENO_PLATFORM.ram.start)[..],
        &load_immediate(Platform::reg_ecall() as u32, KECCAK_PERMUTE)[..],
        &[encode_rv32(InsnKind::EANY, 0, 0, 0, 0)],
        // Halt.
        &load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt())[..],
        &[encode_rv32(InsnKind::EANY, 0, 0, 0, 0)],
    ]
    .concat();

    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(pc, pc, instructions.clone(), Default::default());
    let mut vm = VMState::new(CENO_PLATFORM, program.into());
    let steps = vm.iter_until_halt().collect::<Result<Vec<_>>>().unwrap();

    (steps[4].clone(), instructions)
}
