use std::collections::HashMap;

use super::rv32im::EmuContext;
use crate::{
    addr::{ByteAddr, WordAddr},
    platform::Platform,
    rv32im::{DecodedInstruction, Instruction, TrapCause},
};
use anyhow::{anyhow, Result};

/// An implementation of the machine state and of the side-effects of operations.
pub struct VMState {
    platform: Platform,
    pc: u32,
    /// Map a word-address (addr/4) to a word.
    memory: HashMap<u32, u32>,
    registers: [u32; 32],
    // Termination.
    succeeded: bool,
}

impl VMState {
    pub fn new(platform: Platform) -> Self {
        let pc = platform.pc_start();
        Self {
            platform,
            pc,
            memory: HashMap::new(),
            registers: [0; 32],
            succeeded: false,
        }
    }

    pub fn succeeded(&self) -> bool {
        self.succeeded
    }
}

impl EmuContext for VMState {
    // Expect an ecall to indicate a successful exit:
    // function HALT with argument SUCCESS.
    fn ecall(&mut self) -> Result<bool> {
        let function = self.load_register(self.platform.reg_ecall())?;
        let argument = self.load_register(self.platform.reg_arg0())?;
        if function == self.platform.ecall_halt() && argument == self.platform.code_success() {
            self.succeeded = true;
            Ok(true)
        } else {
            self.trap(TrapCause::EnvironmentCallFromUserMode)
        }
    }

    // No traps are implemented so MRET is not legal.
    fn mret(&self) -> Result<bool> {
        let mret = 0b001100000010_00000_000_00000_1110011;
        self.trap(TrapCause::IllegalInstruction(mret))
    }

    fn trap(&self, cause: TrapCause) -> Result<bool> {
        Err(anyhow!("Trap {:?}", cause)) // Crash.
    }

    fn on_insn_decoded(&self, kind: &Instruction, decoded: &DecodedInstruction) {}

    fn on_normal_end(&mut self, insn: &Instruction, decoded: &DecodedInstruction) {}

    fn get_pc(&self) -> ByteAddr {
        ByteAddr(self.pc)
    }

    fn set_pc(&mut self, addr: ByteAddr) {
        self.pc = addr.0;
    }

    fn load_register(&mut self, idx: usize) -> Result<u32> {
        Ok(self.registers[idx])
    }

    fn store_register(&mut self, idx: usize, data: u32) -> Result<()> {
        if idx != 0 {
            self.registers[idx] = data;
        }
        Ok(())
    }

    fn load_memory(&mut self, addr: WordAddr) -> Result<u32> {
        Ok(*self.memory.get(&addr.0).unwrap_or(&0))
    }

    fn store_memory(&mut self, addr: WordAddr, data: u32) -> Result<()> {
        self.memory.insert(addr.0, data);
        Ok(())
    }

    fn check_insn_load(&self, addr: ByteAddr) -> bool {
        self.platform.rom_range().contains(&addr.0)
    }
}
