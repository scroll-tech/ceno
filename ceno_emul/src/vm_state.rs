use std::collections::HashMap;

use super::rv32im::EmuContext;
use crate::{
    addr::{ByteAddr, WordAddr},
    platform::Platform,
    rv32im::{DecodedInstruction, Emulator, Instruction, TrapCause},
    tracer::{Change, StepRecord, Tracer},
};
use anyhow::{anyhow, Result};
use std::iter::from_fn;

/// An implementation of the machine state and of the side-effects of operations.
pub struct VMState {
    platform: Platform,
    pc: u32,
    /// Map a word-address (addr/4) to a word.
    memory: HashMap<u32, u32>,
    registers: [u32; 32],
    // Termination.
    succeeded: bool,
    tracer: Tracer,
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
            tracer: Default::default(),
        }
    }

    pub fn succeeded(&self) -> bool {
        self.succeeded
    }

    pub fn tracer(&mut self) -> &mut Tracer {
        &mut self.tracer
    }

    /// Get the value of a register without side-effects.
    pub fn peek_register(&self, idx: usize) -> u32 {
        self.registers[idx]
    }

    /// Get the value of a memory word without side-effects.
    pub fn peek_memory(&self, addr: WordAddr) -> u32 {
        *self.memory.get(&addr.0).unwrap_or(&0)
    }

    /// Set a word in memory without side-effects.
    pub fn init_memory(&mut self, addr: WordAddr, value: u32) {
        self.memory.insert(addr.0, value);
    }

    pub fn iter_until_success(&mut self) -> impl Iterator<Item = Result<StepRecord>> + '_ {
        let emu = Emulator::new();
        from_fn(move || {
            if self.succeeded() {
                None
            } else {
                Some(self.step(&emu))
            }
        })
    }

    fn step(&mut self, emu: &Emulator) -> Result<StepRecord> {
        emu.step(self)?;
        let step = self.tracer().advance();
        Ok(step)
    }
}

impl EmuContext for VMState {
    // Expect an ecall to indicate a successful exit:
    // function HALT with argument SUCCESS.
    fn ecall(&mut self) -> Result<bool> {
        let function = 0; // self.load_register(self.platform.reg_ecall())?;
        let argument = 0; // self.load_register(self.platform.reg_arg0())?;
        if function == self.platform.ecall_halt() && argument == self.platform.code_success() {
            self.succeeded = true;
            Ok(true)
        } else {
            self.trap(TrapCause::EnvironmentCallFromUserMode)
        }
    }

    // No traps are implemented so MRET is not legal.
    fn mret(&self) -> Result<bool> {
        #[allow(clippy::unusual_byte_groupings)]
        let mret = 0b001100000010_00000_000_00000_1110011;
        self.trap(TrapCause::IllegalInstruction(mret))
    }

    fn trap(&self, cause: TrapCause) -> Result<bool> {
        Err(anyhow!("Trap {:?}", cause)) // Crash.
    }

    fn on_insn_decoded(&mut self, _kind: &Instruction, _decoded: &DecodedInstruction) {}

    fn on_normal_end(&mut self, _kind: &Instruction, _decoded: &DecodedInstruction) {
        self.tracer.store_pc(ByteAddr(self.pc));
    }

    fn get_pc(&self) -> ByteAddr {
        ByteAddr(self.pc)
    }

    fn set_pc(&mut self, after: ByteAddr) {
        self.pc = after.0;
    }

    /// Load a register and record this operation.
    fn load_register(&mut self, idx: usize) -> Result<u32> {
        self.tracer.load_register(idx, self.peek_register(idx));
        Ok(self.peek_register(idx))
    }

    /// Store a register and record this operation.
    fn store_register(&mut self, idx: usize, after: u32) -> Result<()> {
        if idx != 0 {
            let before = self.peek_register(idx);
            self.tracer.store_register(idx, Change { before, after });
            self.registers[idx] = after;
        }
        Ok(())
    }

    /// Load a memory word and record this operation.
    fn load_memory(&mut self, addr: WordAddr) -> Result<u32> {
        let value = self.peek_memory(addr);
        self.tracer.load_memory(addr, value);
        Ok(value)
    }

    /// Store a memory word and record this operation.
    fn store_memory(&mut self, addr: WordAddr, after: u32) -> Result<()> {
        let before = self.peek_memory(addr);
        self.tracer.store_memory(addr, Change { after, before });
        self.memory.insert(addr.0, after);
        Ok(())
    }

    fn fetch(&mut self, pc: WordAddr) -> Result<u32> {
        let value = self.peek_memory(pc);
        self.tracer.fetch(pc, value);
        Ok(value)
    }

    fn check_data_load(&self, addr: ByteAddr) -> bool {
        self.platform.can_read(addr.0)
    }

    fn check_data_store(&self, addr: ByteAddr) -> bool {
        self.platform.can_write(addr.0)
    }

    fn check_insn_load(&self, addr: ByteAddr) -> bool {
        self.platform.can_execute(addr.0)
    }
}
