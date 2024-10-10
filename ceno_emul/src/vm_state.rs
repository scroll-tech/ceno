use std::collections::HashMap;

use super::rv32im::EmuContext;
use crate::{
    addr::{ByteAddr, RegIdx, Word, WordAddr},
    platform::Platform,
    rv32im::{DecodedInstruction, Emulator, TrapCause},
    tracer::{Change, StepRecord, Tracer},
    Program,
};
use anyhow::{anyhow, Result};
use std::iter::from_fn;

/// An implementation of the machine state and of the side-effects of operations.
pub struct VMState {
    platform: Platform,
    pc: Word,
    /// Map a word-address (addr/4) to a word.
    memory: HashMap<WordAddr, Word>,
    registers: [Word; 32],
    // Termination.
    halted: bool,
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
            halted: false,
            tracer: Tracer::new(),
        }
    }

    pub fn new_from_elf(platform: Platform, elf: &[u8]) -> Result<Self> {
        let mut state = Self::new(platform);
        let program = Program::load_elf(elf, u32::MAX).unwrap();
        for (addr, word) in program.image.iter() {
            let addr = ByteAddr(*addr).waddr();
            state.init_memory(addr, *word);
        }
        if program.entry != state.platform.pc_start() {
            return Err(anyhow!("Invalid entrypoint {:x}", program.entry));
        }
        Ok(state)
    }

    pub fn halted(&self) -> bool {
        self.halted
    }

    pub fn tracer(&self) -> &Tracer {
        &self.tracer
    }

    /// Set a word in memory without side-effects.
    pub fn init_memory(&mut self, addr: WordAddr, value: Word) {
        self.memory.insert(addr, value);
    }

    pub fn iter_until_halt(&mut self) -> impl Iterator<Item = Result<StepRecord>> + '_ {
        let emu = Emulator::new();
        from_fn(move || {
            if self.halted() {
                None
            } else {
                Some(self.step(&emu))
            }
        })
    }

    fn step(&mut self, emu: &Emulator) -> Result<StepRecord> {
        emu.step(self)?;
        let step = self.tracer.advance();
        if step.is_busy_loop() && !self.halted() {
            Err(anyhow!("Stuck in loop {}", "{}"))
        } else {
            Ok(step)
        }
    }

    pub fn init_register_unsafe(&mut self, idx: RegIdx, value: Word) {
        self.registers[idx] = value;
    }
}

impl EmuContext for VMState {
    // Expect an ecall to terminate the program: function HALT with argument exit_code.
    fn ecall(&mut self) -> Result<bool> {
        let function = self.load_register(self.platform.reg_ecall())?;
        if function == self.platform.ecall_halt() {
            let exit_code = self.load_register(self.platform.reg_arg0())?;
            tracing::debug!("halt with exit_code={}", exit_code);

            self.halt(ByteAddr(0));
            Ok(true)
        } else {
            self.trap(TrapCause::EcallError)
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

    fn on_normal_end(&mut self, _decoded: &DecodedInstruction) {
        self.tracer.store_pc(ByteAddr(self.pc));
    }

    fn get_pc(&self) -> ByteAddr {
        ByteAddr(self.pc)
    }

    fn set_pc(&mut self, after: ByteAddr) {
        self.pc = after.0;
    }

    fn halt(&mut self, pc: ByteAddr) {
        self.pc = pc.0;
        self.halted = true;
        self.tracer.halt(ByteAddr(pc.0));
    }

    /// Load a register and record this operation.
    fn load_register(&mut self, idx: RegIdx) -> Result<Word> {
        self.tracer.load_register(idx, self.peek_register(idx));
        Ok(self.peek_register(idx))
    }

    /// Store a register and record this operation.
    fn store_register(&mut self, idx: RegIdx, after: Word) -> Result<()> {
        if idx != 0 {
            let before = self.peek_register(idx);
            self.tracer.store_register(idx, Change { before, after });
            self.registers[idx] = after;
        }
        Ok(())
    }

    /// Load a memory word and record this operation.
    fn load_memory(&mut self, addr: WordAddr) -> Result<Word> {
        let value = self.peek_memory(addr);
        self.tracer.load_memory(addr, value);
        Ok(value)
    }

    /// Store a memory word and record this operation.
    fn store_memory(&mut self, addr: WordAddr, after: Word) -> Result<()> {
        let before = self.peek_memory(addr);
        self.tracer.store_memory(addr, Change { after, before });
        self.memory.insert(addr, after);
        Ok(())
    }

    /// Get the value of a register without side-effects.
    fn peek_register(&self, idx: RegIdx) -> Word {
        self.registers[idx]
    }

    /// Get the value of a memory word without side-effects.
    fn peek_memory(&self, addr: WordAddr) -> Word {
        *self.memory.get(&addr).unwrap_or(&0)
    }

    fn fetch(&mut self, pc: WordAddr) -> Result<Word> {
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
