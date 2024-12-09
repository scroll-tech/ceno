use std::collections::HashMap;

use super::rv32im::EmuContext;
use crate::{
    PC_STEP_SIZE, Program, WORD_SIZE,
    addr::{ByteAddr, RegIdx, Word, WordAddr},
    platform::Platform,
    rv32im::{DecodedInstruction, Emulator, TrapCause},
    tracer::{Change, StepRecord, Tracer},
};
use anyhow::{Result, anyhow};
use std::{iter::from_fn, ops::Deref, sync::Arc};

/// An implementation of the machine state and of the side-effects of operations.
pub struct VMState {
    program: Arc<Program>,
    platform: Platform,
    pc: Word,
    /// Map a word-address (addr/4) to a word.
    memory: HashMap<WordAddr, Word>,
    registers: [Word; VMState::REG_COUNT],
    // Termination.
    halted: bool,
    tracer: Tracer,
}

impl VMState {
    /// The number of registers that the VM uses.
    /// 32 architectural registers + 1 register RD_NULL for dark writes to x0.
    pub const REG_COUNT: usize = 32 + 1;

    pub fn new(platform: Platform, program: Program) -> Self {
        let pc = program.entry;
        let program = Arc::new(program);

        let mut vm = Self {
            pc,
            platform,
            program: program.clone(),
            memory: HashMap::new(),
            registers: [0; VMState::REG_COUNT],
            halted: false,
            tracer: Tracer::new(),
        };

        // init memory from program.image
        for (&addr, &value) in &program.image {
            vm.init_memory(ByteAddr(addr).waddr(), value);
        }

        vm
    }

    pub fn new_from_elf(platform: Platform, elf: &[u8]) -> Result<Self> {
        let program = Program::load_elf(elf, u32::MAX)?;
        Ok(Self::new(platform, program))
    }

    pub fn halted(&self) -> bool {
        self.halted
    }

    pub fn tracer(&self) -> &Tracer {
        &self.tracer
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn program(&self) -> &Program {
        self.program.deref()
    }

    /// Set a word in memory without side effects.
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

    fn halt(&mut self) {
        self.set_pc(0.into());
        self.halted = true;
    }
}

impl EmuContext for VMState {
    // Expect an ecall to terminate the program: function HALT with argument exit_code.
    fn ecall(&mut self) -> Result<bool> {
        let function = self.load_register(Platform::reg_ecall())?;
        let arg0 = self.load_register(Platform::reg_arg0())?;
        if function == Platform::ecall_halt() {
            tracing::debug!("halt with exit_code={}", arg0);

            self.halt();
            Ok(true)
        } else if self.platform.unsafe_ecall_nop {
            // Treat unknown ecalls as all powerful instructions:
            // Read two registers, write one register, write one memory word, and branch.
            tracing::warn!("ecall ignored: syscall_id={}", function);
            self.store_register(DecodedInstruction::RD_NULL as RegIdx, 0)?;
            // Example ecall effect - any writable address will do.
            let addr = (self.platform.stack_top - WORD_SIZE as u32).into();
            self.store_memory(addr, self.peek_memory(addr))?;
            self.set_pc(ByteAddr(self.pc) + PC_STEP_SIZE);
            Ok(true)
        } else {
            self.trap(TrapCause::EcallError)
        }
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

    // TODO(Matthias): this should really return `Result<DecodedInstruction>`
    fn fetch(&mut self, pc: WordAddr) -> Option<Word> {
        let byte_pc: ByteAddr = pc.into();
        let relative_pc = byte_pc.0.wrapping_sub(self.program.base_address);
        let idx = (relative_pc / WORD_SIZE as u32) as usize;
        let word = self.program.instructions.get(idx).copied()?;
        self.tracer.fetch(pc, word);
        Some(word)
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
