use super::rv32im::EmuContext;
use crate::{
    PC_STEP_SIZE, Program, WORD_SIZE,
    addr::{ByteAddr, RegIdx, Word, WordAddr},
    dense_addr_space::DenseAddrSpace,
    platform::Platform,
    rv32im::{Instruction, TrapCause},
    syscalls::{SyscallEffects, handle_syscall},
    tracer::{Change, FullTracer, Tracer},
};
use anyhow::{Result, anyhow};
use std::{iter::from_fn, ops::Deref, sync::Arc};

pub struct HaltState {
    pub exit_code: u32,
}

/// An implementation of the machine state and of the side-effects of operations.
pub const VM_REG_COUNT: usize = 32 + 1;

pub struct VMState<T: Tracer = FullTracer> {
    program: Arc<Program>,
    platform: Platform,
    pc: Word,
    /// Emulated main memory backed by a pre-allocated vector covering the
    /// platform layout in `memory.x`.
    memory: DenseAddrSpace<Word>,
    registers: [Word; VM_REG_COUNT],
    // Termination.
    halt_state: Option<HaltState>,
    tracer: T,
}

impl VMState<FullTracer> {
    pub fn new(platform: Platform, program: Arc<Program>) -> Self {
        Self::new_with_tracer(platform, program)
    }

    pub fn new_from_elf(platform: Platform, elf: &[u8]) -> Result<Self> {
        VMState::<FullTracer>::new_from_elf_with_tracer(platform, elf)
    }
}

impl<T: Tracer> VMState<T> {
    /// The number of registers that the VM uses.
    /// 32 architectural registers + 1 register RD_NULL for dark writes to x0.
    pub const REG_COUNT: usize = VM_REG_COUNT;

    pub fn new_with_tracer(platform: Platform, program: Arc<Program>) -> Self {
        let pc = program.entry;

        let mut vm = Self {
            pc,
            platform: platform.clone(),
            program: program.clone(),
            memory: DenseAddrSpace::new(
                ByteAddr::from(platform.rom.start).waddr(),
                ByteAddr::from(platform.heap.end).waddr(),
            ),
            registers: [0; VM_REG_COUNT],
            halt_state: None,
            tracer: T::new(&platform),
        };

        for (&addr, &value) in &program.image {
            vm.init_memory(ByteAddr(addr).waddr(), value);
        }

        vm
    }

    pub fn new_from_elf_with_tracer(platform: Platform, elf: &[u8]) -> Result<Self> {
        let program = Arc::new(Program::load_elf(elf, u32::MAX)?);
        let platform = Platform {
            prog_data: Arc::new(program.image.keys().copied().collect()),
            ..platform
        };
        Ok(Self::new_with_tracer(platform, program))
    }

    pub fn halted(&self) -> bool {
        self.halt_state.is_some()
    }

    pub fn halted_state(&self) -> Option<&HaltState> {
        self.halt_state.as_ref()
    }

    pub fn tracer(&self) -> &T {
        &self.tracer
    }

    pub fn take_tracer(self) -> T {
        self.tracer
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn program(&self) -> &Program {
        self.program.deref()
    }

    /// Set a word in memory without side effects.
    pub fn init_memory(&mut self, addr: WordAddr, value: Word) {
        self.memory
            .write(addr, value)
            .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
    }

    pub fn iter_until_halt(&mut self) -> impl Iterator<Item = Result<T::Record>> + '_ {
        from_fn(move || {
            if self.halted() {
                None
            } else {
                Some(self.step())
            }
        })
    }

    pub fn next_step_record(&mut self) -> Result<Option<T::Record>> {
        if self.halted() {
            return Ok(None);
        }
        self.step().map(Some)
    }

    fn step(&mut self) -> Result<T::Record> {
        crate::rv32im::step(self)?;
        let step = self.tracer.advance();
        if self.tracer.is_busy_loop(&step) && !self.halted() {
            Err(anyhow!("Stuck in loop {}", "{}"))
        } else {
            Ok(step)
        }
    }

    pub fn init_register_unsafe(&mut self, idx: RegIdx, value: Word) {
        self.registers[idx] = value;
    }

    fn halt(&mut self, exit_code: u32) {
        self.set_pc(0.into());
        self.halt_state = Some(HaltState { exit_code });
    }

    fn apply_syscall(&mut self, effects: SyscallEffects) -> Result<()> {
        for (addr, value) in effects.iter_mem_values() {
            self.memory
                .write(addr, value)
                .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
        }

        for (idx, value) in effects.iter_reg_values() {
            self.registers[idx] = value;
        }

        let next_pc = effects.next_pc.unwrap_or(self.pc + PC_STEP_SIZE as u32);
        self.set_pc(next_pc.into());

        self.tracer.track_syscall(effects);
        Ok(())
    }
}

impl<T: Tracer> EmuContext for VMState<T> {
    // Expect an ecall to terminate the program: function HALT with argument exit_code.
    fn ecall(&mut self) -> Result<bool> {
        let function = self.load_register(Platform::reg_ecall())?;
        if function == Platform::ecall_halt() {
            let exit_code = self.load_register(Platform::reg_arg0())?;
            tracing::debug!("halt with exit_code={}", exit_code);
            self.halt(exit_code);
            Ok(true)
        } else {
            match handle_syscall(self, function) {
                Ok(effects) => {
                    self.apply_syscall(effects)?;
                    Ok(true)
                }
                Err(err) if self.platform.unsafe_ecall_nop => {
                    tracing::warn!("ecall ignored with unsafe_ecall_nop: {:?}", err);
                    // TODO: remove this example.
                    // Treat unknown ecalls as all powerful instructions:
                    // Read two registers, write one register, write one memory word, and branch.
                    let _arg0 = self.load_register(Platform::reg_arg0())?;
                    self.store_register(Instruction::RD_NULL as RegIdx, 0)?;
                    // Example ecall effect - any writable address will do.
                    let addr = (self.platform.stack.end - WORD_SIZE as u32).into();
                    self.store_memory(addr, self.peek_memory(addr))?;
                    self.set_pc(ByteAddr(self.pc) + PC_STEP_SIZE);
                    Ok(true)
                }
                Err(err) => {
                    tracing::error!("ecall error: {:?}", err);
                    self.trap(TrapCause::EcallError)
                }
            }
        }
    }

    fn trap(&self, cause: TrapCause) -> Result<bool> {
        // Crash.
        match cause {
            TrapCause::IllegalInstruction(raw) => {
                Err(anyhow!("Trap IllegalInstruction({:#x})", raw))
            }
            _ => Err(anyhow!("Trap {:?}", cause)),
        }
    }

    fn on_normal_end(&mut self, _decoded: &Instruction) {
        self.tracer.store_pc(ByteAddr(self.pc));
        self.tracer.track_mmu_maxtouch_after();
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
        self.memory
            .write(addr, after)
            .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
        Ok(())
    }

    /// Get the value of a register without side-effects.
    fn peek_register(&self, idx: RegIdx) -> Word {
        self.registers[idx]
    }

    /// Get the value of a memory word without side-effects.
    fn peek_memory(&self, addr: WordAddr) -> Word {
        self.memory
            .read(addr)
            .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"))
    }

    fn fetch(&mut self, pc: WordAddr) -> Option<Instruction> {
        let byte_pc: ByteAddr = pc.into();
        let relative_pc = byte_pc.0.wrapping_sub(self.program.base_address);
        let idx = (relative_pc / WORD_SIZE as u32) as usize;
        let word = self.program.instructions.get(idx).copied()?;
        self.tracer.fetch(pc, word);
        self.tracer.track_mmu_maxtouch_before();
        Some(word)
    }

    fn check_data_load(&self, addr: ByteAddr) -> bool {
        self.platform.can_read(addr.0)
    }

    fn check_data_store(&self, addr: ByteAddr) -> bool {
        self.platform.can_write(addr.0)
    }
}
