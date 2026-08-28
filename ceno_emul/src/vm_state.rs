use super::rv32im::EmuContext;
use crate::{
    PC_STEP_SIZE, Program, WORD_SIZE,
    addr::{ByteAddr, RegIdx, Word, WordAddr},
    dense_addr_space::PackedMemory,
    platform::Platform,
    rv32im::{Instruction, TrapCause},
    syscalls::{SyscallEffects, handle_syscall},
    tensor::{
        TensorWitnessProvider,
        bus::{TensorBusMeta, TensorBusRecord, TensorBusSegment, TensorHandle},
    },
    tracer::{Change, FullTracer, NativeTraceStep, PreflightTracer, Tracer},
};
use anyhow::{Result, anyhow, ensure};
use std::{iter::from_fn, ops::Deref, sync::Arc};

pub struct HaltState {
    pub exit_code: u32,
}

#[cfg(feature = "tensor-cuda")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TensorBusResidentPhase {
    Imported,
    Attention,
    Ffn,
}

#[cfg(feature = "tensor-cuda")]
struct TensorBusResidentSession {
    provider: crate::tensor::resident::TinyResidentCudaProvider,
    witness: crate::tensor::resident::TinyResidentDeviceWitness,
    handle: TensorHandle,
    phase: TensorBusResidentPhase,
}

/// An implementation of the machine state and of the side-effects of operations.
pub const VM_REG_COUNT: usize = 32 + 1;

pub struct VMState<T: Tracer = FullTracer> {
    program: Arc<Program>,
    platform: Platform,
    pc: Word,
    /// Emulated main memory backed by a pre-allocated vector covering the
    /// platform layout in `memory.x`.
    memory: PackedMemory,
    registers: [Word; VM_REG_COUNT],
    // Termination.
    halt_state: Option<HaltState>,
    committed_public_io: Option<[Word; 8]>,
    tensor_witness_provider: Option<Arc<dyn TensorWitnessProvider>>,
    tensor_bus_segment: Option<TensorBusSegment>,
    #[cfg(feature = "tensor-cuda")]
    tensor_bus_resident: Option<TensorBusResidentSession>,
    next_tensor_bus_segment_id: u64,
    completed_tensor_bus_records: Vec<TensorBusRecord>,
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

impl VMState<PreflightTracer> {
    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn trace_preflight_native_step(&mut self, step: NativeTraceStep) -> bool {
        self.pc = step.pc_after.0;
        self.tracer.trace_native_step(step)
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn finish_direct_preflight_syscall(
        &mut self,
        plan: crate::syscalls::pure::AccessPlan,
    ) {
        if self.tracer.track_memory_accesses() {
            let cycle = self.tracer.cycle() + PreflightTracer::SUBCYCLE_MEM;
            for region in &plan.regions[..plan.region_count] {
                let start = ByteAddr(region.byte_addr).waddr();
                for offset in 0..region.words {
                    let addr = start + offset;
                    let value = self.memory.read(addr).unwrap_or_else(|| {
                        panic!("addr {addr:?} outside dense memory layout after direct syscall")
                    });
                    let previous_cycle = self
                        .memory
                        .access(addr, cycle, Some(value))
                        .expect("direct syscall range was validated before mutation")
                        .1;
                    self.tracer
                        .track_direct_syscall_memory(addr, previous_cycle);
                }
            }
        }

        self.tracer.track_access(
            Platform::register_vma(Platform::reg_arg0()).into(),
            PreflightTracer::SUBCYCLE_RD,
        );
        if plan.register_count == 2 {
            self.tracer.track_access(
                Platform::register_vma(Platform::reg_arg1()).into(),
                PreflightTracer::SUBCYCLE_RD,
            );
        }

        self.pc = self.pc.wrapping_add(PC_STEP_SIZE as u32);
        self.tracer.store_pc(ByteAddr(self.pc));
        self.tracer.advance();
    }
}

impl<T: Tracer> VMState<T> {
    /// The number of registers that the VM uses.
    /// 32 architectural registers + 1 register RD_NULL for dark writes to x0.
    pub const REG_COUNT: usize = VM_REG_COUNT;

    pub fn new_with_tracer(platform: Platform, program: Arc<Program>) -> Self
    where
        T::Config: Default,
    {
        Self::new_with_tracer_config(platform, program, T::Config::default())
    }

    pub fn new_with_tracer_config(
        platform: Platform,
        program: Arc<Program>,
        config: T::Config,
    ) -> Self {
        Self::new_with_tracer_config_and_next_accesses(platform, program, config, None)
    }

    pub fn new_with_tracer_config_and_next_accesses(
        platform: Platform,
        program: Arc<Program>,
        config: T::Config,
        next_accesses: Option<Arc<crate::NextCycleAccess>>,
    ) -> Self {
        let pc = program.entry;

        let mut vm = Self {
            pc,
            platform: platform.clone(),
            program: program.clone(),
            memory: PackedMemory::new(
                ByteAddr::from(platform.rom.start).waddr(),
                ByteAddr::from(
                    platform
                        .stack
                        .end
                        .max(platform.heap.end)
                        .max(platform.hints.end),
                )
                .waddr(),
            ),
            registers: [0; VM_REG_COUNT],
            tensor_witness_provider: None,
            tensor_bus_segment: None,
            #[cfg(feature = "tensor-cuda")]
            tensor_bus_resident: None,
            next_tensor_bus_segment_id: 1,
            completed_tensor_bus_records: Vec::new(),
            halt_state: None,
            committed_public_io: None,
            tracer: T::with_next_accesses(&platform, config, next_accesses),
        };

        for (&addr, &value) in &program.image {
            vm.init_memory(ByteAddr(addr).waddr(), value);
        }

        vm
    }

    pub fn new_from_elf_with_tracer(platform: Platform, elf: &[u8]) -> Result<Self>
    where
        T::Config: Default,
    {
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

    /// The last digest passed to the guest public-I/O commit syscall.
    pub fn committed_public_io(&self) -> Option<[Word; 8]> {
        self.committed_public_io
    }

    /// Install the deterministic, read-only source used by tensor ecalls.
    pub fn set_tensor_witness_provider(&mut self, provider: Arc<dyn TensorWitnessProvider>) {
        self.tensor_witness_provider = Some(provider);
    }

    pub(crate) fn tensor_witness_provider(&self) -> Option<&dyn TensorWitnessProvider> {
        self.tensor_witness_provider.as_deref()
    }

    fn tensor_bus_begin(&mut self, segment_id: u64) -> Result<()> {
        if self.tensor_bus_segment.is_some() {
            return Err(anyhow!("TensorBus segment is already active"));
        }
        self.tensor_bus_segment = Some(TensorBusSegment::begin(segment_id)?);
        Ok(())
    }

    pub(crate) fn tensor_bus_import_begin(
        &mut self,
        meta: TensorBusMeta,
        words: Vec<i32>,
    ) -> Result<(TensorHandle, Vec<TensorBusRecord>)> {
        let segment_id = self.next_tensor_bus_segment_id;
        self.next_tensor_bus_segment_id = self
            .next_tensor_bus_segment_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("TensorBus segment id overflow"))?;
        self.tensor_bus_begin(segment_id)?;
        self.tensor_bus_import(meta, words)
    }

    #[cfg(feature = "tensor-cuda")]
    pub(crate) fn tensor_bus_resident_import(
        &mut self,
        handle: TensorHandle,
        words: &[i32],
    ) -> Result<()> {
        use crate::tensor::resident::{TINY_RESIDENT_WORDS, TinyResidentCudaProvider};

        ensure!(
            self.tensor_bus_resident.is_none(),
            "TensorBus CUDA segment is already active"
        );
        let input: [i32; TINY_RESIDENT_WORDS] = words
            .try_into()
            .map_err(|_| anyhow!("TensorBus CUDA input length mismatch"))?;
        let provider = TinyResidentCudaProvider::new(0)?;
        let witness = provider.import(input)?;
        self.tensor_bus_resident = Some(TensorBusResidentSession {
            provider,
            witness,
            handle,
            phase: TensorBusResidentPhase::Imported,
        });
        Ok(())
    }

    #[cfg(feature = "tensor-cuda")]
    pub(crate) fn tensor_bus_resident_apply(
        &mut self,
        input: TensorHandle,
        output: TensorHandle,
        operator: u32,
    ) -> Result<()> {
        let session = self
            .tensor_bus_resident
            .as_mut()
            .ok_or_else(|| anyhow!("TensorBus CUDA operator is outside a segment"))?;
        ensure!(
            session.handle == input,
            "TensorBus CUDA handle continuity mismatch"
        );
        match (session.phase, operator) {
            (TensorBusResidentPhase::Imported, crate::tensor::TENSOR_HANDLE_ATTENTION_V1) => {
                session.provider.attention(&mut session.witness)?;
                session.phase = TensorBusResidentPhase::Attention;
            }
            (TensorBusResidentPhase::Attention, crate::tensor::TENSOR_HANDLE_FFN_V1) => {
                session.provider.ffn(&mut session.witness)?;
                session.phase = TensorBusResidentPhase::Ffn;
            }
            _ => anyhow::bail!("TensorBus CUDA operator order mismatch"),
        }
        session.handle = output;
        Ok(())
    }

    #[cfg(feature = "tensor-cuda")]
    pub(crate) fn tensor_bus_resident_export(&mut self, handle: TensorHandle) -> Result<Vec<i32>> {
        let mut session = self
            .tensor_bus_resident
            .take()
            .ok_or_else(|| anyhow!("TensorBus CUDA export is outside a segment"))?;
        ensure!(
            session.handle == handle,
            "TensorBus CUDA export handle mismatch"
        );
        ensure!(
            session.phase == TensorBusResidentPhase::Ffn,
            "TensorBus CUDA export before FFN"
        );
        Ok(session.provider.export(&mut session.witness)?.to_vec())
    }

    pub(crate) fn tensor_bus_import(
        &mut self,
        meta: TensorBusMeta,
        words: Vec<i32>,
    ) -> Result<(TensorHandle, Vec<TensorBusRecord>)> {
        let segment = self
            .tensor_bus_segment
            .as_mut()
            .ok_or_else(|| anyhow!("TensorBus import is outside a segment"))?;
        let start = segment.records().len();
        let handle = segment.import(meta, words)?;
        Ok((handle, segment.records()[start..].to_vec()))
    }

    #[cfg(not(feature = "tensor-cuda"))]
    pub(crate) fn tensor_bus_export_end(
        &mut self,
        handle: TensorHandle,
    ) -> Result<(Vec<i32>, Vec<TensorBusRecord>)> {
        let (words, records) = self.tensor_bus_export(handle)?;
        self.tensor_bus_end()?;
        Ok((words, records))
    }

    pub(crate) fn tensor_bus_export(
        &mut self,
        handle: TensorHandle,
    ) -> Result<(Vec<i32>, Vec<TensorBusRecord>)> {
        let segment = self
            .tensor_bus_segment
            .as_mut()
            .ok_or_else(|| anyhow!("TensorBus export is outside a segment"))?;
        let start = segment.records().len();
        let words = segment.export(handle)?;
        let records = segment.records()[start..].to_vec();
        Ok((words, records))
    }

    pub(crate) fn tensor_bus_apply<F>(
        &mut self,
        input: TensorHandle,
        meta: TensorBusMeta,
        operator: u32,
        transform: F,
    ) -> Result<(TensorHandle, Vec<TensorBusRecord>)>
    where
        F: FnOnce(&[i32]) -> Result<Vec<i32>>,
    {
        let segment = self
            .tensor_bus_segment
            .as_mut()
            .ok_or_else(|| anyhow!("TensorBus operator is outside a segment"))?;
        let start = segment.records().len();
        let handle = segment.apply(input, meta, operator, transform)?;
        Ok((handle, segment.records()[start..].to_vec()))
    }

    pub(crate) fn tensor_bus_end(&mut self) -> Result<()> {
        let segment = self
            .tensor_bus_segment
            .take()
            .ok_or_else(|| anyhow!("TensorBus segment is not active"))?;
        self.completed_tensor_bus_records.extend(segment.end()?);
        #[cfg(feature = "tensor-cuda")]
        ensure!(
            self.tensor_bus_resident.is_none(),
            "TensorBus CUDA segment was not exported"
        );
        Ok(())
    }

    pub fn tracer(&self) -> &T {
        &self.tracer
    }

    pub fn tracer_mut(&mut self) -> &mut T {
        &mut self.tracer
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
            .write_value(addr, value)
            .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
    }

    /// Return the latest exact global access cycle for a register or memory word.
    pub fn final_access_cycle(&self, addr: WordAddr) -> crate::Cycle {
        self.memory
            .latest_cycle(addr)
            .unwrap_or_else(|| self.tracer.final_register_accesses().cycle(addr))
    }

    pub fn final_access_count(&self) -> usize {
        self.memory.len() + self.tracer.final_register_accesses().len()
    }

    #[cfg(all(
        any(test, debug_assertions),
        feature = "aot-x86_64",
        target_arch = "x86_64",
        target_os = "linux"
    ))]
    pub(crate) fn record_native_memory_first_touch(&mut self, addr: WordAddr) {
        self.memory.record_native_first_touch(addr);
    }

    pub fn final_access_addresses(&self) -> Vec<WordAddr> {
        self.tracer
            .final_register_accesses()
            .addresses()
            .chain(self.memory.addresses())
            .collect()
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

    pub(crate) fn step(&mut self) -> Result<T::Record> {
        crate::rv32im::step(self)?;
        let step = self.tracer.advance();
        if self.tracer.is_busy_loop(&step) && !self.halted() {
            Err(anyhow!("Stuck in loop {}", "{}"))
        } else {
            Ok(step)
        }
    }

    pub fn init_register_unsafe(&mut self, idx: RegIdx, value: Word) {
        self.registers[idx as usize] = value;
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn registers_mut_ptr(&mut self) -> *mut Word {
        self.registers.as_mut_ptr()
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn pc_mut_ptr(&mut self) -> *mut Word {
        &mut self.pc
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn memory_cells_mut_ptr(&mut self) -> *mut u64 {
        self.memory.cells_mut_ptr()
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn memory_base_word(&self) -> WordAddr {
        self.memory.base()
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn memory_end_word(&self) -> WordAddr {
        self.memory.end()
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn trace_fetch_known(&mut self, pc: WordAddr, insn: Instruction) {
        self.tracer.fetch(pc, insn);
        self.tracer.track_mmu_maxtouch_before();
    }

    fn halt(&mut self, exit_code: u32) {
        self.set_pc(0.into());
        self.halt_state = Some(HaltState { exit_code });
    }

    fn apply_syscall(&mut self, mut effects: SyscallEffects) -> Result<()> {
        let cycle = self.tracer.cycle() + T::SUBCYCLE_MEM;
        for op in effects.iter_mem_ops_mut() {
            let addr = op.addr;
            let previous_cycle = if self.tracer.track_memory_accesses() {
                self.memory
                    .access(addr, cycle, Some(op.value.after))
                    .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"))
                    .1
            } else {
                self.memory
                    .write_value(addr, op.value.after)
                    .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
                0
            };
            op.previous_cycle = previous_cycle;
        }

        for (idx, value) in effects.iter_reg_values() {
            self.registers[idx as usize] = value;
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
            if function == ceno_syscall::PUB_IO_COMMIT {
                let digest_ptr = self.peek_register(Platform::reg_arg0());
                self.committed_public_io = Some(std::array::from_fn(|index| {
                    self.peek_memory(ByteAddr(digest_ptr).waddr() + index)
                }));
            }
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
            self.registers[idx as usize] = after;
        }
        Ok(())
    }

    /// Load a memory word and record this operation.
    fn load_memory(&mut self, addr: WordAddr) -> Result<Word> {
        if !self.tracer.track_memory_accesses() {
            return Ok(self.peek_memory(addr));
        }
        let cycle = self.tracer.cycle() + T::SUBCYCLE_MEM;
        let (value, previous_cycle) = self
            .memory
            .access(addr, cycle, None)
            .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
        self.tracer.load_memory(addr, value, previous_cycle);
        Ok(value)
    }

    /// Store a memory word and record this operation.
    fn store_memory(&mut self, addr: WordAddr, after: Word) -> Result<()> {
        if !self.tracer.track_memory_accesses() {
            self.memory
                .write_value(addr, after)
                .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
            return Ok(());
        }
        let cycle = self.tracer.cycle() + T::SUBCYCLE_MEM;
        let (before, previous_cycle) = self
            .memory
            .access(addr, cycle, Some(after))
            .unwrap_or_else(|| panic!("addr {addr:?} outside dense memory layout"));
        self.tracer
            .store_memory(addr, Change { after, before }, previous_cycle);
        Ok(())
    }

    /// Get the value of a register without side-effects.
    fn peek_register(&self, idx: RegIdx) -> Word {
        self.registers[idx as usize]
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
