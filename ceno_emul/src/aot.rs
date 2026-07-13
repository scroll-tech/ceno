use crate::{
    Change, EmuContext, InsnKind, Instruction, PC_STEP_SIZE, PreflightTracer, Program, Tracer,
    VMState,
    addr::{ByteAddr, Cycle, RegIdx, WordAddr},
    rv32im::TrapCause,
    tracer::{
        NATIVE_TRACE_LOAD_MEM, NATIVE_TRACE_READ_RS1, NATIVE_TRACE_READ_RS2,
        NATIVE_TRACE_STORE_MEM, NATIVE_TRACE_WRITE_RD,
    },
};
use anyhow::{Context, Result, anyhow, bail};
use libloading::{Library, Symbol};
use std::{
    any::TypeId,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::raw::c_void,
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

type NativeEntry = unsafe extern "C" fn(
    *mut AotRuntimeContext,
    AotInsnFn,
    *const c_void,
    u64,
    *mut u64,
    u32,
) -> u32;
type AotInsnFn = unsafe extern "C" fn(*mut c_void, u32, *mut u32) -> u32;
type AotTraceFn = unsafe extern "C" fn(*mut AotRuntimeContext) -> u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssemblyTraceStyle {
    Generic,
    PreflightDirect,
    PreflightDirectBlockPlan,
    PreflightDirectBlockPlanExactAccess,
}

impl AssemblyTraceStyle {
    fn needs_callback_values(self) -> bool {
        matches!(self, Self::Generic)
    }

    fn is_preflight_direct(self) -> bool {
        matches!(
            self,
            Self::PreflightDirect
                | Self::PreflightDirectBlockPlan
                | Self::PreflightDirectBlockPlanExactAccess
        )
    }
}

const AOT_STATUS_HALTED: u32 = 0;
const AOT_STATUS_CONTINUE: u32 = 1;
const AOT_STATUS_ERROR: u32 = 2;

const AOT_CTX_VM_OFFSET: usize = 0;
const AOT_CTX_REGISTERS_OFFSET: usize = 8;
const AOT_CTX_TRACE_PC_OFFSET: usize = 16;
const AOT_CTX_TRACE_NEXT_PC_OFFSET: usize = 20;
const AOT_CTX_TRACE_RS1_VALUE_OFFSET: usize = 24;
const AOT_CTX_TRACE_RS2_VALUE_OFFSET: usize = 28;
const AOT_CTX_TRACE_RD_BEFORE_OFFSET: usize = 32;
const AOT_CTX_TRACE_RD_AFTER_OFFSET: usize = 36;
const AOT_CTX_MEMORY_CELLS_OFFSET: usize = 40;
const AOT_CTX_MEMORY_BASE_WORD_OFFSET: usize = 48;
const AOT_CTX_HEAP_START_OFFSET: usize = 52;
const AOT_CTX_HEAP_END_OFFSET: usize = 56;
const AOT_CTX_STACK_START_OFFSET: usize = 60;
const AOT_CTX_STACK_END_OFFSET: usize = 64;
const AOT_CTX_HINTS_START_OFFSET: usize = 68;
const AOT_CTX_HINTS_END_OFFSET: usize = 72;
const AOT_CTX_TRACE_MEM_ADDR_OFFSET: usize = 76;
const AOT_CTX_TRACE_MEM_BEFORE_OFFSET: usize = 80;
const AOT_CTX_TRACE_MEM_AFTER_OFFSET: usize = 84;
const AOT_CTX_PC_OFFSET: usize = 88;
const AOT_CTX_TRACE_FLAGS_OFFSET: usize = 108;
const AOT_CTX_TRACE_RS1_IDX_OFFSET: usize = 112;
const AOT_CTX_TRACE_RS2_IDX_OFFSET: usize = 116;
const AOT_CTX_TRACE_RD_IDX_OFFSET: usize = 120;
const AOT_CTX_TRACE_KIND_OFFSET: usize = 124;
const AOT_CTX_TRACE_MODE_OFFSET: usize = 128;
const AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET: usize = 136;
const AOT_CTX_PREFLIGHT_CYCLE_OFFSET: usize = 152;
const AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET: usize = 184;
const AOT_CTX_PREFLIGHT_PREV_CYCLE_OFFSET: usize = 192;
const AOT_CTX_PREFLIGHT_CUR_CYCLE_OFFSET: usize = 200;
const AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET: usize = 208;
const AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET: usize = 212;
const AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET: usize = 216;
const AOT_CTX_PREFLIGHT_STEP_CELLS_OFFSET: usize = 224;
const AOT_CTX_PREFLIGHT_PLANNER_CUR_CELLS_OFFSET: usize = 232;
const AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET: usize = 240;
const AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET: usize = 248;
const AOT_CTX_PREFLIGHT_PLANNER_SHARD_ID_OFFSET: usize = 264;
const AOT_CTX_PREFLIGHT_MAX_CELL_PER_SHARD_OFFSET: usize = 272;
const AOT_CTX_PREFLIGHT_TARGET_CELL_FIRST_SHARD_OFFSET: usize = 280;
const AOT_CTX_PREFLIGHT_MAX_CYCLE_PER_SHARD_OFFSET: usize = 288;
const AOT_CTX_PREFLIGHT_STEP_CELLS_TABLE_OFFSET: usize = 296;
const AOT_CTX_PREFLIGHT_HEAP_START_WORD_OFFSET: usize = 304;
const AOT_CTX_PREFLIGHT_HEAP_END_WORD_OFFSET: usize = 308;
const AOT_CTX_PREFLIGHT_STACK_START_WORD_OFFSET: usize = 312;
const AOT_CTX_PREFLIGHT_STACK_END_WORD_OFFSET: usize = 316;
const AOT_CTX_PREFLIGHT_HINTS_START_WORD_OFFSET: usize = 320;
const AOT_CTX_PREFLIGHT_HINTS_END_WORD_OFFSET: usize = 324;
const AOT_CTX_PREFLIGHT_HEAP_MIN_OFFSET: usize = 328;
const AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET: usize = 336;
const AOT_CTX_PREFLIGHT_STACK_MIN_OFFSET: usize = 344;
const AOT_CTX_PREFLIGHT_STACK_MAX_OFFSET: usize = 352;
const AOT_CTX_PREFLIGHT_HINTS_MIN_OFFSET: usize = 360;
const AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET: usize = 368;
const AOT_CTX_FALLBACK_STEPS_OFFSET: usize = 376;
const AOT_CTX_PREFLIGHT_BLOCK_CELLS_TABLE_OFFSET: usize = 384;

const AOT_TRACE_MODE_NONE: u32 = 0;
const AOT_TRACE_MODE_CALLBACK: u32 = 1;
const AOT_TRACE_MODE_PREFLIGHT_DIRECT: u32 = 2;

const AOT_PREFLIGHT_HELPER_ACCESS: u32 = 1;
const AOT_PREFLIGHT_HELPER_SYNC: u32 = 2;
const AOT_PREFLIGHT_HELPER_BUSY_LOOP: u32 = 3;
const AOT_PREFLIGHT_HELPER_CALLBACK: u32 = 4;
const AOT_PREFLIGHT_HELPER_SHARD_SPLIT: u32 = 5;

thread_local! {
    static LAST_AOT_ERROR: RefCell<Option<anyhow::Error>> = const { RefCell::new(None) };
}

#[repr(C)]
struct AotRuntimeContext {
    vm: *mut c_void,
    registers: *mut u32,
    trace_pc: u32,
    trace_next_pc: u32,
    trace_rs1_value: u32,
    trace_rs2_value: u32,
    trace_rd_before: u32,
    trace_rd_after: u32,
    memory_cells: *mut u32,
    memory_base_word: u32,
    heap_start: u32,
    heap_end: u32,
    stack_start: u32,
    stack_end: u32,
    hints_start: u32,
    hints_end: u32,
    trace_mem_addr: u32,
    trace_mem_before: u32,
    trace_mem_after: u32,
    pc: *mut u32,
    instructions: *const Instruction,
    program_base: u32,
    trace_flags: u32,
    trace_rs1_idx: u32,
    trace_rs2_idx: u32,
    trace_rd_idx: u32,
    trace_kind: u32,
    trace_mode: u32,
    preflight_latest_cells: *mut Cycle,
    preflight_latest_base: u32,
    preflight_cycle: *mut Cycle,
    preflight_pc_before: *mut ByteAddr,
    preflight_pc_after: *mut ByteAddr,
    preflight_last_kind: *mut InsnKind,
    preflight_current_shard_start: *const Cycle,
    preflight_prev_cycle: Cycle,
    preflight_cur_cycle: Cycle,
    preflight_event_addr: u32,
    preflight_helper_kind: u32,
    preflight_pending_steps: Cycle,
    preflight_step_cells: u64,
    preflight_planner_cur_cells: *mut u64,
    preflight_planner_cur_cycle_in_shard: *mut Cycle,
    preflight_planner_cur_step_count: *mut usize,
    preflight_planner_max_step_shard: *mut usize,
    preflight_planner_shard_id: *mut usize,
    preflight_max_cell_per_shard: u64,
    preflight_target_cell_first_shard: u64,
    preflight_max_cycle_per_shard: Cycle,
    preflight_step_cells_table: *const u64,
    preflight_heap_start_word: u32,
    preflight_heap_end_word: u32,
    preflight_stack_start_word: u32,
    preflight_stack_end_word: u32,
    preflight_hints_start_word: u32,
    preflight_hints_end_word: u32,
    preflight_heap_min: *mut WordAddr,
    preflight_heap_max: *mut WordAddr,
    preflight_stack_min: *mut WordAddr,
    preflight_stack_max: *mut WordAddr,
    preflight_hints_min: *mut WordAddr,
    preflight_hints_max: *mut WordAddr,
    fallback_steps: u64,
    preflight_block_cells_table: *const u64,
}

#[derive(Debug)]
pub struct AotCompileReport {
    pub block_count: usize,
    pub reachable_instruction_count: usize,
    pub compile_load_time: Duration,
}

pub struct AotProgram {
    program: Arc<Program>,
    blocks: Vec<BasicBlock>,
    _library: Library,
    entry: NativeEntry,
    compile_load_time: Duration,
    trace_style: AssemblyTraceStyle,
}

pub type AotInstance = AotProgram;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_pc: u32,
    pub end_pc: u32,
}

impl AotProgram {
    pub fn compile(program: Arc<Program>) -> Result<Self> {
        Self::compile_with_extra_roots(program, Vec::new())
    }

    pub fn compile_with_extra_roots(program: Arc<Program>, extra_roots: Vec<u32>) -> Result<Self> {
        Self::compile_with_extra_roots_and_trace_style(
            program,
            extra_roots,
            AssemblyTraceStyle::Generic,
        )
    }

    pub fn compile_preflight_direct_with_extra_roots(
        program: Arc<Program>,
        extra_roots: Vec<u32>,
    ) -> Result<Self> {
        Self::compile_with_extra_roots_and_trace_style(
            program,
            extra_roots,
            AssemblyTraceStyle::PreflightDirectBlockPlan,
        )
    }

    fn compile_with_extra_roots_and_trace_style(
        program: Arc<Program>,
        extra_roots: Vec<u32>,
        trace_style: AssemblyTraceStyle,
    ) -> Result<Self> {
        let started = Instant::now();
        let blocks = partition_basic_blocks_with_roots(&program, extra_roots)?;
        let (library, entry) = compile_and_load_native(&program, &blocks, trace_style)?;
        Ok(Self {
            program,
            blocks,
            _library: library,
            entry,
            compile_load_time: started.elapsed(),
            trace_style,
        })
    }

    pub fn report(&self) -> AotCompileReport {
        AotCompileReport {
            block_count: self.blocks.len(),
            reachable_instruction_count: self
                .blocks
                .iter()
                .map(|block| ((block.end_pc - block.start_pc) / PC_STEP_SIZE as u32) as usize)
                .sum(),
            compile_load_time: self.compile_load_time,
        }
    }

    pub fn run_to_halt<T: Tracer + 'static>(
        &self,
        vm: &mut VMState<T>,
        max_steps: usize,
    ) -> Result<AotRunReport> {
        self.run_to_halt_with_trace(vm, max_steps, true)
    }

    pub fn run_pure_to_halt<T: Tracer + 'static>(
        &self,
        vm: &mut VMState<T>,
        max_steps: usize,
    ) -> Result<AotRunReport> {
        self.run_to_halt_with_trace(vm, max_steps, false)
    }

    fn run_to_halt_with_trace<T: Tracer + 'static>(
        &self,
        vm: &mut VMState<T>,
        max_steps: usize,
        trace_native_steps: bool,
    ) -> Result<AotRunReport> {
        if !std::ptr::eq(vm.program(), self.program.as_ref()) {
            bail!("AOT program does not match VM program");
        }

        let started = Instant::now();
        LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = None);
        let mut executed_steps = 0u64;
        let memory_base_word = vm.memory_base_word().0;
        let heap = vm.platform().heap.clone();
        let stack = vm.platform().stack.clone();
        let hints = vm.platform().hints.clone();
        let vm_ptr = vm as *mut VMState<T> as *mut c_void;
        let registers = vm.registers_mut_ptr();
        let pc_ptr = vm.pc_mut_ptr();
        let memory_cells = vm.memory_cells_mut_ptr();
        let instructions = self.program.instructions.as_ptr();
        let program_base = self.program.base_address;
        let mut trace_mode = if trace_native_steps {
            AOT_TRACE_MODE_CALLBACK
        } else {
            AOT_TRACE_MODE_NONE
        };
        let mut preflight_latest_cells = std::ptr::null_mut();
        let mut preflight_latest_base = 0;
        let mut preflight_cycle = std::ptr::null_mut();
        let mut preflight_pc_before = std::ptr::null_mut();
        let mut preflight_pc_after = std::ptr::null_mut();
        let mut preflight_last_kind = std::ptr::null_mut();
        let mut preflight_current_shard_start = std::ptr::null();
        let mut preflight_planner_cur_cells = std::ptr::null_mut();
        let mut preflight_planner_cur_cycle_in_shard = std::ptr::null_mut();
        let mut preflight_planner_cur_step_count = std::ptr::null_mut();
        let mut preflight_planner_max_step_shard = std::ptr::null_mut();
        let mut preflight_planner_shard_id = std::ptr::null_mut();
        let mut preflight_max_cell_per_shard = u64::MAX;
        let mut preflight_target_cell_first_shard = u64::MAX;
        let mut preflight_max_cycle_per_shard = Cycle::MAX;
        let mut preflight_step_cells = Vec::new();
        let mut preflight_heap_min = std::ptr::null_mut();
        let mut preflight_heap_max = std::ptr::null_mut();
        let mut preflight_stack_min = std::ptr::null_mut();
        let mut preflight_stack_max = std::ptr::null_mut();
        let mut preflight_hints_min = std::ptr::null_mut();
        let mut preflight_hints_max = std::ptr::null_mut();
        let mut preflight_block_cells = Vec::new();
        if trace_native_steps && TypeId::of::<T>() == TypeId::of::<PreflightTracer>() {
            let preflight_vm = unsafe { &mut *(vm_ptr as *mut VMState<PreflightTracer>) };
            if preflight_vm.tracer().supports_direct_native_trace() {
                preflight_step_cells = self
                    .program
                    .instructions
                    .iter()
                    .map(|insn| preflight_vm.tracer().native_step_cells_for_kind(insn.kind))
                    .collect();
                if self.trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
                    preflight_block_cells = self
                        .blocks
                        .iter()
                        .map(|block| {
                            let start = ((block.start_pc - self.program.base_address)
                                / PC_STEP_SIZE as u32)
                                as usize;
                            let end = ((block.end_pc - self.program.base_address)
                                / PC_STEP_SIZE as u32)
                                as usize;
                            preflight_step_cells[start..end].iter().copied().sum()
                        })
                        .collect();
                }
                (preflight_heap_min, preflight_heap_max) = preflight_vm
                    .tracer_mut()
                    .native_mmio_bound_ptrs(ByteAddr(heap.start).waddr());
                (preflight_stack_min, preflight_stack_max) = preflight_vm
                    .tracer_mut()
                    .native_mmio_bound_ptrs(ByteAddr(stack.start).waddr());
                (preflight_hints_min, preflight_hints_max) = preflight_vm
                    .tracer_mut()
                    .native_mmio_bound_ptrs(ByteAddr(hints.start).waddr());
                let state = preflight_vm.tracer_mut().native_trace_state();
                trace_mode = AOT_TRACE_MODE_PREFLIGHT_DIRECT;
                preflight_latest_cells = state.latest_cells;
                preflight_latest_base = state.latest_base.0;
                preflight_cycle = state.cycle;
                preflight_pc_before = state.pc_before;
                preflight_pc_after = state.pc_after;
                preflight_last_kind = state.last_kind;
                preflight_current_shard_start = state.current_shard_start_cycle;
                preflight_planner_cur_cells = state.planner_cur_cells;
                preflight_planner_cur_cycle_in_shard = state.planner_cur_cycle_in_shard;
                preflight_planner_cur_step_count = state.planner_cur_step_count;
                preflight_planner_max_step_shard = state.planner_max_step_shard;
                preflight_planner_shard_id = state.planner_shard_id;
                preflight_max_cell_per_shard = state.planner_max_cell_per_shard;
                preflight_target_cell_first_shard = state.planner_target_cell_first_shard;
                preflight_max_cycle_per_shard = state.planner_max_cycle_per_shard;
            }
        }
        let preflight_step_cells_table = if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            preflight_step_cells.as_ptr()
        } else {
            std::ptr::null()
        };
        let preflight_block_cells_table = if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT
            && self.trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan
        {
            preflight_block_cells.as_ptr()
        } else {
            std::ptr::null()
        };
        let mut context = AotRuntimeContext {
            vm: vm_ptr,
            registers,
            trace_pc: 0,
            trace_next_pc: 0,
            trace_rs1_value: 0,
            trace_rs2_value: 0,
            trace_rd_before: 0,
            trace_rd_after: 0,
            memory_cells,
            memory_base_word,
            heap_start: heap.start,
            heap_end: heap.end,
            stack_start: stack.start,
            stack_end: stack.end,
            hints_start: hints.start,
            hints_end: hints.end,
            trace_mem_addr: 0,
            trace_mem_before: 0,
            trace_mem_after: 0,
            pc: pc_ptr,
            instructions,
            program_base,
            trace_flags: 0,
            trace_rs1_idx: 0,
            trace_rs2_idx: 0,
            trace_rd_idx: 0,
            trace_kind: 0,
            trace_mode,
            preflight_latest_cells,
            preflight_latest_base,
            preflight_cycle,
            preflight_pc_before,
            preflight_pc_after,
            preflight_last_kind,
            preflight_current_shard_start,
            preflight_prev_cycle: 0,
            preflight_cur_cycle: 0,
            preflight_event_addr: 0,
            preflight_helper_kind: 0,
            preflight_pending_steps: 0,
            preflight_step_cells: 0,
            preflight_planner_cur_cells,
            preflight_planner_cur_cycle_in_shard,
            preflight_planner_cur_step_count,
            preflight_planner_max_step_shard,
            preflight_planner_shard_id,
            preflight_max_cell_per_shard,
            preflight_target_cell_first_shard,
            preflight_max_cycle_per_shard,
            preflight_step_cells_table,
            preflight_heap_start_word: ByteAddr(heap.start).waddr().0,
            preflight_heap_end_word: ByteAddr(heap.end).waddr().0,
            preflight_stack_start_word: ByteAddr(stack.start).waddr().0,
            preflight_stack_end_word: ByteAddr(stack.end).waddr().0,
            preflight_hints_start_word: ByteAddr(hints.start).waddr().0,
            preflight_hints_end_word: ByteAddr(hints.end).waddr().0,
            preflight_heap_min,
            preflight_heap_max,
            preflight_stack_min,
            preflight_stack_max,
            preflight_hints_min,
            preflight_hints_max,
            fallback_steps: 0,
            preflight_block_cells_table,
        };
        let trace_fn = if trace_native_steps {
            if TypeId::of::<T>() == TypeId::of::<PreflightTracer>() {
                if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
                    (aot_preflight_direct_helper as AotTraceFn) as *const c_void
                } else {
                    (aot_trace_native_preflight as AotTraceFn) as *const c_void
                }
            } else {
                (aot_trace_native_compute::<T> as AotTraceFn) as *const c_void
            }
        } else {
            std::ptr::null()
        };
        let native_status = unsafe {
            (self.entry)(
                &mut context,
                aot_exec_one::<T>,
                trace_fn,
                max_steps as u64,
                &mut executed_steps,
                vm.get_pc().0,
            )
        };
        if native_status == AOT_STATUS_ERROR {
            let err = LAST_AOT_ERROR
                .with(|slot| slot.borrow_mut().take())
                .unwrap_or_else(|| anyhow!("AOT native step failed without error detail"));
            return Err(err);
        }
        if native_status != AOT_STATUS_HALTED {
            bail!("AOT native entry returned invalid status {native_status}");
        }
        Ok(AotRunReport {
            executed_steps: executed_steps as usize,
            fallback_steps: context.fallback_steps as usize,
            execute_time: started.elapsed(),
        })
    }
}

#[derive(Debug)]
pub struct AotRunReport {
    pub executed_steps: usize,
    pub fallback_steps: usize,
    pub execute_time: Duration,
}

pub fn partition_basic_blocks(program: &Program) -> Result<Vec<BasicBlock>> {
    partition_basic_blocks_with_roots(program, Vec::new())
}

pub fn partition_basic_blocks_with_roots(
    program: &Program,
    extra_roots: Vec<u32>,
) -> Result<Vec<BasicBlock>> {
    partition_basic_blocks_inner(program, extra_roots)
}

fn partition_basic_blocks_inner(
    program: &Program,
    extra_roots: Vec<u32>,
) -> Result<Vec<BasicBlock>> {
    if program.instructions.is_empty() {
        bail!("AOT program has no instructions");
    }

    let mut leaders = BTreeSet::new();
    leaders.insert(program.entry);
    leaders.extend(extra_roots.iter().copied());
    for (idx, &insn) in program.instructions.iter().enumerate() {
        let pc = program.base_address + (idx as u32 * PC_STEP_SIZE as u32);
        match insn.kind {
            InsnKind::BEQ
            | InsnKind::BNE
            | InsnKind::BLT
            | InsnKind::BGE
            | InsnKind::BLTU
            | InsnKind::BGEU => {
                leaders.insert(branch_target(pc, insn)?);
                if let Some(next_pc) = fallthrough_pc(program, pc) {
                    leaders.insert(next_pc);
                }
            }
            InsnKind::JAL => {
                leaders.insert(branch_target(pc, insn)?);
                if let Some(next_pc) = fallthrough_pc(program, pc) {
                    leaders.insert(next_pc);
                }
            }
            InsnKind::JALR | InsnKind::ECALL | InsnKind::INVALID => {
                if let Some(next_pc) = fallthrough_pc(program, pc) {
                    leaders.insert(next_pc);
                }
            }
            _ => {}
        }
    }

    let valid_leaders = leaders
        .into_iter()
        .filter(|pc| instruction_at(program, *pc).is_ok())
        .collect::<BTreeSet<_>>();

    let mut reachable_leaders = BTreeSet::new();
    let mut pending = vec![program.entry];
    pending.extend(
        valid_leaders
            .iter()
            .copied()
            .filter(|pc| extra_roots.contains(pc)),
    );
    let mut blocks = Vec::new();
    while let Some(start_pc) = pending.pop() {
        if !valid_leaders.contains(&start_pc) || !reachable_leaders.insert(start_pc) {
            continue;
        }
        let mut end_pc = start_pc;
        loop {
            let insn = instruction_at(program, end_pc)?;
            end_pc = end_pc.wrapping_add(PC_STEP_SIZE as u32);
            let terminates = terminates_block(insn.kind);
            if terminates
                || instruction_at(program, end_pc).is_err()
                || valid_leaders.contains(&end_pc)
            {
                blocks.push(BasicBlock { start_pc, end_pc });
                for successor in static_successors(program, end_pc - PC_STEP_SIZE as u32, insn)? {
                    if valid_leaders.contains(&successor) {
                        pending.push(successor);
                    }
                }
                break;
            }
        }
    }

    blocks.sort_by_key(|block| block.start_pc);

    Ok(blocks)
}

fn terminates_block(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::BEQ
            | InsnKind::BNE
            | InsnKind::BLT
            | InsnKind::BGE
            | InsnKind::BLTU
            | InsnKind::BGEU
            | InsnKind::JAL
            | InsnKind::JALR
            | InsnKind::ECALL
            | InsnKind::INVALID
    )
}

fn instruction_at(program: &Program, pc: u32) -> Result<Instruction> {
    if !pc.is_multiple_of(PC_STEP_SIZE as u32) {
        bail!("instruction pc {pc:#010x} is misaligned");
    }
    let relative_pc = pc.wrapping_sub(program.base_address);
    let idx = (relative_pc / PC_STEP_SIZE as u32) as usize;
    program
        .instructions
        .get(idx)
        .copied()
        .ok_or_else(|| anyhow!("instruction pc {pc:#010x} is outside program"))
}

fn branch_target(pc: u32, insn: Instruction) -> Result<u32> {
    let target = ByteAddr(pc).wrapping_add(insn.imm as u32).0;
    if !target.is_multiple_of(PC_STEP_SIZE as u32) {
        bail!("branch target {target:#010x} is misaligned");
    }
    Ok(target)
}

fn fallthrough_pc(program: &Program, pc: u32) -> Option<u32> {
    let next_pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    let relative_pc = next_pc.wrapping_sub(program.base_address);
    let idx = (relative_pc / PC_STEP_SIZE as u32) as usize;
    (idx < program.instructions.len()).then_some(next_pc)
}

fn static_successors(program: &Program, pc: u32, insn: Instruction) -> Result<Vec<u32>> {
    let mut successors = Vec::new();
    match insn.kind {
        InsnKind::BEQ
        | InsnKind::BNE
        | InsnKind::BLT
        | InsnKind::BGE
        | InsnKind::BLTU
        | InsnKind::BGEU => {
            successors.push(branch_target(pc, insn)?);
            if let Some(next_pc) = fallthrough_pc(program, pc) {
                successors.push(next_pc);
            }
        }
        InsnKind::JAL => {
            successors.push(branch_target(pc, insn)?);
        }
        InsnKind::JALR | InsnKind::ECALL | InsnKind::INVALID => {}
        _ => {
            if let Some(next_pc) = fallthrough_pc(program, pc) {
                successors.push(next_pc);
            }
        }
    }
    successors.sort_unstable();
    successors.dedup();
    Ok(successors)
}

fn compile_and_load_native(
    program: &Program,
    blocks: &[BasicBlock],
    trace_style: AssemblyTraceStyle,
) -> Result<(Library, NativeEntry)> {
    let dir = tempfile::Builder::new()
        .prefix("ceno-aot-")
        .tempdir()
        .context("create AOT tempdir")?;
    let asm_path = dir.path().join("program.S");
    let so_path = dir.path().join("program.so");
    write_assembly(&asm_path, program, blocks, trace_style)?;
    let output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-x")
        .arg("assembler")
        .arg(&asm_path)
        .arg("-o")
        .arg(&so_path)
        .output()
        .context("invoke cc for AOT assembly")?;
    if !output.status.success() {
        bail!(
            "AOT assembly compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let library = unsafe { Library::new(&so_path) }.context("load AOT shared object")?;
    let entry = unsafe {
        let symbol: Symbol<'_, NativeEntry> = library
            .get(b"ceno_aot_entry")
            .context("load ceno_aot_entry")?;
        *symbol
    };
    Ok((library, entry))
}

fn write_assembly(
    path: &Path,
    program: &Program,
    blocks: &[BasicBlock],
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    let mut labels = BTreeMap::new();
    for (idx, block) in blocks.iter().enumerate() {
        labels.insert(block.start_pc, format!("L_bb_{idx}"));
    }

    let mut file = fs::File::create(path).context("create AOT assembly")?;
    writeln!(file, ".text")?;
    writeln!(file, ".globl ceno_aot_entry")?;
    writeln!(file, ".type ceno_aot_entry, @function")?;
    writeln!(file, "ceno_aot_entry:")?;
    writeln!(file, "    pushq %rbx")?;
    writeln!(file, "    pushq %r12")?;
    writeln!(file, "    pushq %r13")?;
    writeln!(file, "    pushq %r14")?;
    writeln!(file, "    pushq %r15")?;
    writeln!(file, "    pushq %rbp")?;
    writeln!(file, "    subq $24, %rsp")?;
    writeln!(file, "    movq %rdi, %r12")?;
    writeln!(file, "    movq %rsi, %r13")?;
    writeln!(file, "    movq %rdx, %r14")?;
    writeln!(file, "    movq %rcx, %rbp")?;
    writeln!(file, "    movq %r8, %rbx")?;
    writeln!(file, "    movl %r9d, %r15d")?;
    writeln!(file, "    movq $0, 0(%rsp)")?;
    writeln!(file, "    movl %r15d, 8(%rsp)")?;
    writeln!(file, "L_dispatch:")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    jae L_done")?;
    emit_dispatch_tree(&mut file, blocks, &labels, 0, blocks.len())?;
    for (block_idx, block) in blocks.iter().enumerate() {
        let label = labels.get(&block.start_pc).expect("block label must exist");
        writeln!(file, "{label}:")?;
        let block_plan = if trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
            preflight_block_plan_kind(program, block)?
        } else {
            None
        };
        if block_plan.is_some() {
            emit_preflight_direct_block_budget_guard(&mut file, block)?;
            if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess)) {
                emit_preflight_direct_block_memory_fast_path_guard(&mut file, program, block)?;
            }
            emit_preflight_direct_block_plan_entry(&mut file, block_idx, block)?;
            if matches!(block_plan, Some(PreflightBlockPlanKind::RegisterOnly)) {
                emit_preflight_direct_block_access_entry(&mut file, program, block_idx, block)?;
            }
        }
        let mut pc = block.start_pc;
        while pc < block.end_pc {
            let insn = instruction_at(program, pc)?;
            let step_trace_style =
                if matches!(block_plan, Some(PreflightBlockPlanKind::RegisterOnly)) {
                    AssemblyTraceStyle::PreflightDirectBlockPlan
                } else if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess)) {
                    AssemblyTraceStyle::PreflightDirectBlockPlanExactAccess
                } else if trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
                    AssemblyTraceStyle::PreflightDirect
                } else {
                    trace_style
                };
            emit_instruction_body(&mut file, program, pc, insn, step_trace_style)?;
            pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        }
        if let Some(prev_pc) = pc.checked_sub(PC_STEP_SIZE as u32) {
            let insn = instruction_at(program, prev_pc)?;
            if block_plan.is_some() {
                emit_preflight_direct_block_plan_exit(&mut file, block_idx, block)?;
                emit_preflight_direct_busy_loop_guard(&mut file, prev_pc)?;
            }
            emit_successor_jump(&mut file, program, &labels, prev_pc, insn)?;
        }
    }
    writeln!(file, "L_dynamic:")?;
    emit_call_current_pc(&mut file)?;
    writeln!(file, "    jmp L_dispatch")?;
    writeln!(file, "L_done:")?;
    emit_sync_preflight_direct(&mut file)?;
    writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
    writeln!(file, "    movl %r15d, (%rdx)")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    movq %rax, (%rbx)")?;
    writeln!(file, "    movl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    jmp L_return")?;
    writeln!(file, "L_error:")?;
    writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
    writeln!(file, "    movl %r15d, (%rdx)")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    movq %rax, (%rbx)")?;
    writeln!(file, "    movl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "L_return:")?;
    writeln!(file, "    addq $24, %rsp")?;
    writeln!(file, "    popq %rbp")?;
    writeln!(file, "    popq %r15")?;
    writeln!(file, "    popq %r14")?;
    writeln!(file, "    popq %r13")?;
    writeln!(file, "    popq %r12")?;
    writeln!(file, "    popq %rbx")?;
    writeln!(file, "    ret")?;
    writeln!(file, ".section .note.GNU-stack,\"\",@progbits")?;
    Ok(())
}

fn emit_dispatch_tree(
    file: &mut impl Write,
    blocks: &[BasicBlock],
    labels: &BTreeMap<u32, String>,
    start: usize,
    end: usize,
) -> Result<()> {
    if start >= end {
        writeln!(file, "    jmp L_dynamic")?;
        return Ok(());
    }

    if end - start <= 8 {
        for block in &blocks[start..end] {
            let label = labels.get(&block.start_pc).expect("block label must exist");
            writeln!(file, "    cmpl ${:#010x}, %r15d", block.start_pc)?;
            writeln!(file, "    je {label}")?;
        }
        writeln!(file, "    jmp L_dynamic")?;
        return Ok(());
    }

    let mid = start + (end - start) / 2;
    let block = &blocks[mid];
    let label = labels.get(&block.start_pc).expect("block label must exist");
    let lower_label = format!(".L_dispatch_lower_{start}_{end}");

    writeln!(file, "    cmpl ${:#010x}, %r15d", block.start_pc)?;
    writeln!(file, "    jb {lower_label}")?;
    writeln!(file, "    je {label}")?;
    emit_dispatch_tree(file, blocks, labels, mid + 1, end)?;
    writeln!(file, "{lower_label}:")?;
    emit_dispatch_tree(file, blocks, labels, start, mid)?;
    Ok(())
}

fn emit_call_one(mut file: impl Write, pc: u32) -> Result<()> {
    emit_sync_preflight_direct(&mut file)?;
    writeln!(file, "    incq {AOT_CTX_FALLBACK_STEPS_OFFSET}(%r12)")?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq {AOT_CTX_VM_OFFSET}(%r12), %rdi")?;
    writeln!(file, "    movl ${pc:#010x}, %esi")?;
    writeln!(file, "    call *%r13")?;
    emit_after_step(&mut file)?;
    Ok(())
}

fn emit_call_current_pc(mut file: impl Write) -> Result<()> {
    emit_sync_preflight_direct(&mut file)?;
    writeln!(file, "    incq {AOT_CTX_FALLBACK_STEPS_OFFSET}(%r12)")?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq {AOT_CTX_VM_OFFSET}(%r12), %rdi")?;
    writeln!(file, "    movl %r15d, %esi")?;
    writeln!(file, "    call *%r13")?;
    emit_after_step(&mut file)?;
    Ok(())
}

fn emit_after_step(mut file: impl Write) -> Result<()> {
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "    incq 0(%rsp)")?;
    writeln!(file, "    movl 8(%rsp), %r15d")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je L_done")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    jae L_done")?;
    Ok(())
}

fn emit_after_native_step(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    preflight_memory_bounds_updated: bool,
) -> Result<()> {
    if trace_style.is_preflight_direct() {
        writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
        writeln!(file, "    movl %r15d, 8(%rsp)")?;
        emit_preflight_direct_step_static(
            &mut file,
            pc,
            program,
            insn,
            trace_style == AssemblyTraceStyle::PreflightDirect,
            preflight_memory_bounds_updated,
            if trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
                PreflightAccessMode::BlockAtomic
            } else {
                PreflightAccessMode::Exact
            },
            matches!(trace_style, AssemblyTraceStyle::PreflightDirect),
        )?;
        emit_after_step(&mut file)?;
        return Ok(());
    }

    let no_trace_label = format!(".L_after_native_no_trace_{pc:x}");
    let direct_label = format!(".L_after_native_direct_{pc:x}");
    let callback_label = format!(".L_after_native_callback_{pc:x}");
    let done_label = format!(".L_after_native_done_{pc:x}");
    writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
    writeln!(file, "    movl %r15d, 8(%rsp)")?;
    writeln!(file, "    testq %r14, %r14")?;
    writeln!(file, "    je {no_trace_label}")?;
    writeln!(
        file,
        "    cmpl ${AOT_TRACE_MODE_PREFLIGHT_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
    )?;
    writeln!(file, "    je {direct_label}")?;
    writeln!(file, "    jmp {callback_label}")?;
    writeln!(file, "{callback_label}:")?;
    emit_native_trace_metadata(&mut file, pc, program, insn)?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{no_trace_label}:")?;
    writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{direct_label}:")?;
    emit_preflight_direct_step_static(
        &mut file,
        pc,
        program,
        insn,
        true,
        false,
        PreflightAccessMode::Exact,
        true,
    )?;
    writeln!(file, "{done_label}:")?;
    emit_after_step(&mut file)?;
    Ok(())
}

fn emit_sync_preflight_direct(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    cmpl ${AOT_TRACE_MODE_PREFLIGHT_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jne 1f")?;
    writeln!(
        file,
        "    cmpq $0, {AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET}(%r12)"
    )?;
    writeln!(file, "    je 1f")?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_SYNC}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "1:")?;
    Ok(())
}

fn block_instruction_count(block: &BasicBlock) -> u64 {
    ((block.end_pc - block.start_pc) / PC_STEP_SIZE as u32) as u64
}

#[derive(Clone, Copy)]
enum PreflightAccessMode {
    Exact,
    BlockAtomic,
}

#[derive(Clone, Copy)]
struct PreflightBlockAccess {
    addr: u32,
    cycle_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreflightBlockPlanKind {
    RegisterOnly,
    MemoryExactAccess,
}

#[cfg(test)]
fn block_supports_preflight_block_plan(program: &Program, block: &BasicBlock) -> Result<bool> {
    Ok(matches!(
        preflight_block_plan_kind(program, block)?,
        Some(PreflightBlockPlanKind::RegisterOnly)
    ))
}

fn preflight_block_plan_kind(
    program: &Program,
    block: &BasicBlock,
) -> Result<Option<PreflightBlockPlanKind>> {
    let mut has_memory = false;
    let mut written_regs = BTreeSet::new();
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        match native_opcode_family(insn.kind) {
            Some(NativeOpcodeFamily::Compute) => {}
            Some(NativeOpcodeFamily::ControlFlow) => {
                if matches!(insn.kind, InsnKind::JALR) {
                    return Ok(None);
                }
            }
            Some(NativeOpcodeFamily::Memory) => {
                has_memory = true;
                if written_regs.contains(&insn.rs1) {
                    return Ok(None);
                }
            }
            None => return Ok(None),
        }
        if native_step_writes_rd(insn.kind) {
            written_regs.insert(insn.rd_internal() as RegIdx);
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(Some(if has_memory {
        PreflightBlockPlanKind::MemoryExactAccess
    } else {
        PreflightBlockPlanKind::RegisterOnly
    }))
}

fn preflight_static_register_accesses(insn: Instruction) -> Vec<(u32, PreflightSubcycle)> {
    let mut accesses = Vec::new();
    if native_step_reads_rs1(insn.kind) {
        accesses.push((insn.rs1 as u32, PreflightSubcycle::Rs1));
    }
    if native_step_reads_rs2(insn.kind) {
        accesses.push((insn.rs2 as u32, PreflightSubcycle::Rs2));
    }
    if native_step_writes_rd(insn.kind) {
        accesses.push((insn.rd_internal(), PreflightSubcycle::Rd));
    }
    accesses
}

fn preflight_block_first_accesses(
    program: &Program,
    block: &BasicBlock,
) -> Result<Vec<PreflightBlockAccess>> {
    let mut first_accesses = BTreeMap::new();
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        let insn_cycle_offset = (pc - block.start_pc) as u64;
        for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
            let addr = reg_idx << 6;
            first_accesses
                .entry(addr)
                .or_insert(insn_cycle_offset + subcycle.value());
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(first_accesses
        .into_iter()
        .map(|(addr, cycle_offset)| PreflightBlockAccess { addr, cycle_offset })
        .collect())
}

fn emit_preflight_direct_block_budget_guard(
    mut file: impl Write,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    addq ${block_steps}, %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    ja L_dynamic")?;
    Ok(())
}

fn emit_preflight_direct_block_memory_fast_path_guard(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    writeln!(file, "    movq {AOT_CTX_REGISTERS_OFFSET}(%r12), %r10")?;
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        if matches!(
            native_opcode_family(insn.kind),
            Some(NativeOpcodeFamily::Memory)
        ) {
            emit_preflight_direct_memory_fast_path_guard(&mut file, pc, insn)?;
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(())
}

fn emit_preflight_direct_memory_fast_path_guard(
    mut file: impl Write,
    pc: u32,
    insn: Instruction,
) -> Result<()> {
    let heap_ok_label = format!(".L_block_memory_heap_ok_{pc:x}");
    let stack_ok_label = format!(".L_block_memory_stack_ok_{pc:x}");
    let hints_ok_label = format!(".L_block_memory_hints_ok_{pc:x}");
    let done_label = format!(".L_block_memory_guard_done_{pc:x}");

    writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
    writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
    match insn.kind {
        InsnKind::LH | InsnKind::LHU | InsnKind::SH => {
            writeln!(file, "    testl $1, %edx")?;
            writeln!(file, "    jne L_dynamic")?;
        }
        InsnKind::LW | InsnKind::SW => {
            writeln!(file, "    testl $3, %edx")?;
            writeln!(file, "    jne L_dynamic")?;
        }
        _ => {}
    }
    emit_native_range_check(
        &mut file,
        AOT_CTX_HEAP_START_OFFSET,
        AOT_CTX_HEAP_END_OFFSET,
        &heap_ok_label,
    )?;
    emit_native_range_check(
        &mut file,
        AOT_CTX_STACK_START_OFFSET,
        AOT_CTX_STACK_END_OFFSET,
        &stack_ok_label,
    )?;
    emit_native_range_check(
        &mut file,
        AOT_CTX_HINTS_START_OFFSET,
        AOT_CTX_HINTS_END_OFFSET,
        &hints_ok_label,
    )?;
    writeln!(file, "    jmp L_dynamic")?;
    writeln!(file, "{heap_ok_label}:")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{stack_ok_label}:")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{hints_ok_label}:")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_block_access_entry(
    mut file: impl Write,
    program: &Program,
    block_idx: usize,
    block: &BasicBlock,
) -> Result<()> {
    let accesses = preflight_block_first_accesses(program, block)?;
    if accesses.is_empty() {
        return Ok(());
    }

    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r8")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r10")?;

    for (access_idx, access) in accesses.iter().enumerate() {
        let done_label = format!(".L_preflight_block_access_done_{block_idx}_{access_idx}");
        let event_label = format!(".L_preflight_block_access_event_{block_idx}_{access_idx}");
        let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
        writeln!(file, "    movq {offset}(%rdx), %r11")?;
        writeln!(file, "    testq %r11, %r11")?;
        writeln!(file, "    je {event_label}")?;
        writeln!(file, "    cmpq %r10, %r11")?;
        writeln!(file, "    jae {done_label}")?;
        writeln!(file, "{event_label}:")?;
        writeln!(
            file,
            "    movl ${}, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)",
            access.addr
        )?;
        writeln!(
            file,
            "    movq %r11, {AOT_CTX_PREFLIGHT_PREV_CYCLE_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movq %r8, %rax")?;
        writeln!(file, "    addq ${}, %rax", access.cycle_offset)?;
        writeln!(
            file,
            "    movq %rax, {AOT_CTX_PREFLIGHT_CUR_CYCLE_OFFSET}(%r12)"
        )?;
        writeln!(
            file,
            "    movl ${AOT_PREFLIGHT_HELPER_ACCESS}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movq %r12, %rdi")?;
        writeln!(file, "    call *%r14")?;
        writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
        writeln!(file, "    je L_error")?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
        )?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    movq (%rax), %r10")?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    movq (%rax), %r8")?;
        writeln!(file, "{done_label}:")?;
    }
    Ok(())
}

fn emit_load_preflight_block_cells(
    mut file: impl Write,
    block_idx: usize,
    label_suffix: &str,
    dst_reg: &str,
) -> Result<()> {
    let zero_label = format!(".L_preflight_block_cells_zero_{block_idx}_{label_suffix}");
    let done_label = format!(".L_preflight_block_cells_done_{block_idx}_{label_suffix}");
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_BLOCK_CELLS_TABLE_OFFSET}(%r12), {dst_reg}"
    )?;
    writeln!(file, "    testq {dst_reg}, {dst_reg}")?;
    writeln!(file, "    je {zero_label}")?;
    writeln!(file, "    movq {}({dst_reg}), {dst_reg}", block_idx * 8)?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{zero_label}:")?;
    writeln!(file, "    xorq {dst_reg}, {dst_reg}")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_block_plan_entry(
    mut file: impl Write,
    block_idx: usize,
    block: &BasicBlock,
) -> Result<()> {
    let no_split_label = format!(".L_preflight_block_no_split_{block_idx}");
    let first_shard_label = format!(".L_preflight_block_first_shard_{block_idx}");
    let target_done_label = format!(".L_preflight_block_target_done_{block_idx}");
    let split_label = format!(".L_preflight_block_split_{block_idx}");
    let block_cycles = block_instruction_count(block) * PC_STEP_SIZE as u64;

    emit_load_preflight_block_cells(&mut file, block_idx, "entry", "%r8")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    cmpq $0, (%rax)")?;
    writeln!(file, "    je {no_split_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_SHARD_ID_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    cmpq $0, (%rax)")?;
    writeln!(file, "    je {first_shard_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_MAX_CELL_PER_SHARD_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    jmp {target_done_label}")?;
    writeln!(file, "{first_shard_label}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_TARGET_CELL_FIRST_SHARD_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "{target_done_label}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CELLS_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r9")?;
    writeln!(file, "    addq %r8, %r9")?;
    writeln!(file, "    cmpq %r10, %r9")?;
    writeln!(file, "    jae {split_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r9")?;
    writeln!(file, "    addq ${block_cycles}, %r9")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_MAX_CYCLE_PER_SHARD_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    cmpq %r10, %r9")?;
    writeln!(file, "    jb {no_split_label}")?;
    writeln!(file, "{split_label}:")?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_SHARD_SPLIT}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "{no_split_label}:")?;
    Ok(())
}

fn emit_preflight_direct_block_plan_exit(
    mut file: impl Write,
    block_idx: usize,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    let block_cycles = block_steps * PC_STEP_SIZE as u64;
    emit_load_preflight_block_cells(&mut file, block_idx, "exit", "%r8")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CELLS_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq %r8, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq ${block_cycles}, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq ${block_steps}, (%rax)")?;
    Ok(())
}

fn emit_preflight_direct_step_static(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    update_planner: bool,
    preflight_memory_bounds_updated: bool,
    access_mode: PreflightAccessMode,
    check_busy_loop: bool,
) -> Result<()> {
    let has_memory_access =
        native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind);
    if has_memory_access && !preflight_memory_bounds_updated {
        writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
        emit_preflight_direct_memory_bounds(&mut file, "%eax")?;
    }

    match access_mode {
        PreflightAccessMode::Exact => {
            if native_step_reads_rs1(insn.kind)
                || native_step_reads_rs2(insn.kind)
                || native_step_writes_rd(insn.kind)
                || has_memory_access
            {
                emit_preflight_direct_access_cache_load(&mut file)?;
            }

            if native_step_loads_memory(insn.kind) {
                if native_step_reads_rs1(insn.kind) {
                    emit_preflight_direct_register_access_cached(
                        &mut file,
                        insn.rs1 as u32,
                        PreflightSubcycle::Rs1,
                    )?;
                }
                writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                emit_preflight_direct_access_cached(&mut file, "%eax", PreflightSubcycle::Mem)?;
                if native_step_writes_rd(insn.kind) {
                    emit_preflight_direct_register_access_cached(
                        &mut file,
                        insn.rd_internal(),
                        PreflightSubcycle::Rd,
                    )?;
                }
            } else {
                for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
                    emit_preflight_direct_register_access_cached(&mut file, reg_idx, subcycle)?;
                }
                if has_memory_access {
                    writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                    emit_preflight_direct_access_cached(&mut file, "%eax", PreflightSubcycle::Mem)?;
                }
            }
        }
        PreflightAccessMode::BlockAtomic => {
            debug_assert!(!has_memory_access);
            if native_step_reads_rs1(insn.kind)
                || native_step_reads_rs2(insn.kind)
                || native_step_writes_rd(insn.kind)
            {
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
                )?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
                )?;
                writeln!(file, "    movq (%rax), %r8")?;
            }
            for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
                emit_preflight_direct_register_access_store_only(
                    &mut file,
                    reg_idx,
                    subcycle.value(),
                )?;
            }
        }
    }

    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq $4, (%rax)")?;
    writeln!(
        file,
        "    incq {AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET}(%r12)"
    )?;
    if update_planner {
        emit_preflight_direct_planner_step_static(&mut file, program, pc)?;
    }
    if check_busy_loop {
        emit_preflight_direct_busy_loop_guard(&mut file, pc)?;
    }
    writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
    Ok(())
}

fn emit_preflight_direct_busy_loop_guard(mut file: impl Write, pc: u32) -> Result<()> {
    let done_label = format!(".L_preflight_busy_loop_done_{pc:x}");
    writeln!(
        file,
        "    cmpl ${pc:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jne {done_label}")?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_BUSY_LOOP}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je L_done")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_memory_bounds(mut file: impl Write, addr_reg: &str) -> Result<()> {
    emit_preflight_direct_memory_bound_region(
        &mut file,
        addr_reg,
        AOT_CTX_PREFLIGHT_HEAP_START_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HEAP_END_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HEAP_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET,
    )?;
    emit_preflight_direct_memory_bound_region(
        &mut file,
        addr_reg,
        AOT_CTX_PREFLIGHT_STACK_START_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_STACK_END_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_STACK_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_STACK_MAX_OFFSET,
    )?;
    emit_preflight_direct_memory_bound_region(
        &mut file,
        addr_reg,
        AOT_CTX_PREFLIGHT_HINTS_START_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HINTS_END_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HINTS_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET,
    )?;
    Ok(())
}

fn emit_preflight_direct_memory_bound_region(
    mut file: impl Write,
    addr_reg: &str,
    start_offset: usize,
    end_offset: usize,
    min_ptr_offset: usize,
    max_ptr_offset: usize,
) -> Result<()> {
    writeln!(file, "    movl {addr_reg}, %r9d")?;
    writeln!(file, "    cmpl {start_offset}(%r12), %r9d")?;
    writeln!(file, "    jb 1f")?;
    writeln!(file, "    cmpl {end_offset}(%r12), %r9d")?;
    writeln!(file, "    jae 1f")?;
    writeln!(file, "    movq {min_ptr_offset}(%r12), %rdx")?;
    writeln!(file, "    testq %rdx, %rdx")?;
    writeln!(file, "    je 2f")?;
    writeln!(file, "    cmpl (%rdx), %r9d")?;
    writeln!(file, "    jae 2f")?;
    writeln!(file, "    movl %r9d, (%rdx)")?;
    writeln!(file, "2:")?;
    writeln!(file, "    movq {max_ptr_offset}(%r12), %rdx")?;
    writeln!(file, "    testq %rdx, %rdx")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    cmpl (%rdx), %r9d")?;
    writeln!(file, "    jb 1f")?;
    writeln!(file, "    leal 1(%r9d), %ecx")?;
    writeln!(file, "    movl %ecx, (%rdx)")?;
    writeln!(file, "1:")?;
    Ok(())
}

fn emit_preflight_direct_memory_bound_known_region(
    mut file: impl Write,
    addr_reg: &str,
    min_ptr_offset: usize,
    max_ptr_offset: usize,
) -> Result<()> {
    writeln!(file, "    movq {min_ptr_offset}(%r12), %rax")?;
    writeln!(file, "    testq %rax, %rax")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    cmpl (%rax), {addr_reg}")?;
    writeln!(file, "    jae 1f")?;
    writeln!(file, "    movl {addr_reg}, (%rax)")?;
    writeln!(file, "1:")?;
    writeln!(file, "    movq {max_ptr_offset}(%r12), %rax")?;
    writeln!(file, "    testq %rax, %rax")?;
    writeln!(file, "    je 2f")?;
    writeln!(file, "    cmpl (%rax), {addr_reg}")?;
    writeln!(file, "    jb 2f")?;
    writeln!(file, "    leal 1({addr_reg}), %ecx")?;
    writeln!(file, "    movl %ecx, (%rax)")?;
    writeln!(file, "2:")?;
    Ok(())
}

fn emit_preflight_direct_planner_step_static(
    mut file: impl Write,
    program: &Program,
    pc: u32,
) -> Result<()> {
    let insn_idx = (pc.wrapping_sub(program.base_address) / PC_STEP_SIZE as u32) as usize;
    let no_step_cells_label = format!(".L_preflight_no_step_cells_{pc:x}");
    let step_cells_done_label = format!(".L_preflight_step_cells_done_{pc:x}");
    let no_split_label = format!(".L_preflight_no_split_{pc:x}");
    let split_done_label = format!(".L_preflight_split_done_{pc:x}");

    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_STEP_CELLS_TABLE_OFFSET}(%r12), %rcx"
    )?;
    writeln!(file, "    testq %rcx, %rcx")?;
    writeln!(file, "    je {no_step_cells_label}")?;
    writeln!(file, "    movq {}(%rcx), %rcx", insn_idx * 8)?;
    writeln!(file, "    jmp {step_cells_done_label}")?;
    writeln!(file, "{no_step_cells_label}:")?;
    writeln!(file, "    xorq %rcx, %rcx")?;
    writeln!(file, "{step_cells_done_label}:")?;

    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CELLS_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq %rcx, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq $4, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    incq (%rax)")?;

    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_SHARD_ID_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    cmpq $0, (%rax)")?;
    writeln!(file, "    jne 1f")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_TARGET_CELL_FIRST_SHARD_OFFSET}(%r12), %rcx"
    )?;
    writeln!(file, "    jmp 2f")?;
    writeln!(file, "1:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_MAX_CELL_PER_SHARD_OFFSET}(%r12), %rcx"
    )?;
    writeln!(file, "2:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CELLS_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    cmpq %rcx, (%rax)")?;
    writeln!(file, "    jae 3f")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_MAX_CYCLE_PER_SHARD_OFFSET}(%r12), %rcx"
    )?;
    writeln!(file, "    cmpq %rcx, (%rax)")?;
    writeln!(file, "    jb {no_split_label}")?;
    writeln!(file, "3:")?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_SHARD_SPLIT}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "    jmp {split_done_label}")?;
    writeln!(file, "{no_split_label}:")?;
    writeln!(file, "{split_done_label}:")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum PreflightSubcycle {
    Rs1,
    Rs2,
    Rd,
    Mem,
}

impl PreflightSubcycle {
    fn value(self) -> u64 {
        match self {
            PreflightSubcycle::Rs1 => 0,
            PreflightSubcycle::Rs2 => 1,
            PreflightSubcycle::Rd => 2,
            PreflightSubcycle::Mem => 3,
        }
    }
}

fn emit_preflight_direct_access_cache_load(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rsi"
    )?;
    writeln!(file, "    movq (%rsi), %r8")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET}(%r12), %rsi"
    )?;
    writeln!(file, "    movq (%rsi), %r10")?;
    Ok(())
}

fn emit_preflight_direct_access_helper_call(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_ACCESS}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    emit_preflight_direct_access_cache_load(&mut file)?;
    Ok(())
}

fn emit_preflight_direct_access_cached(
    mut file: impl Write,
    addr_reg: &str,
    subcycle: PreflightSubcycle,
) -> Result<()> {
    writeln!(file, "    movl {addr_reg}, %ecx")?;
    writeln!(file, "    movq %r8, %r9")?;
    writeln!(file, "    addq ${}, %r9", subcycle.value())?;
    writeln!(file, "    movq (%rdx,%rcx,8), %r11")?;
    writeln!(file, "    movq %r9, (%rdx,%rcx,8)")?;
    writeln!(file, "    testq %r11, %r11")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    cmpq %r10, %r11")?;
    writeln!(file, "    jae 2f")?;
    writeln!(file, "1:")?;
    writeln!(
        file,
        "    movl %ecx, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movq %r11, {AOT_CTX_PREFLIGHT_PREV_CYCLE_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movq %r9, {AOT_CTX_PREFLIGHT_CUR_CYCLE_OFFSET}(%r12)"
    )?;
    emit_preflight_direct_access_helper_call(&mut file)?;
    writeln!(file, "2:")?;
    Ok(())
}

fn emit_preflight_direct_register_access_cached(
    mut file: impl Write,
    reg_idx: u32,
    subcycle: PreflightSubcycle,
) -> Result<()> {
    let addr = reg_idx << 6;
    let offset = addr as u64 * std::mem::size_of::<Cycle>() as u64;
    writeln!(file, "    movq %r8, %rax")?;
    writeln!(file, "    addq ${}, %rax", subcycle.value())?;
    writeln!(file, "    movq {offset}(%rdx), %r11")?;
    writeln!(file, "    movq %rax, {offset}(%rdx)")?;
    writeln!(file, "    testq %r11, %r11")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    cmpq %r10, %r11")?;
    writeln!(file, "    jae 2f")?;
    writeln!(file, "1:")?;
    writeln!(
        file,
        "    movl ${addr}, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movq %r11, {AOT_CTX_PREFLIGHT_PREV_CYCLE_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movq %rax, {AOT_CTX_PREFLIGHT_CUR_CYCLE_OFFSET}(%r12)"
    )?;
    emit_preflight_direct_access_helper_call(&mut file)?;
    writeln!(file, "2:")?;
    Ok(())
}

fn emit_preflight_direct_register_access_store_only(
    mut file: impl Write,
    reg_idx: u32,
    cycle_offset: u64,
) -> Result<()> {
    let addr = reg_idx << 6;
    let offset = addr as u64 * std::mem::size_of::<Cycle>() as u64;
    writeln!(file, "    movq %r8, %rax")?;
    writeln!(file, "    addq ${cycle_offset}, %rax")?;
    writeln!(file, "    movq %rax, {offset}(%rdx)")?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeOpcodeFamily {
    Compute,
    ControlFlow,
    Memory,
}

fn native_opcode_family(kind: InsnKind) -> Option<NativeOpcodeFamily> {
    if supports_native_compute(kind) {
        Some(NativeOpcodeFamily::Compute)
    } else if supports_native_control_flow(kind) {
        Some(NativeOpcodeFamily::ControlFlow)
    } else if supports_native_memory(kind) {
        Some(NativeOpcodeFamily::Memory)
    } else {
        None
    }
}

fn emit_instruction_body(
    mut file: impl Write,
    program: &Program,
    pc: u32,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    match native_opcode_family(insn.kind) {
        Some(NativeOpcodeFamily::Compute) => {
            emit_native_compute(&mut file, pc, program, insn, trace_style)
        }
        Some(NativeOpcodeFamily::ControlFlow) => {
            emit_native_control_flow(&mut file, pc, program, insn, trace_style)
        }
        Some(NativeOpcodeFamily::Memory) => {
            emit_native_memory(&mut file, pc, program, insn, trace_style)
        }
        None => emit_call_one(&mut file, pc),
    }
}

fn supports_native_compute(kind: InsnKind) -> bool {
    let base_supported = matches!(
        kind,
        InsnKind::ADD
            | InsnKind::SUB
            | InsnKind::XOR
            | InsnKind::OR
            | InsnKind::AND
            | InsnKind::SLL
            | InsnKind::SRL
            | InsnKind::SRA
            | InsnKind::SLT
            | InsnKind::SLTU
            | InsnKind::MUL
            | InsnKind::MULH
            | InsnKind::MULHSU
            | InsnKind::MULHU
            | InsnKind::DIV
            | InsnKind::DIVU
            | InsnKind::REM
            | InsnKind::REMU
            | InsnKind::ADDI
            | InsnKind::XORI
            | InsnKind::ORI
            | InsnKind::ANDI
            | InsnKind::SLLI
            | InsnKind::SRLI
            | InsnKind::SRAI
            | InsnKind::SLTI
            | InsnKind::SLTIU
    );
    #[cfg(feature = "u16limb_circuit")]
    let feature_supported = matches!(kind, InsnKind::LUI | InsnKind::AUIPC);
    #[cfg(not(feature = "u16limb_circuit"))]
    let feature_supported = false;
    base_supported || feature_supported
}

fn supports_native_control_flow(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::BEQ
            | InsnKind::BNE
            | InsnKind::BLT
            | InsnKind::BGE
            | InsnKind::BLTU
            | InsnKind::BGEU
            | InsnKind::JAL
            | InsnKind::JALR
    )
}

fn supports_native_memory(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::LB
            | InsnKind::LH
            | InsnKind::LW
            | InsnKind::LBU
            | InsnKind::LHU
            | InsnKind::SB
            | InsnKind::SH
            | InsnKind::SW
    )
}

fn native_compute_reads_rs2(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::ADD
            | InsnKind::SUB
            | InsnKind::XOR
            | InsnKind::OR
            | InsnKind::AND
            | InsnKind::SLL
            | InsnKind::SRL
            | InsnKind::SRA
            | InsnKind::SLT
            | InsnKind::SLTU
            | InsnKind::MUL
            | InsnKind::MULH
            | InsnKind::MULHSU
            | InsnKind::MULHU
            | InsnKind::DIV
            | InsnKind::DIVU
            | InsnKind::REM
            | InsnKind::REMU
    )
}

fn native_step_reads_rs1(kind: InsnKind) -> bool {
    supports_native_compute(kind)
        || matches!(
            kind,
            InsnKind::BEQ
                | InsnKind::BNE
                | InsnKind::BLT
                | InsnKind::BGE
                | InsnKind::BLTU
                | InsnKind::BGEU
                | InsnKind::JALR
                | InsnKind::LB
                | InsnKind::LH
                | InsnKind::LW
                | InsnKind::LBU
                | InsnKind::LHU
                | InsnKind::SB
                | InsnKind::SH
                | InsnKind::SW
        )
}

fn native_step_reads_rs2(kind: InsnKind) -> bool {
    native_compute_reads_rs2(kind)
        || matches!(
            kind,
            InsnKind::BEQ
                | InsnKind::BNE
                | InsnKind::BLT
                | InsnKind::BGE
                | InsnKind::BLTU
                | InsnKind::BGEU
                | InsnKind::SB
                | InsnKind::SH
                | InsnKind::SW
        )
}

fn native_step_writes_rd(kind: InsnKind) -> bool {
    let base_writes_rd = matches!(
        kind,
        InsnKind::ADD
            | InsnKind::SUB
            | InsnKind::XOR
            | InsnKind::OR
            | InsnKind::AND
            | InsnKind::SLL
            | InsnKind::SRL
            | InsnKind::SRA
            | InsnKind::SLT
            | InsnKind::SLTU
            | InsnKind::MUL
            | InsnKind::MULH
            | InsnKind::MULHSU
            | InsnKind::MULHU
            | InsnKind::DIV
            | InsnKind::DIVU
            | InsnKind::REM
            | InsnKind::REMU
            | InsnKind::ADDI
            | InsnKind::XORI
            | InsnKind::ORI
            | InsnKind::ANDI
            | InsnKind::SLLI
            | InsnKind::SRLI
            | InsnKind::SRAI
            | InsnKind::SLTI
            | InsnKind::SLTIU
            | InsnKind::JAL
            | InsnKind::JALR
            | InsnKind::LB
            | InsnKind::LH
            | InsnKind::LW
            | InsnKind::LBU
            | InsnKind::LHU
    );
    #[cfg(feature = "u16limb_circuit")]
    let feature_writes_rd = matches!(kind, InsnKind::LUI | InsnKind::AUIPC);
    #[cfg(not(feature = "u16limb_circuit"))]
    let feature_writes_rd = false;
    base_writes_rd || feature_writes_rd
}

fn native_step_loads_memory(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::LB | InsnKind::LH | InsnKind::LW | InsnKind::LBU | InsnKind::LHU
    )
}

fn native_step_stores_memory(kind: InsnKind) -> bool {
    matches!(kind, InsnKind::SB | InsnKind::SH | InsnKind::SW)
}

fn native_trace_flags(insn: Instruction) -> u32 {
    let mut flags = 0;
    if native_step_reads_rs1(insn.kind) {
        flags |= NATIVE_TRACE_READ_RS1;
    }
    if native_step_reads_rs2(insn.kind) {
        flags |= NATIVE_TRACE_READ_RS2;
    }
    if native_step_writes_rd(insn.kind) {
        flags |= NATIVE_TRACE_WRITE_RD;
    }
    if native_step_loads_memory(insn.kind) {
        flags |= NATIVE_TRACE_LOAD_MEM;
    }
    if native_step_stores_memory(insn.kind) {
        flags |= NATIVE_TRACE_STORE_MEM;
    }
    flags
}

fn emit_native_trace_metadata(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
) -> Result<()> {
    writeln!(
        file,
        "    movl ${:#010x}, {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12)",
        native_trace_flags(insn)
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12)",
        insn.rs1
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12)",
        insn.rs2
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12)",
        insn.rd_internal()
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_KIND_OFFSET}(%r12)",
        insn.kind as u8
    )?;
    let insn_idx = (pc.wrapping_sub(program.base_address) / PC_STEP_SIZE as u32) as usize;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_STEP_CELLS_TABLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    testq %rax, %rax")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    movq {}(%rax), %rax", insn_idx * 8)?;
    writeln!(
        file,
        "    movq %rax, {AOT_CTX_PREFLIGHT_STEP_CELLS_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jmp 2f")?;
    writeln!(file, "1:")?;
    writeln!(
        file,
        "    movq $0, {AOT_CTX_PREFLIGHT_STEP_CELLS_OFFSET}(%r12)"
    )?;
    writeln!(file, "2:")?;
    Ok(())
}

fn native_trace_kind(kind: u32) -> InsnKind {
    match kind as u8 {
        x if x == InsnKind::ADD as u8 => InsnKind::ADD,
        x if x == InsnKind::SUB as u8 => InsnKind::SUB,
        x if x == InsnKind::XOR as u8 => InsnKind::XOR,
        x if x == InsnKind::OR as u8 => InsnKind::OR,
        x if x == InsnKind::AND as u8 => InsnKind::AND,
        x if x == InsnKind::SLL as u8 => InsnKind::SLL,
        x if x == InsnKind::SRL as u8 => InsnKind::SRL,
        x if x == InsnKind::SRA as u8 => InsnKind::SRA,
        x if x == InsnKind::SLT as u8 => InsnKind::SLT,
        x if x == InsnKind::SLTU as u8 => InsnKind::SLTU,
        x if x == InsnKind::ADDI as u8 => InsnKind::ADDI,
        x if x == InsnKind::XORI as u8 => InsnKind::XORI,
        x if x == InsnKind::ORI as u8 => InsnKind::ORI,
        x if x == InsnKind::ANDI as u8 => InsnKind::ANDI,
        x if x == InsnKind::SLLI as u8 => InsnKind::SLLI,
        x if x == InsnKind::SRLI as u8 => InsnKind::SRLI,
        x if x == InsnKind::SRAI as u8 => InsnKind::SRAI,
        x if x == InsnKind::SLTI as u8 => InsnKind::SLTI,
        x if x == InsnKind::SLTIU as u8 => InsnKind::SLTIU,
        x if x == InsnKind::BEQ as u8 => InsnKind::BEQ,
        x if x == InsnKind::BNE as u8 => InsnKind::BNE,
        x if x == InsnKind::BLT as u8 => InsnKind::BLT,
        x if x == InsnKind::BGE as u8 => InsnKind::BGE,
        x if x == InsnKind::BLTU as u8 => InsnKind::BLTU,
        x if x == InsnKind::BGEU as u8 => InsnKind::BGEU,
        x if x == InsnKind::JAL as u8 => InsnKind::JAL,
        x if x == InsnKind::JALR as u8 => InsnKind::JALR,
        x if x == InsnKind::MUL as u8 => InsnKind::MUL,
        x if x == InsnKind::MULH as u8 => InsnKind::MULH,
        x if x == InsnKind::MULHSU as u8 => InsnKind::MULHSU,
        x if x == InsnKind::MULHU as u8 => InsnKind::MULHU,
        x if x == InsnKind::DIV as u8 => InsnKind::DIV,
        x if x == InsnKind::DIVU as u8 => InsnKind::DIVU,
        x if x == InsnKind::REM as u8 => InsnKind::REM,
        x if x == InsnKind::REMU as u8 => InsnKind::REMU,
        x if x == InsnKind::LB as u8 => InsnKind::LB,
        x if x == InsnKind::LH as u8 => InsnKind::LH,
        x if x == InsnKind::LW as u8 => InsnKind::LW,
        x if x == InsnKind::LBU as u8 => InsnKind::LBU,
        x if x == InsnKind::LHU as u8 => InsnKind::LHU,
        #[cfg(feature = "u16limb_circuit")]
        x if x == InsnKind::LUI as u8 => InsnKind::LUI,
        #[cfg(feature = "u16limb_circuit")]
        x if x == InsnKind::AUIPC as u8 => InsnKind::AUIPC,
        x if x == InsnKind::SB as u8 => InsnKind::SB,
        x if x == InsnKind::SH as u8 => InsnKind::SH,
        x if x == InsnKind::SW as u8 => InsnKind::SW,
        _ => InsnKind::INVALID,
    }
}

fn emit_native_compute(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    let rd = insn.rd_internal();
    writeln!(file, "    movq {AOT_CTX_REGISTERS_OFFSET}(%r12), %r10")?;
    writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
        )?;
    }
    if native_compute_reads_rs2(insn.kind) {
        writeln!(file, "    movl {}(%r10), %ecx", insn.rs2 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %ecx, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)"
            )?;
        }
    } else if trace_style.needs_callback_values() {
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)")?;
    }
    if trace_style.needs_callback_values() {
        writeln!(file, "    movl {}(%r10), %edx", rd as usize * 4)?;
        writeln!(
            file,
            "    movl %edx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
        )?;
    }
    match insn.kind {
        InsnKind::ADD => writeln!(file, "    addl %ecx, %eax")?,
        InsnKind::SUB => writeln!(file, "    subl %ecx, %eax")?,
        InsnKind::XOR => writeln!(file, "    xorl %ecx, %eax")?,
        InsnKind::OR => writeln!(file, "    orl %ecx, %eax")?,
        InsnKind::AND => writeln!(file, "    andl %ecx, %eax")?,
        InsnKind::SLL => writeln!(file, "    shll %cl, %eax")?,
        InsnKind::SRL => writeln!(file, "    shrl %cl, %eax")?,
        InsnKind::SRA => writeln!(file, "    sarl %cl, %eax")?,
        InsnKind::SLT => {
            writeln!(file, "    cmpl %ecx, %eax")?;
            writeln!(file, "    setl %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        InsnKind::SLTU => {
            writeln!(file, "    cmpl %ecx, %eax")?;
            writeln!(file, "    setb %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        InsnKind::MUL => writeln!(file, "    imull %ecx, %eax")?,
        InsnKind::MULH => {
            writeln!(file, "    imull %ecx")?;
            writeln!(file, "    movl %edx, %eax")?;
        }
        InsnKind::MULHSU => {
            writeln!(file, "    movslq %eax, %rax")?;
            writeln!(file, "    movl %ecx, %ecx")?;
            writeln!(file, "    imulq %rcx, %rax")?;
            writeln!(file, "    sarq $32, %rax")?;
        }
        InsnKind::MULHU => {
            writeln!(file, "    mull %ecx")?;
            writeln!(file, "    movl %edx, %eax")?;
        }
        InsnKind::DIV => emit_native_signed_div(&mut file, pc, SignedDivOp::Quotient)?,
        InsnKind::REM => emit_native_signed_div(&mut file, pc, SignedDivOp::Remainder)?,
        InsnKind::DIVU => emit_native_unsigned_div(&mut file, pc, UnsignedDivOp::Quotient)?,
        InsnKind::REMU => emit_native_unsigned_div(&mut file, pc, UnsignedDivOp::Remainder)?,
        InsnKind::ADDI => writeln!(file, "    addl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::XORI => writeln!(file, "    xorl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::ORI => writeln!(file, "    orl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::ANDI => writeln!(file, "    andl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::SLLI => writeln!(file, "    shll ${}, %eax", insn.imm as u32 & 0x1f)?,
        InsnKind::SRLI => writeln!(file, "    shrl ${}, %eax", insn.imm as u32 & 0x1f)?,
        InsnKind::SRAI => writeln!(file, "    sarl ${}, %eax", insn.imm as u32 & 0x1f)?,
        InsnKind::SLTI => {
            writeln!(file, "    cmpl ${:#010x}, %eax", insn.imm as u32)?;
            writeln!(file, "    setl %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        InsnKind::SLTIU => {
            writeln!(file, "    cmpl ${:#010x}, %eax", insn.imm as u32)?;
            writeln!(file, "    setb %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        #[cfg(feature = "u16limb_circuit")]
        InsnKind::LUI => writeln!(file, "    movl ${:#010x}, %eax", insn.imm as u32)?,
        #[cfg(feature = "u16limb_circuit")]
        InsnKind::AUIPC => writeln!(
            file,
            "    movl ${:#010x}, %eax",
            pc.wrapping_add(insn.imm as u32)
        )?,
        _ => unreachable!("unsupported native compute instruction: {:?}", insn.kind),
    }
    writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
    if trace_style.needs_callback_values() {
        writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
    }
    writeln!(
        file,
        "    movl ${:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)",
        pc.wrapping_add(PC_STEP_SIZE as u32)
    )?;
    emit_after_native_step(&mut file, pc, program, insn, trace_style, false)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum SignedDivOp {
    Quotient,
    Remainder,
}

fn emit_native_signed_div(mut file: impl Write, pc: u32, op: SignedDivOp) -> Result<()> {
    let zero_label = format!(".L_signed_div_zero_{pc:x}");
    let overflow_label = format!(".L_signed_div_overflow_{pc:x}");
    let done_label = format!(".L_signed_div_done_{pc:x}");

    writeln!(file, "    testl %ecx, %ecx")?;
    writeln!(file, "    je {zero_label}")?;
    writeln!(file, "    cmpl $0xffffffff, %ecx")?;
    writeln!(file, "    jne 1f")?;
    writeln!(file, "    cmpl $0x80000000, %eax")?;
    writeln!(file, "    je {overflow_label}")?;
    writeln!(file, "1:")?;
    writeln!(file, "    cltd")?;
    writeln!(file, "    idivl %ecx")?;
    if matches!(op, SignedDivOp::Remainder) {
        writeln!(file, "    movl %edx, %eax")?;
    }
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{zero_label}:")?;
    if matches!(op, SignedDivOp::Quotient) {
        writeln!(file, "    movl $0xffffffff, %eax")?;
    }
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{overflow_label}:")?;
    match op {
        SignedDivOp::Quotient => writeln!(file, "    movl $0x80000000, %eax")?,
        SignedDivOp::Remainder => writeln!(file, "    xorl %eax, %eax")?,
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum UnsignedDivOp {
    Quotient,
    Remainder,
}

fn emit_native_unsigned_div(mut file: impl Write, pc: u32, op: UnsignedDivOp) -> Result<()> {
    let zero_label = format!(".L_unsigned_div_zero_{pc:x}");
    let done_label = format!(".L_unsigned_div_done_{pc:x}");

    writeln!(file, "    testl %ecx, %ecx")?;
    writeln!(file, "    je {zero_label}")?;
    writeln!(file, "    xorl %edx, %edx")?;
    writeln!(file, "    divl %ecx")?;
    if matches!(op, UnsignedDivOp::Remainder) {
        writeln!(file, "    movl %edx, %eax")?;
    }
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{zero_label}:")?;
    if matches!(op, UnsignedDivOp::Quotient) {
        writeln!(file, "    movl $0xffffffff, %eax")?;
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_native_control_flow(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    writeln!(file, "    movq {AOT_CTX_REGISTERS_OFFSET}(%r12), %r10")?;
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
    }

    if insn.kind == InsnKind::JAL {
        let rd = insn.rd_internal();
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl {}(%r10), %edx", rd as usize * 4)?;
            writeln!(
                file,
                "    movl %edx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
            )?;
        }
        writeln!(
            file,
            "    movl ${:#010x}, %eax",
            pc.wrapping_add(PC_STEP_SIZE as u32)
        )?;
        writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
        }
        writeln!(
            file,
            "    movl ${:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)",
            branch_target(pc, insn)?
        )?;
    } else if insn.kind == InsnKind::JALR {
        let slow_label = format!(".L_jalr_slow_{pc:x}");
        let done_label = format!(".L_jalr_done_{pc:x}");
        let rd = insn.rd_internal();
        writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
            )?;
        }
        writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
        writeln!(file, "    andl $0xfffffffe, %edx")?;
        writeln!(file, "    testl $3, %edx")?;
        writeln!(file, "    jne {slow_label}")?;
        writeln!(file, "    movl %edx, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)")?;
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl {}(%r10), %edx", rd as usize * 4)?;
            writeln!(
                file,
                "    movl %edx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
            )?;
        }
        writeln!(
            file,
            "    movl ${:#010x}, %eax",
            pc.wrapping_add(PC_STEP_SIZE as u32)
        )?;
        writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
        }
        emit_after_native_step(&mut file, pc, program, insn, trace_style, false)?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{slow_label}:")?;
        emit_call_one(&mut file, pc)?;
        writeln!(file, "{done_label}:")?;
        return Ok(());
    } else {
        let target_pc = branch_target(pc, insn)?;
        let fallthrough_pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        let taken_label = format!(".L_branch_taken_{pc:x}");
        let done_label = format!(".L_branch_done_{pc:x}");
        writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
            )?;
        }
        writeln!(file, "    movl {}(%r10), %ecx", insn.rs2 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %ecx, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)"
            )?;
        }
        writeln!(file, "    cmpl %ecx, %eax")?;
        match insn.kind {
            InsnKind::BEQ => writeln!(file, "    je {taken_label}")?,
            InsnKind::BNE => writeln!(file, "    jne {taken_label}")?,
            InsnKind::BLT => writeln!(file, "    jl {taken_label}")?,
            InsnKind::BGE => writeln!(file, "    jge {taken_label}")?,
            InsnKind::BLTU => writeln!(file, "    jb {taken_label}")?,
            InsnKind::BGEU => writeln!(file, "    jae {taken_label}")?,
            _ => unreachable!(
                "unsupported native control-flow instruction: {:?}",
                insn.kind
            ),
        }
        writeln!(
            file,
            "    movl ${fallthrough_pc:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
        )?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{taken_label}:")?;
        writeln!(
            file,
            "    movl ${target_pc:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
        )?;
        writeln!(file, "{done_label}:")?;
    }

    emit_after_native_step(&mut file, pc, program, insn, trace_style, false)?;
    Ok(())
}

fn emit_native_memory(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    let slow_label = format!(".L_memory_slow_{pc:x}");
    let done_label = format!(".L_memory_done_{pc:x}");
    let heap_ok_label = format!(".L_memory_heap_ok_{pc:x}");
    let stack_ok_label = format!(".L_memory_stack_ok_{pc:x}");
    let hints_ok_label = format!(".L_memory_hints_ok_{pc:x}");
    let body_label = format!(".L_memory_body_{pc:x}");
    let rd = insn.rd_internal();

    writeln!(file, "    movq {AOT_CTX_REGISTERS_OFFSET}(%r12), %r10")?;
    writeln!(file, "    movq {AOT_CTX_MEMORY_CELLS_OFFSET}(%r12), %r11")?;
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
    }
    writeln!(
        file,
        "    movl ${:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)",
        pc.wrapping_add(PC_STEP_SIZE as u32)
    )?;
    if trace_style.needs_callback_values() {
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
    }
    writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
        )?;
    }
    writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
    match insn.kind {
        InsnKind::LH | InsnKind::LHU | InsnKind::SH => {
            writeln!(file, "    testl $1, %edx")?;
            writeln!(file, "    jne {slow_label}")?;
        }
        InsnKind::LW | InsnKind::SW => {
            writeln!(file, "    testl $3, %edx")?;
            writeln!(file, "    jne {slow_label}")?;
        }
        _ => {}
    }
    emit_native_range_check(
        &mut file,
        AOT_CTX_HEAP_START_OFFSET,
        AOT_CTX_HEAP_END_OFFSET,
        &heap_ok_label,
    )?;
    emit_native_range_check(
        &mut file,
        AOT_CTX_STACK_START_OFFSET,
        AOT_CTX_STACK_END_OFFSET,
        &stack_ok_label,
    )?;
    emit_native_range_check(
        &mut file,
        AOT_CTX_HINTS_START_OFFSET,
        AOT_CTX_HINTS_END_OFFSET,
        &hints_ok_label,
    )?;
    writeln!(file, "    jmp {slow_label}")?;

    emit_native_memory_region_entry(
        &mut file,
        &heap_ok_label,
        &body_label,
        trace_style,
        AOT_CTX_PREFLIGHT_HEAP_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET,
    )?;
    emit_native_memory_region_entry(
        &mut file,
        &stack_ok_label,
        &body_label,
        trace_style,
        AOT_CTX_PREFLIGHT_STACK_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_STACK_MAX_OFFSET,
    )?;
    emit_native_memory_region_entry(
        &mut file,
        &hints_ok_label,
        &body_label,
        trace_style,
        AOT_CTX_PREFLIGHT_HINTS_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET,
    )?;

    writeln!(file, "{body_label}:")?;
    writeln!(
        file,
        "    subl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %edx"
    )?;
    writeln!(file, "    movl %edx, %esi")?;
    match insn.kind {
        InsnKind::LB | InsnKind::LH | InsnKind::LW | InsnKind::LBU | InsnKind::LHU => {
            writeln!(file, "    movl (%r11,%rsi,4), %eax")?;
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12)"
                )?;
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12)"
                )?;
                writeln!(file, "    movl {}(%r10), %ecx", rd as usize * 4)?;
                writeln!(
                    file,
                    "    movl %ecx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
                )?;
            }
            if insn.kind != InsnKind::LW {
                writeln!(file, "    movl %r8d, %ecx")?;
                writeln!(file, "    shrl %cl, %eax")?;
            }
            match insn.kind {
                InsnKind::LB => writeln!(file, "    movsbl %al, %eax")?,
                InsnKind::LH => writeln!(file, "    movswl %ax, %eax")?,
                InsnKind::LW => {}
                InsnKind::LBU => writeln!(file, "    movzbl %al, %eax")?,
                InsnKind::LHU => writeln!(file, "    movzwl %ax, %eax")?,
                _ => unreachable!("unsupported native load instruction: {:?}", insn.kind),
            }
            writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
            if trace_style.needs_callback_values() {
                writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
            }
        }
        InsnKind::SB | InsnKind::SH | InsnKind::SW => {
            writeln!(file, "    movl {}(%r10), %r9d", insn.rs2 as usize * 4)?;
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %r9d, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)"
                )?;
            }
            writeln!(file, "    movl (%r11,%rsi,4), %eax")?;
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12)"
                )?;
            }
            match insn.kind {
                InsnKind::SB => {
                    writeln!(file, "    andl $0xff, %r9d")?;
                    writeln!(file, "    movl %r8d, %ecx")?;
                    writeln!(file, "    shll %cl, %r9d")?;
                    writeln!(file, "    movl $0xff, %edx")?;
                    writeln!(file, "    shll %cl, %edx")?;
                    writeln!(file, "    notl %edx")?;
                    writeln!(file, "    andl %edx, %eax")?;
                    writeln!(file, "    orl %r9d, %eax")?;
                }
                InsnKind::SH => {
                    writeln!(file, "    andl $0xffff, %r9d")?;
                    writeln!(file, "    movl %r8d, %ecx")?;
                    writeln!(file, "    shll %cl, %r9d")?;
                    writeln!(file, "    movl $0xffff, %edx")?;
                    writeln!(file, "    shll %cl, %edx")?;
                    writeln!(file, "    notl %edx")?;
                    writeln!(file, "    andl %edx, %eax")?;
                    writeln!(file, "    orl %r9d, %eax")?;
                }
                InsnKind::SW => {
                    writeln!(file, "    movl %r9d, %eax")?;
                }
                _ => unreachable!("unsupported native store instruction: {:?}", insn.kind),
            }
            writeln!(file, "    movl %eax, (%r11,%rsi,4)")?;
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12)"
                )?;
            }
        }
        _ => unreachable!("unsupported native memory instruction: {:?}", insn.kind),
    }
    emit_after_native_step(
        &mut file,
        pc,
        program,
        insn,
        trace_style,
        trace_style.is_preflight_direct(),
    )?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{slow_label}:")?;
    emit_call_one(&mut file, pc)?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_native_memory_region_entry(
    mut file: impl Write,
    label: &str,
    body_label: &str,
    trace_style: AssemblyTraceStyle,
    min_ptr_offset: usize,
    max_ptr_offset: usize,
) -> Result<()> {
    writeln!(file, "{label}:")?;
    writeln!(file, "    movl %edx, %r8d")?;
    writeln!(file, "    andl $3, %r8d")?;
    writeln!(file, "    shll $3, %r8d")?;
    writeln!(file, "    shrl $2, %edx")?;
    writeln!(file, "    movl %edx, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
    if trace_style.is_preflight_direct() {
        emit_preflight_direct_memory_bound_known_region(
            &mut file,
            "%edx",
            min_ptr_offset,
            max_ptr_offset,
        )?;
    }
    writeln!(file, "    jmp {body_label}")?;
    Ok(())
}

fn emit_native_range_check(
    mut file: impl Write,
    start_offset: usize,
    end_offset: usize,
    ok_label: &str,
) -> Result<()> {
    writeln!(file, "    cmpl {start_offset}(%r12), %edx")?;
    writeln!(file, "    jb 1f")?;
    writeln!(file, "    cmpl {end_offset}(%r12), %edx")?;
    writeln!(file, "    jb {ok_label}")?;
    writeln!(file, "1:")?;
    Ok(())
}

fn emit_successor_jump(
    mut file: impl Write,
    program: &Program,
    labels: &BTreeMap<u32, String>,
    pc: u32,
    insn: Instruction,
) -> Result<()> {
    let mut successors = Vec::new();
    successors.extend(static_successors(program, pc, insn)?);
    for successor in successors {
        if let Some(label) = labels.get(&successor) {
            writeln!(file, "    cmpl ${successor:#010x}, %r15d")?;
            writeln!(file, "    je {label}")?;
        }
    }
    writeln!(file, "    jmp L_dispatch")?;
    Ok(())
}

unsafe extern "C" fn aot_exec_one<T: Tracer>(vm: *mut c_void, pc: u32, next_pc: *mut u32) -> u32 {
    let vm = unsafe { &mut *(vm as *mut VMState<T>) };
    if vm.halted() {
        unsafe {
            *next_pc = vm.get_pc().0;
        }
        return AOT_STATUS_HALTED;
    }

    let pc = ByteAddr(pc);
    vm.set_pc(pc);
    let result = (|| -> Result<()> {
        let Some(insn) = vm.fetch(pc.waddr()) else {
            vm.trap(TrapCause::InstructionAccessFault)?;
            bail!(
                "Fatal: could not fetch instruction at pc={pc:?}, ELF does not have instructions there."
            );
        };
        crate::rv32im::step_fetched(vm, &insn)?;
        let step = vm.tracer_mut().advance();
        if vm.tracer().is_busy_loop(&step) && !vm.halted() {
            bail!("Stuck in loop {}", "{}");
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            unsafe {
                *next_pc = vm.get_pc().0;
            }
            if vm.halted() {
                AOT_STATUS_HALTED
            } else {
                AOT_STATUS_CONTINUE
            }
        }
        Err(err) => {
            unsafe {
                *next_pc = vm.get_pc().0;
            }
            LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
            AOT_STATUS_ERROR
        }
    }
}

unsafe extern "C" fn aot_trace_native_compute<T: Tracer>(context: *mut AotRuntimeContext) -> u32 {
    let context = unsafe { &mut *context };
    let vm = unsafe { &mut *(context.vm as *mut VMState<T>) };
    if vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        return AOT_STATUS_HALTED;
    }

    let pc = ByteAddr(context.trace_pc);
    vm.set_pc(pc);
    let result = (|| -> Result<()> {
        let idx = pc.0.wrapping_sub(context.program_base) / PC_STEP_SIZE as u32;
        let insn = unsafe { *context.instructions.add(idx as usize) };
        vm.trace_fetch_known(pc.waddr(), insn);
        if !supports_native_compute(insn.kind)
            && !supports_native_control_flow(insn.kind)
            && !supports_native_memory(insn.kind)
        {
            bail!(
                "AOT native trace helper received unsupported instruction {:?} at pc={:#010x}",
                insn.kind,
                pc.0
            );
        }

        if native_step_reads_rs1(insn.kind) {
            vm.tracer_mut()
                .load_register(insn.rs1, context.trace_rs1_value);
        }
        if native_step_reads_rs2(insn.kind) {
            vm.tracer_mut()
                .load_register(insn.rs2, context.trace_rs2_value);
        }
        if native_step_writes_rd(insn.kind) {
            vm.tracer_mut().store_register(
                insn.rd_internal() as _,
                Change {
                    before: context.trace_rd_before,
                    after: context.trace_rd_after,
                },
            );
        }
        if native_step_loads_memory(insn.kind) {
            vm.tracer_mut()
                .load_memory(WordAddr(context.trace_mem_addr), context.trace_mem_after);
        }
        if native_step_stores_memory(insn.kind) {
            vm.tracer_mut().store_memory(
                WordAddr(context.trace_mem_addr),
                Change {
                    before: context.trace_mem_before,
                    after: context.trace_mem_after,
                },
            );
        }
        vm.set_pc(ByteAddr(context.trace_next_pc));
        vm.on_normal_end(&insn);
        let step = vm.tracer_mut().advance();
        if context.trace_next_pc == context.trace_pc
            && vm.tracer().is_busy_loop(&step)
            && !vm.halted()
        {
            bail!("Stuck in loop {}", "{}");
        }
        Ok(())
    })();

    match result {
        Ok(()) => AOT_STATUS_CONTINUE,
        Err(err) => {
            context.trace_next_pc = vm.get_pc().0;
            LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
            AOT_STATUS_ERROR
        }
    }
}

unsafe extern "C" fn aot_trace_native_preflight(context: *mut AotRuntimeContext) -> u32 {
    let context = unsafe { &mut *context };
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    if vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        return AOT_STATUS_HALTED;
    }

    let pc = ByteAddr(context.trace_pc);
    let kind = native_trace_kind(context.trace_kind);
    let busy_loop = vm.trace_preflight_native_step(
        pc,
        kind,
        context.trace_flags,
        context.trace_rs1_idx as RegIdx,
        context.trace_rs2_idx as RegIdx,
        context.trace_rd_idx as RegIdx,
        WordAddr(context.trace_mem_addr),
        ByteAddr(context.trace_next_pc),
    );
    if busy_loop && !vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!("Stuck in loop {}", "{}")));
        AOT_STATUS_ERROR
    } else {
        AOT_STATUS_CONTINUE
    }
}

unsafe extern "C" fn aot_preflight_direct_helper(context: *mut AotRuntimeContext) -> u32 {
    let context = unsafe { &mut *context };
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    if vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        return AOT_STATUS_HALTED;
    }

    match context.preflight_helper_kind {
        AOT_PREFLIGHT_HELPER_ACCESS => {
            vm.tracer_mut().record_native_access_side_effects(
                WordAddr(context.preflight_event_addr),
                context.preflight_prev_cycle,
                context.preflight_cur_cycle,
            );
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_SYNC => {
            vm.tracer_mut()
                .observe_native_steps(context.preflight_pending_steps);
            context.preflight_pending_steps = 0;
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_BUSY_LOOP => {
            vm.tracer_mut()
                .observe_native_steps(context.preflight_pending_steps);
            context.preflight_pending_steps = 0;
            context.trace_next_pc = vm.get_pc().0;
            LAST_AOT_ERROR
                .with(|slot| *slot.borrow_mut() = Some(anyhow!("Stuck in loop {}", "{}")));
            AOT_STATUS_ERROR
        }
        AOT_PREFLIGHT_HELPER_CALLBACK => {
            vm.tracer_mut()
                .observe_native_steps(context.preflight_pending_steps);
            context.preflight_pending_steps = 0;
            unsafe { aot_trace_native_preflight(context as *mut AotRuntimeContext) }
        }
        AOT_PREFLIGHT_HELPER_SHARD_SPLIT => {
            vm.tracer_mut().record_native_shard_split();
            AOT_STATUS_CONTINUE
        }
        other => {
            LAST_AOT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(anyhow!("unknown AOT Preflight helper kind {other}"))
            });
            AOT_STATUS_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CENO_PLATFORM, EmuContext, encode_rv32};
    use std::sync::Arc;

    fn program(instructions: Vec<Instruction>) -> Program {
        Program::new(
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.heap.start,
            instructions,
            Default::default(),
        )
    }

    #[test]
    fn partitions_direct_branch_and_fallthrough() {
        let base = CENO_PLATFORM.pc_base();
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);

        let blocks = partition_basic_blocks(&program).unwrap();
        assert_eq!(
            blocks,
            vec![
                BasicBlock {
                    start_pc: base,
                    end_pc: base + 8,
                },
                BasicBlock {
                    start_pc: base + 8,
                    end_pc: base + 12,
                },
                BasicBlock {
                    start_pc: base + 12,
                    end_pc: base + 16,
                },
            ]
        );
    }

    #[test]
    fn partitions_only_static_reachable_blocks() {
        let base = CENO_PLATFORM.pc_base();
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
            encode_rv32(InsnKind::JAL, 0, 0, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 3, 3),
        ]);

        let blocks = partition_basic_blocks(&program).unwrap();
        assert_eq!(
            blocks,
            vec![BasicBlock {
                start_pc: base,
                end_pc: base + 8,
            }]
        );
    }

    #[test]
    fn aot_runtime_context_offsets_match_assembly_constants() {
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, trace_mode),
            AOT_CTX_TRACE_MODE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_latest_cells),
            AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_cycle),
            AOT_CTX_PREFLIGHT_CYCLE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_current_shard_start),
            AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_steps),
            AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_step_cells_table),
            AOT_CTX_PREFLIGHT_STEP_CELLS_TABLE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_heap_start_word),
            AOT_CTX_PREFLIGHT_HEAP_START_WORD_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_hints_max),
            AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_steps),
            AOT_CTX_FALLBACK_STEPS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_block_cells_table),
            AOT_CTX_PREFLIGHT_BLOCK_CELLS_TABLE_OFFSET
        );
    }

    #[test]
    fn invalid_instruction_errors_if_executed() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::INVALID, 0, 0, 0, 0)]));
        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut vm = VMState::new(CENO_PLATFORM.clone(), program);
        let err = aot.run_to_halt(&mut vm, 1).unwrap_err().to_string();
        assert!(err.contains("IllegalInstruction"));
    }

    #[test]
    fn native_opcode_family_keeps_unsupported_ops_on_slow_path() {
        assert_eq!(
            native_opcode_family(InsnKind::ADD),
            Some(NativeOpcodeFamily::Compute)
        );
        assert_eq!(
            native_opcode_family(InsnKind::BEQ),
            Some(NativeOpcodeFamily::ControlFlow)
        );
        assert_eq!(
            native_opcode_family(InsnKind::LW),
            Some(NativeOpcodeFamily::Memory)
        );
        assert_eq!(
            native_opcode_family(InsnKind::DIV),
            Some(NativeOpcodeFamily::Compute)
        );
        assert_eq!(
            native_opcode_family(InsnKind::JALR),
            Some(NativeOpcodeFamily::ControlFlow)
        );
        assert_eq!(native_opcode_family(InsnKind::ECALL), None);
    }

    #[test]
    fn aot_trace_matches_interpreter_for_supported_loop() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
        assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_preflight_direct_trace_matches_interpreter_accesses() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
            encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer(
            CENO_PLATFORM.clone(),
            program.clone(),
        );
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm =
            VMState::<crate::PreflightTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
        assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
        assert_eq!(
            aot_vm.tracer().final_accesses().len(),
            interp.tracer().final_accesses().len()
        );
        for addr in interp.tracer().final_accesses().addresses() {
            assert_eq!(
                aot_vm.tracer().final_accesses().cycle(*addr),
                interp.tracer().final_accesses().cycle(*addr),
                "final access mismatch at {addr:?}"
            );
        }

        let interp_next = interp.take_tracer().into_next_accesses();
        let aot_next = aot_vm.take_tracer().into_next_accesses();
        assert_eq!(aot_next, interp_next);
    }

    #[derive(Debug)]
    struct OneCellPerNativeStep;

    impl crate::StepCellExtractor for OneCellPerNativeStep {
        fn cells_for_kind(&self, kind: InsnKind, _rs1_value: Option<crate::addr::Word>) -> u64 {
            if native_opcode_family(kind).is_some() {
                1
            } else {
                0
            }
        }
    }

    #[test]
    fn aot_preflight_block_plan_matches_without_shard_cuts() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
            encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));

        let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        while interp.next_step_record().unwrap().is_some() {}

        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        assert_eq!(
            aot.trace_style,
            AssemblyTraceStyle::PreflightDirectBlockPlan
        );
        let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
        assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
        assert_eq!(
            aot_vm.tracer().final_accesses().len(),
            interp.tracer().final_accesses().len()
        );
        for addr in interp.tracer().final_accesses().addresses() {
            assert_eq!(
                aot_vm.tracer().final_accesses().cycle(*addr),
                interp.tracer().final_accesses().cycle(*addr),
                "final access mismatch at {addr:?}"
            );
        }

        let (interp_plan, interp_next) = interp.take_tracer().into_shard_plan();
        let (aot_plan, aot_next) = aot_vm.take_tracer().into_shard_plan();
        assert_eq!(aot_next, interp_next);
        assert_eq!(
            aot_plan.shard_cycle_boundaries(),
            interp_plan.shard_cycle_boundaries()
        );
        assert_eq!(aot_plan.max_step_shard(), interp_plan.max_step_shard());
    }

    #[test]
    fn preflight_block_plan_only_accepts_static_register_blocks() {
        let compute = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        ]);
        let block = BasicBlock {
            start_pc: compute.base_address,
            end_pc: compute.base_address + 8,
        };
        assert!(block_supports_preflight_block_plan(&compute, &block).unwrap());

        let memory = program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 0)]);
        let block = BasicBlock {
            start_pc: memory.base_address,
            end_pc: memory.base_address + 4,
        };
        assert_eq!(
            preflight_block_plan_kind(&memory, &block).unwrap(),
            Some(PreflightBlockPlanKind::MemoryExactAccess)
        );

        let dynamic_memory_base = program(vec![
            encode_rv32(InsnKind::ADDI, 20, 0, 20, 4),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        ]);
        let block = BasicBlock {
            start_pc: dynamic_memory_base.base_address,
            end_pc: dynamic_memory_base.base_address + 8,
        };
        assert_eq!(
            preflight_block_plan_kind(&dynamic_memory_base, &block).unwrap(),
            None
        );

        let jalr = program(vec![encode_rv32(InsnKind::JALR, 1, 0, 0, 0)]);
        let block = BasicBlock {
            start_pc: jalr.base_address,
            end_pc: jalr.base_address + 4,
        };
        assert!(!block_supports_preflight_block_plan(&jalr, &block).unwrap());

        let ecall = program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]);
        let block = BasicBlock {
            start_pc: ecall.base_address,
            end_pc: ecall.base_address + 4,
        };
        assert!(!block_supports_preflight_block_plan(&ecall, &block).unwrap());
    }

    #[test]
    fn aot_preflight_block_plan_simple_memory_keeps_exact_accesses() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 2, 1),
            encode_rv32(InsnKind::SW, 20, 2, 0, 4),
            encode_rv32(InsnKind::ADDI, 2, 0, 3, 1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));

        let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        interp.init_register_unsafe(20, base);
        interp.init_memory(ByteAddr(base).waddr(), 41);
        interp.init_memory(ByteAddr(base + 4).waddr(), 0);
        while interp.next_step_record().unwrap().is_some() {}

        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        aot_vm.init_register_unsafe(20, base);
        aot_vm.init_memory(ByteAddr(base).waddr(), 41);
        aot_vm.init_memory(ByteAddr(base + 4).waddr(), 0);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::PreflightTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(
            aot_vm.peek_memory(ByteAddr(base + 4).waddr()),
            interp.peek_memory(ByteAddr(base + 4).waddr())
        );

        let (interp_plan, interp_next) = interp.take_tracer().into_shard_plan();
        let (aot_plan, aot_next) = aot_vm.take_tracer().into_shard_plan();
        assert_eq!(aot_next, interp_next);
        assert_eq!(
            aot_plan.shard_cycle_boundaries(),
            interp_plan.shard_cycle_boundaries()
        );
        assert_eq!(aot_plan.max_step_shard(), interp_plan.max_step_shard());
    }

    #[test]
    fn aot_preflight_block_plan_memory_guard_falls_back_to_exact_path() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LW, 20, 0, 1, 1),
            encode_rv32(InsnKind::ADDI, 1, 0, 2, 1),
        ]));
        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        let mut aot_vm =
            VMState::<crate::PreflightTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        aot_vm.init_register_unsafe(20, base);

        let err = aot.run_to_halt(&mut aot_vm, 10).unwrap_err().to_string();

        assert!(err.contains("LoadAddressMisaligned"));
    }

    fn assert_preflight_aot_matches_interpreter(
        program: Arc<Program>,
        config: crate::PreflightTracerConfig,
        init: impl Fn(&mut VMState<crate::PreflightTracer>),
    ) {
        let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        init(&mut interp);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        init(&mut aot_vm);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::PreflightTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(
            aot_vm.tracer().final_accesses().len(),
            interp.tracer().final_accesses().len()
        );
        for addr in interp.tracer().final_accesses().addresses() {
            assert_eq!(
                aot_vm.tracer().final_accesses().cycle(*addr),
                interp.tracer().final_accesses().cycle(*addr),
                "final access mismatch at {addr:?}"
            );
        }

        let (interp_plan, interp_next) = interp.take_tracer().into_shard_plan();
        let (aot_plan, aot_next) = aot_vm.take_tracer().into_shard_plan();
        assert_eq!(aot_next, interp_next);
        assert_eq!(
            aot_plan.shard_cycle_boundaries(),
            interp_plan.shard_cycle_boundaries()
        );
        assert_eq!(aot_plan.max_step_shard(), interp_plan.max_step_shard());
    }

    #[test]
    fn aot_preflight_direct_matches_finite_cycle_shards() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 6),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
            encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, 12);

        assert_preflight_aot_matches_interpreter(program, config, |_| {});
    }

    #[test]
    fn aot_preflight_direct_matches_finite_cell_shards_and_store_accesses() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 11),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 2, 0),
            encode_rv32(InsnKind::ADDI, 2, 0, 3, 1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, 2, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));

        assert_preflight_aot_matches_interpreter(program, config, |vm| {
            vm.init_register_unsafe(20, base);
            vm.init_memory(ByteAddr(base).waddr(), 0);
        });
    }

    #[test]
    fn aot_native_arithmetic_matches_interpreter() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, -1),
            encode_rv32(InsnKind::ADDI, 1, 0, 2, 2),
            encode_rv32(InsnKind::XORI, 2, 0, 3, -1),
            encode_rv32(InsnKind::ORI, 3, 0, 4, 0x55),
            encode_rv32(InsnKind::ANDI, 4, 0, 6, 0x0f),
            encode_rv32(InsnKind::ADD, 1, 6, 7, 0),
            encode_rv32(InsnKind::SUB, 7, 6, 8, 0),
            encode_rv32(InsnKind::XOR, 8, 7, 9, 0),
            encode_rv32(InsnKind::OR, 9, 6, 12, 0),
            encode_rv32(InsnKind::AND, 12, 7, 13, 0),
            encode_rv32(InsnKind::ADDI, 13, 0, 0, 123),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_native_shifts_and_comparisons_match_interpreter() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 33),
            encode_rv32(InsnKind::SLL, 1, 2, 3, 0),
            encode_rv32(InsnKind::SRL, 3, 2, 4, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 6, -8),
            encode_rv32(InsnKind::SRAI, 6, 0, 7, 1),
            encode_rv32(InsnKind::SRA, 6, 2, 8, 0),
            encode_rv32(InsnKind::SLLI, 1, 0, 9, 31),
            encode_rv32(InsnKind::SRLI, 9, 0, 12, 31),
            encode_rv32(InsnKind::SLT, 6, 1, 13, 0),
            encode_rv32(InsnKind::SLTU, 6, 1, 14, 0),
            encode_rv32(InsnKind::SLTI, 6, 0, 15, -7),
            encode_rv32(InsnKind::SLTIU, 6, 0, 16, -7),
            encode_rv32(InsnKind::SLTIU, 1, 0, 17, -1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_native_branches_and_jal_match_interpreter() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, -1),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 1),
            encode_rv32(InsnKind::BEQ, 2, 2, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 3, 99),
            encode_rv32(InsnKind::BNE, 1, 2, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 4, 99),
            encode_rv32(InsnKind::BLT, 1, 2, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 6, 99),
            encode_rv32(InsnKind::BGE, 2, 1, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
            encode_rv32(InsnKind::BLTU, 1, 2, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 8, 8),
            encode_rv32(InsnKind::BGEU, 1, 2, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 9, 99),
            encode_rv32(InsnKind::JAL, 0, 0, 12, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 13, 99),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_native_multiply_matches_interpreter() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, -1),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
            encode_rv32(InsnKind::MUL, 1, 2, 3, 0),
            encode_rv32(InsnKind::MULH, 1, 2, 4, 0),
            encode_rv32(InsnKind::MULHU, 1, 2, 6, 0),
            encode_rv32(InsnKind::MULHSU, 1, 2, 7, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 8, 1),
            encode_rv32(InsnKind::SLLI, 8, 0, 8, 31),
            encode_rv32(InsnKind::MUL, 8, 1, 9, 0),
            encode_rv32(InsnKind::MULH, 8, 1, 11, 0),
            encode_rv32(InsnKind::MULHU, 8, 1, 12, 0),
            encode_rv32(InsnKind::MULHSU, 8, 1, 13, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_native_div_rem_matches_interpreter() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, -7),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 3),
            encode_rv32(InsnKind::DIV, 1, 2, 3, 0),
            encode_rv32(InsnKind::REM, 1, 2, 4, 0),
            encode_rv32(InsnKind::DIVU, 1, 2, 6, 0),
            encode_rv32(InsnKind::REMU, 1, 2, 7, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 8, 1),
            encode_rv32(InsnKind::SLLI, 8, 0, 8, 31),
            encode_rv32(InsnKind::ADDI, 0, 0, 9, -1),
            encode_rv32(InsnKind::DIV, 8, 9, 11, 0),
            encode_rv32(InsnKind::REM, 8, 9, 12, 0),
            encode_rv32(InsnKind::DIV, 1, 0, 13, 0),
            encode_rv32(InsnKind::REM, 1, 0, 14, 0),
            encode_rv32(InsnKind::DIVU, 1, 0, 15, 0),
            encode_rv32(InsnKind::REMU, 1, 0, 16, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    #[cfg(feature = "u16limb_circuit")]
    fn aot_native_lui_auipc_matches_interpreter() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LUI, 0, 0, 1, 0x1234),
            encode_rv32(InsnKind::AUIPC, 0, 0, 2, 0x40),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
        assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_native_lw_sw_match_interpreter() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, 5),
            encode_rv32(InsnKind::SW, 20, 1, 0, 4),
            encode_rv32(InsnKind::LW, 20, 0, 2, 4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        interp.init_register_unsafe(20, base);
        interp.init_memory(ByteAddr(base).waddr(), 37);
        interp.init_memory(ByteAddr(base + 4).waddr(), 0);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        aot_vm.init_register_unsafe(20, base);
        aot_vm.init_memory(ByteAddr(base).waddr(), 37);
        aot_vm.init_memory(ByteAddr(base + 4).waddr(), 0);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(aot_vm.peek_memory(ByteAddr(base + 4).waddr()), 42);
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_pure_execution_updates_state_without_native_trace_callbacks() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
            encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
            encode_rv32(InsnKind::SW, 20, 2, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        interp.init_register_unsafe(20, base);
        interp.init_memory(ByteAddr(base).waddr(), 0);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        aot_vm.init_register_unsafe(20, base);
        aot_vm.init_memory(ByteAddr(base).waddr(), 0);
        let report = aot.run_pure_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert!(aot_vm.halted());
        assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
        assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
        assert_eq!(
            aot_vm.peek_memory(ByteAddr(base).waddr()),
            interp.peek_memory(ByteAddr(base).waddr())
        );
    }

    #[test]
    #[ignore]
    fn aot_pure_perf_probe() {
        let iterations = 1_000_000u32;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, iterations as i32),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
            encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer(
            CENO_PLATFORM.clone(),
            program.clone(),
        );
        let started = Instant::now();
        while interp.next_step_record().unwrap().is_some() {}
        let interp_time = started.elapsed();

        let aot_started = Instant::now();
        let aot = AotProgram::compile(program.clone()).unwrap();
        let compile_time = aot_started.elapsed();

        let mut traced = VMState::<crate::PreflightTracer>::new_with_tracer(
            CENO_PLATFORM.clone(),
            program.clone(),
        );
        let traced = aot.run_to_halt(&mut traced, usize::MAX).unwrap();

        let mut pure =
            VMState::<crate::PreflightTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        let pure = aot.run_pure_to_halt(&mut pure, usize::MAX).unwrap();

        println!(
            "loop-heavy: steps={}, compile={:?}, interp={:?}, traced_aot={:?} ({:.3}x), pure_aot={:?} ({:.3}x)",
            traced.executed_steps,
            compile_time,
            interp_time,
            traced.execute_time,
            interp_time.as_secs_f64() / traced.execute_time.as_secs_f64(),
            pure.execute_time,
            interp_time.as_secs_f64() / pure.execute_time.as_secs_f64(),
        );
    }

    #[test]
    fn aot_native_byte_halfword_memory_matches_interpreter() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LB, 20, 0, 1, 2),
            encode_rv32(InsnKind::LBU, 20, 0, 2, 2),
            encode_rv32(InsnKind::LH, 20, 0, 3, 2),
            encode_rv32(InsnKind::LHU, 20, 0, 4, 2),
            encode_rv32(InsnKind::ADDI, 0, 0, 6, 0x55),
            encode_rv32(InsnKind::SB, 20, 6, 0, 1),
            encode_rv32(InsnKind::ADDI, 0, 0, 7, 0xabcd),
            encode_rv32(InsnKind::SH, 20, 7, 0, 4),
            encode_rv32(InsnKind::LW, 20, 0, 8, 0),
            encode_rv32(InsnKind::LW, 20, 0, 9, 4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        interp.init_register_unsafe(20, base);
        interp.init_memory(ByteAddr(base).waddr(), 0x80ff_7f00);
        interp.init_memory(ByteAddr(base + 4).waddr(), 0);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        aot_vm.init_register_unsafe(20, base);
        aot_vm.init_memory(ByteAddr(base).waddr(), 0x80ff_7f00);
        aot_vm.init_memory(ByteAddr(base + 4).waddr(), 0);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
            assert_eq!(
                aot_vm.peek_register(idx),
                interp.peek_register(idx),
                "register x{idx} mismatch"
            );
        }
        assert_eq!(aot_vm.peek_memory(ByteAddr(base).waddr()), 0x80ff_5500);
        assert_eq!(aot_vm.peek_memory(ByteAddr(base + 4).waddr()), 0xabcd);
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_memory_misalignment_uses_exact_slow_path_traps() {
        let base = CENO_PLATFORM.heap.start;
        let lw_program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
        let lw_aot = AotProgram::compile(lw_program.clone()).unwrap();
        let mut lw_vm = VMState::new(CENO_PLATFORM.clone(), lw_program);
        lw_vm.init_register_unsafe(20, base);
        let err = lw_aot.run_to_halt(&mut lw_vm, 1).unwrap_err().to_string();
        assert!(err.contains("LoadAddressMisaligned"));

        let lh_program = Arc::new(program(vec![encode_rv32(InsnKind::LH, 20, 0, 1, 1)]));
        let lh_aot = AotProgram::compile(lh_program.clone()).unwrap();
        let mut lh_vm = VMState::new(CENO_PLATFORM.clone(), lh_program);
        lh_vm.init_register_unsafe(20, base);
        let err = lh_aot.run_to_halt(&mut lh_vm, 1).unwrap_err().to_string();
        assert!(err.contains("LoadAddressMisaligned"));

        let sw_program = Arc::new(program(vec![encode_rv32(InsnKind::SW, 20, 1, 0, 1)]));
        let sw_aot = AotProgram::compile(sw_program.clone()).unwrap();
        let mut sw_vm = VMState::new(CENO_PLATFORM.clone(), sw_program);
        sw_vm.init_register_unsafe(20, base);
        sw_vm.init_register_unsafe(1, 42);
        let err = sw_aot.run_to_halt(&mut sw_vm, 1).unwrap_err().to_string();
        assert!(err.contains("StoreAddressMisaligned"));

        let sh_program = Arc::new(program(vec![encode_rv32(InsnKind::SH, 20, 1, 0, 1)]));
        let sh_aot = AotProgram::compile(sh_program.clone()).unwrap();
        let mut sh_vm = VMState::new(CENO_PLATFORM.clone(), sh_program);
        sh_vm.init_register_unsafe(20, base);
        sh_vm.init_register_unsafe(1, 42);
        let err = sh_aot.run_to_halt(&mut sh_vm, 1).unwrap_err().to_string();
        assert!(err.contains("StoreAddressMisaligned"));
    }

    #[test]
    fn aot_memory_access_faults_use_exact_slow_path_traps() {
        let lb_program = Arc::new(program(vec![encode_rv32(InsnKind::LB, 20, 0, 1, 0)]));
        let lb_aot = AotProgram::compile(lb_program.clone()).unwrap();
        let mut lb_vm = VMState::new(CENO_PLATFORM.clone(), lb_program);
        lb_vm.init_register_unsafe(20, 0);
        let err = lb_aot.run_to_halt(&mut lb_vm, 1).unwrap_err().to_string();
        assert!(err.contains("LoadAccessFault"));

        let sb_program = Arc::new(program(vec![encode_rv32(InsnKind::SB, 20, 1, 0, 0)]));
        let sb_aot = AotProgram::compile(sb_program.clone()).unwrap();
        let mut sb_vm = VMState::new(CENO_PLATFORM.clone(), sb_program);
        sb_vm.init_register_unsafe(20, 0);
        sb_vm.init_register_unsafe(1, 42);
        let err = sb_aot.run_to_halt(&mut sb_vm, 1).unwrap_err().to_string();
        assert!(err.contains("StoreAccessFault"));
    }

    #[test]
    fn aot_respects_max_steps_without_halting() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut vm = VMState::new(CENO_PLATFORM.clone(), program);

        let report = aot.run_to_halt(&mut vm, 2).unwrap();

        assert_eq!(report.executed_steps, 2);
        assert!(!vm.halted());
        assert_eq!(vm.get_pc().0, base + 8);

        let report = aot.run_to_halt(&mut vm, 10).unwrap();
        assert_eq!(report.executed_steps, 6);
        assert!(vm.halted());
    }

    #[test]
    fn aot_dynamic_dispatch_handles_jalr_into_block_middle() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 3, 1),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 7),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        interp.init_register_unsafe(1, base + 8);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        aot_vm.init_register_unsafe(1, base + 8);
        let report = aot.run_to_halt(&mut aot_vm, 10).unwrap();

        assert_eq!(report.executed_steps, 3);
        assert_eq!(aot_vm.peek_register(2), 7);
        assert_eq!(aot_vm.peek_register(3), 0);
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_jalr_misalignment_uses_exact_slow_path_trap() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![encode_rv32(InsnKind::JALR, 1, 0, 0, 0)]));
        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut vm = VMState::new(CENO_PLATFORM.clone(), program);
        vm.init_register_unsafe(1, base + 2);

        let err = aot.run_to_halt(&mut vm, 1).unwrap_err().to_string();

        assert!(err.contains("InstructionAddressMisaligned"));
    }
}
