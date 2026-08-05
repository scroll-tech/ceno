//! AOT support for emulator execution.
//!
//! The AOT backend compiles statically reachable RISC-V basic blocks into a
//! small x86_64 shared object, loads it, and executes it against `VMState`.
//! Unsupported instructions, dynamic control flow, traps, syscalls, and guarded
//! memory cases fall back to the normal interpreter. The preflight mode uses
//! this to speed up shard planning while keeping witness replay interpreter
//! backed elsewhere.

use crate::{
    Change, EmuContext, InsnKind, Instruction, LatestAccesses, NextAccessEvent, NextCycleAccess,
    PC_STEP_SIZE, Platform, PreflightTracer, PreflightTracerConfig, Program, SHARD_COST_BUCKETS,
    ShardCostModel, Tracer, VMState,
    addr::{ByteAddr, Cycle, RegIdx, WORD_SIZE, Word, WordAddr},
    rv32im::TrapCause,
    syscalls::{SyscallEffects, SyscallWitness},
    tracer::{
        NATIVE_TRACE_LOAD_MEM, NATIVE_TRACE_READ_RS1, NATIVE_TRACE_READ_RS2,
        NATIVE_TRACE_STORE_MEM, NATIVE_TRACE_WRITE_RD, NativeTraceStep,
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
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use tiny_keccak::{Hasher, Keccak};

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
    /// Generic AOT execution calls back into Rust after each native step so the
    /// active tracer can observe register and memory values.
    Generic,
    /// Native code emits `StepRecord`s and maintains FullTracer access state
    /// directly. Rust is entered only for fallback instructions and syscalls.
    FullTracerDirect,
    /// Native code updates `PreflightTracer` state directly for per-step access
    /// accounting, avoiding the generic callback value path.
    PreflightDirect,
    /// Native code additionally maintains shard planner counters for blocks
    /// that have statically known access cost.
    PreflightDirectBlockPlan,
    /// Exact dynamic-memory tracking with block-atomic static registers.
    PreflightDirectBlockPlanMemoryAtomicRegisters,
}

impl AssemblyTraceStyle {
    fn needs_callback_values(self) -> bool {
        matches!(self, Self::Generic | Self::FullTracerDirect)
    }

    fn is_preflight_direct(self) -> bool {
        matches!(
            self,
            Self::PreflightDirect
                | Self::PreflightDirectBlockPlan
                | Self::PreflightDirectBlockPlanMemoryAtomicRegisters
        )
    }

    fn cache_name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::FullTracerDirect => "fulltracer-direct",
            Self::PreflightDirect => "preflight-direct",
            Self::PreflightDirectBlockPlan => "preflight-block-plan",
            Self::PreflightDirectBlockPlanMemoryAtomicRegisters => {
                "preflight-block-memory-atomic-registers"
            }
        }
    }
}

const AOT_STATUS_HALTED: u32 = 0;
const AOT_STATUS_CONTINUE: u32 = 1;
const AOT_STATUS_ERROR: u32 = 2;

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
const AOT_CTX_INSTRUCTIONS_OFFSET: usize = 96;
const AOT_CTX_PROGRAM_BASE_OFFSET: usize = 104;
const AOT_CTX_TRACE_FLAGS_OFFSET: usize = 108;
const AOT_CTX_TRACE_RS1_IDX_OFFSET: usize = 112;
const AOT_CTX_TRACE_RS2_IDX_OFFSET: usize = 116;
const AOT_CTX_TRACE_RD_IDX_OFFSET: usize = 120;
const AOT_CTX_TRACE_KIND_OFFSET: usize = 124;
const AOT_CTX_TRACE_MODE_OFFSET: usize = 128;
const AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET: usize = 136;
const AOT_CTX_PREFLIGHT_CYCLE_OFFSET: usize = 152;
const AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET: usize = 184;
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
#[cfg(test)]
const AOT_CTX_FALLBACK_STEPS_OFFSET: usize = 376;
#[cfg(test)]
const AOT_CTX_PREFLIGHT_BLOCK_CELLS_TABLE_OFFSET: usize = 384;
const AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET: usize = 392;
const AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET: usize = 400;
const AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET: usize = 408;
const AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET: usize = 416;
#[allow(dead_code)]
const AOT_CTX_PREFLIGHT_NUM_CHIPS_OFFSET: usize = 424;
const AOT_CTX_PREFLIGHT_PENDING_BLOCK_OFFSET: usize = 432;
const AOT_CTX_PREFLIGHT_PLANNER_CUR_TRACE_OFFSET: usize = 440;
const AOT_CTX_PREFLIGHT_PLANNER_CUR_MAIN_OFFSET: usize = 448;
const AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET: usize = 456;
const AOT_CTX_PREFLIGHT_TOWER_COST_TABLE_OFFSET: usize = 464;
#[cfg(test)]
const AOT_CTX_FALLBACK_DYNAMIC_PC_OFFSET: usize = 472;
#[cfg(test)]
const AOT_CTX_FALLBACK_MEMORY_GUARD_OFFSET: usize = 480;
#[cfg(test)]
const AOT_CTX_FALLBACK_ECALL_OFFSET: usize = 488;
#[cfg(test)]
const AOT_CTX_FALLBACK_EXCEPTIONAL_OFFSET: usize = 496;
const AOT_CTX_FALLBACK_REASON_OFFSET: usize = 504;
#[cfg(test)]
const AOT_CTX_FALLBACK_ECALL_CODES_OFFSET: usize = 512;
const AOT_CTX_FALLBACK_RECOVERY_REASON_OFFSET: usize = 520;
const AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET: usize = 528;
const AOT_CTX_PREFLIGHT_EVENT_END_OFFSET: usize = 536;
const AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET: usize = 544;
const AOT_CTX_MEMORY_END_WORD_OFFSET: usize = 552;
const AOT_CTX_FULLTRACER_RECORDS_OFFSET: usize = 560;
const AOT_CTX_FULLTRACER_LEN_OFFSET: usize = 568;
const AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET: usize = 576;
const AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET: usize = 584;
const AOT_CTX_FULLTRACER_LATEST_CELLS_OFFSET: usize = 592;
const AOT_CTX_FULLTRACER_LATEST_BASE_OFFSET: usize = 600;
const AOT_CTX_FULLTRACER_LATEST_LEN_OFFSET: usize = 608;
const AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET: usize = 616;
const AOT_CTX_FULLTRACER_MAX_HINT_OFFSET: usize = 624;
const AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET: usize = 632;
#[cfg(test)]
const AOT_CTX_PREFLIGHT_REGISTER_SHARD_START_OFFSET: usize = 640;

const AOT_FALLBACK_DYNAMIC_PC: u32 = 1;
const AOT_FALLBACK_MEMORY_GUARD: u32 = 2;
const AOT_FALLBACK_ECALL: u32 = 3;
const AOT_FALLBACK_EXCEPTIONAL: u32 = 4;
const AOT_ABI_VERSION: u32 = 16;
const AOT_CACHE_MAGIC: &str = "ceno-aot-cache-v3";

const AOT_TRACE_MODE_NONE: u32 = 0;
const AOT_TRACE_MODE_CALLBACK: u32 = 1;
const AOT_TRACE_MODE_PREFLIGHT_DIRECT: u32 = 2;
const AOT_TRACE_MODE_FULLTRACER_DIRECT: u32 = 3;

const AOT_PREFLIGHT_HELPER_SYNC: u32 = 1;
const AOT_PREFLIGHT_HELPER_BUSY_LOOP: u32 = 2;
const AOT_PREFLIGHT_HELPER_CALLBACK: u32 = 3;
const AOT_PREFLIGHT_HELPER_SHARD_SPLIT: u32 = 4;
const AOT_PREFLIGHT_HELPER_FIRST_TOUCH: u32 = 5;
const AOT_PREFLIGHT_HELPER_GROW_TAPE: u32 = u32::MAX;

thread_local! {
    static LAST_AOT_ERROR: RefCell<Option<anyhow::Error>> = const { RefCell::new(None) };
}

/// Raw state shared between generated assembly and Rust fallback helpers.
///
/// The generated assembly uses hard-coded byte offsets into this struct, so any
/// layout change must update the `AOT_CTX_*_OFFSET` constants and the offset
/// regression test. Fields near the top are generic VM execution state; the
/// `preflight_*` fields are only used by direct preflight trace modes.
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
    preflight_block_cost_descriptors: *const AotBlockCostDescriptor,
    preflight_chip_contributions: *const AotChipContribution,
    preflight_cost_table: *const AotAdditiveCost,
    preflight_num_instances: *mut u64,
    preflight_num_chips: usize,
    preflight_pending_block: usize,
    preflight_planner_cur_trace_cells: *mut u64,
    preflight_planner_cur_main_peak: *mut u64,
    preflight_planner_cur_tower_peak: *mut u64,
    preflight_tower_cost_table: *const u64,
    fallback_dynamic_pc: u64,
    fallback_memory_guard: u64,
    fallback_ecall: u64,
    fallback_exceptional: u64,
    fallback_reason: u32,
    _fallback_padding: u32,
    fallback_ecall_codes: *mut BTreeMap<u32, usize>,
    fallback_recovery_reason: u32,
    _fallback_recovery_padding: u32,
    preflight_event_cursor: *mut NextAccessEvent,
    preflight_event_end: *mut NextAccessEvent,
    preflight_latest_len: *mut usize,
    memory_end_word: u32,
    _memory_end_padding: u32,
    fulltracer_records: *mut crate::StepRecord,
    fulltracer_len: *mut usize,
    fulltracer_pending_index: *mut usize,
    fulltracer_pending_cycle: *mut Cycle,
    fulltracer_latest_cells: *mut Cycle,
    fulltracer_latest_base: u32,
    _fulltracer_latest_padding: u32,
    fulltracer_latest_len: *mut usize,
    fulltracer_max_heap: *mut ByteAddr,
    fulltracer_max_hint: *mut ByteAddr,
    preflight_register_touched_mask: u64,
    preflight_register_shard_start: Cycle,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct AotBlockCostDescriptor {
    contribution_offset: u32,
    contribution_count: u32,
    standalone_trace_cells: u64,
    standalone_main_peak: u64,
    standalone_tower_peak: u64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct AotChipContribution {
    chip_index: u32,
    cost_row_byte_offset: u32,
    instance_delta: u64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct AotAdditiveCost {
    trace_cells: u64,
    main_peak: u64,
}

#[derive(Debug)]
pub struct AotCompileReport {
    pub block_count: usize,
    pub reachable_instruction_count: usize,
    pub compile_load_time: Duration,
    pub next_access_capacity: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AotFallbackReport {
    pub dynamic_pc_miss: usize,
    pub memory_guard: usize,
    pub ecall_by_code: BTreeMap<u32, usize>,
    pub exceptional_jump_or_trap: usize,
}

/// Loaded native image for one guest program.
///
/// `AotProgram` owns the generated shared library so the entry symbol stays
/// valid. It can execute against any compatible `VMState` for the same
/// `Program`; execution still uses Rust callbacks/fallbacks for cases outside
/// the selected `AssemblyTraceStyle`.
pub struct AotProgram {
    program: Arc<Program>,
    blocks: Vec<BasicBlock>,
    layout_profile: AotLayoutProfile,
    _library: Library,
    entry: NativeEntry,
    compile_load_time: Duration,
    trace_style: AssemblyTraceStyle,
    next_access_capacity: usize,
}

pub type AotInstance = AotProgram;

#[derive(Debug)]
struct CoverageTracer {
    cycle: Cycle,
    pc_before: ByteAddr,
    pc_after: ByteAddr,
    kind: InsnKind,
    roots: BTreeSet<u32>,
    program_base: u32,
    instruction_counts: Vec<u64>,
    branch_counts: Vec<BranchCounts>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BranchCounts {
    taken: u64,
    not_taken: u64,
}

#[derive(Clone, Debug)]
struct CoverageTracerConfig {
    entry: u32,
    program_base: u32,
    instruction_count: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AotTrainingProfile {
    roots: Vec<u32>,
    instruction_counts: Vec<u64>,
    branch_counts: Vec<BranchCounts>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AotLayoutProfile {
    block_counts: Vec<u64>,
    edge_counts: BTreeMap<(u32, u32), u64>,
    emission_order: Vec<u32>,
    digest: [u8; 32],
}

impl Tracer for CoverageTracer {
    type Record = (ByteAddr, ByteAddr, InsnKind);
    type Config = CoverageTracerConfig;

    fn new(_platform: &Platform, config: CoverageTracerConfig) -> Self {
        Self {
            cycle: Self::SUBCYCLES_PER_INSN,
            pc_before: config.entry.into(),
            pc_after: config.entry.into(),
            kind: InsnKind::INVALID,
            roots: BTreeSet::from([config.entry]),
            program_base: config.program_base,
            instruction_counts: vec![0; config.instruction_count],
            branch_counts: vec![BranchCounts::default(); config.instruction_count],
        }
    }

    fn advance(&mut self) -> Self::Record {
        let record = (self.pc_before, self.pc_after, self.kind);
        let relative_pc = self.pc_before.0.wrapping_sub(self.program_base);
        let index = (relative_pc / PC_STEP_SIZE as u32) as usize;
        if let Some(count) = self.instruction_counts.get_mut(index) {
            *count = count.saturating_add(1);
            if is_static_conditional_branch(self.kind) {
                let branch = &mut self.branch_counts[index];
                if self.pc_after.0 == self.pc_before.0.wrapping_add(PC_STEP_SIZE as u32) {
                    branch.not_taken = branch.not_taken.saturating_add(1);
                } else {
                    branch.taken = branch.taken.saturating_add(1);
                }
            }
        }
        if self.kind == InsnKind::ECALL
            || self.pc_after.0 != self.pc_before.0.wrapping_add(PC_STEP_SIZE as u32)
        {
            self.roots.insert(self.pc_after.0);
        }
        self.cycle += Self::SUBCYCLES_PER_INSN;
        record
    }

    fn is_busy_loop(&self, record: &Self::Record) -> bool {
        record.0 == record.1
    }
    fn store_pc(&mut self, pc: ByteAddr) {
        self.pc_after = pc;
    }
    fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        self.pc_before = pc.baddr();
        self.pc_after = self.pc_before + PC_STEP_SIZE;
        self.kind = value.kind;
    }
    fn track_mmu_maxtouch_before(&mut self) {}
    fn track_mmu_maxtouch_after(&mut self) {}
    fn load_register(&mut self, _idx: RegIdx, _value: Word) {}
    fn store_register(&mut self, _idx: RegIdx, _value: Change<Word>) {}
    fn load_memory(&mut self, _addr: WordAddr, _value: Word) {}
    fn store_memory(&mut self, _addr: WordAddr, _value: Change<Word>) {}
    fn track_syscall(&mut self, effects: SyscallEffects) {
        let _witness: SyscallWitness = effects.finalize(self);
    }
    fn track_access(&mut self, _addr: WordAddr, _subcycle: Cycle) -> Cycle {
        0
    }
    fn final_accesses(&self) -> &LatestAccesses {
        panic!("coverage tracer has no access history")
    }
    fn into_next_accesses(self) -> NextCycleAccess {
        NextCycleAccess::default()
    }
    fn cycle(&self) -> Cycle {
        self.cycle
    }
    fn executed_insts(&self) -> usize {
        ((self.cycle - Self::SUBCYCLES_PER_INSN) / Self::SUBCYCLES_PER_INSN) as usize
    }
    fn probe_min_max_address_by_start_addr(
        &self,
        _start: WordAddr,
    ) -> Option<(WordAddr, WordAddr)> {
        None
    }
}

/// Executes the complete training input while retaining dynamic block roots.
pub fn trace_preflight_roots(
    platform: &Platform,
    program: Arc<Program>,
    init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
) -> Result<Vec<u32>> {
    Ok(trace_preflight_profile(platform, program, init_memory)?.roots)
}

fn trace_preflight_profile(
    platform: &Platform,
    program: Arc<Program>,
    init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
) -> Result<AotTrainingProfile> {
    let started = Instant::now();
    let mut vm = VMState::<CoverageTracer>::new_with_tracer_config(
        platform.clone(),
        program.clone(),
        CoverageTracerConfig {
            entry: program.entry,
            program_base: program.base_address,
            instruction_count: program.instructions.len(),
        },
    );
    for (addr, value) in init_memory {
        vm.init_memory(addr, value);
    }

    let text_end = program.base_address + (program.instructions.len() * WORD_SIZE) as u32;
    let mut steps = 0usize;
    while vm.next_step_record()?.is_some() {
        steps += 1;
    }
    let tracer = vm.tracer();
    let roots = tracer
        .roots
        .iter()
        .copied()
        .filter(|pc| {
            *pc >= program.base_address && *pc < text_end && pc.is_multiple_of(WORD_SIZE as u32)
        })
        .collect::<Vec<_>>();
    tracing::info!(
        "AOT coverage training completed {} steps in {:?}; roots={}",
        steps,
        started.elapsed(),
        roots.len()
    );
    Ok(AotTrainingProfile {
        roots,
        instruction_counts: tracer.instruction_counts.clone(),
        branch_counts: tracer.branch_counts.clone(),
    })
}

fn trace_preflight_event_count(
    platform: &Platform,
    program: Arc<Program>,
    init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
    config: PreflightTracerConfig,
) -> Result<usize> {
    let started = Instant::now();
    let mut vm =
        VMState::<PreflightTracer>::new_with_tracer_config(platform.clone(), program, config);
    for (addr, value) in init_memory {
        vm.init_memory(addr, value);
    }
    while vm.next_step_record()?.is_some() {}
    let event_count = vm.take_tracer().into_next_accesses().len();
    tracing::info!(
        "AOT next-access training counted {} events in {:?}",
        event_count,
        started.elapsed()
    );
    Ok(event_count)
}

fn next_access_capacity(event_count: usize) -> usize {
    let headed = event_count.saturating_add(event_count.saturating_add(7) / 8);
    let bytes = headed
        .saturating_mul(std::mem::size_of::<NextAccessEvent>())
        .max(4096)
        .next_multiple_of(4096);
    let capacity = bytes / std::mem::size_of::<NextAccessEvent>();
    assert!(capacity >= headed);
    capacity
}

/// Half-open interval of guest PCs that can be entered as one native block.
///
/// A block is compiled only when all instructions in `[start_pc, end_pc)` can
/// be emitted for the selected trace style. Control transfers to unsupported or
/// unknown targets return to Rust dispatch/fallback.
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

    pub fn load_or_train_preflight(
        platform: &Platform,
        program: Arc<Program>,
        init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
    ) -> Result<Self> {
        Self::load_or_train_preflight_with_config(
            platform,
            program,
            init_memory,
            PreflightTracerConfig::default(),
        )
    }

    pub fn load_or_train_preflight_with_config(
        platform: &Platform,
        program: Arc<Program>,
        init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
        config: PreflightTracerConfig,
    ) -> Result<Self> {
        Self::load_or_train_preflight_in(
            platform,
            program,
            init_memory,
            config,
            &default_aot_cache_dir(),
        )
    }

    /// Load or build the direct-record image used by `FullTracer` witness
    /// replay. It reuses the trained preflight image's block leaders, so warm
    /// replay does not repeat coverage training and has its own cache entry.
    pub fn load_or_compile_fulltracer_replay(&self) -> Result<Self> {
        let cache_dir = default_aot_cache_dir();
        let trace_style = AssemblyTraceStyle::FullTracerDirect;
        let key = format!(
            "{}-layout{}-fulltracer-replay",
            aot_cache_key(&self.program, trace_style),
            hex_digest(&self.layout_profile.digest),
        );
        match load_cached_aot(self.program.clone(), trace_style, &cache_dir, &key) {
            Ok(Some(aot)) => {
                tracing::info!("FullTracer AOT replay artifact cache hit: {key}");
                return Ok(aot);
            }
            Ok(None) => tracing::info!("FullTracer AOT replay artifact cache miss: {key}"),
            Err(err) => {
                tracing::warn!("FullTracer AOT replay artifact cache invalid, rebuilding: {err:#}")
            }
        }

        let roots = self.blocks.iter().map(|block| block.start_pc).collect();
        compile_cached_aot(
            self.program.clone(),
            roots,
            Some(self.layout_profile.clone()),
            trace_style,
            &cache_dir,
            &key,
            0,
        )
    }

    fn load_or_train_preflight_in(
        platform: &Platform,
        program: Arc<Program>,
        init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
        config: PreflightTracerConfig,
        cache_dir: &Path,
    ) -> Result<Self> {
        let trace_style = AssemblyTraceStyle::PreflightDirectBlockPlan;
        let key = format!(
            "{}-cells{}-cycles{}",
            aot_cache_key(&program, trace_style),
            config.max_cell_per_shard(),
            config.max_cycle_per_shard()
        );
        match load_cached_aot(program.clone(), trace_style, cache_dir, &key) {
            Ok(Some(aot)) => {
                tracing::info!("AOT artifact cache hit: {}", key);
                return Ok(aot);
            }
            Ok(None) => tracing::info!("AOT artifact cache miss: {}", key),
            Err(err) => tracing::warn!("AOT artifact cache invalid, rebuilding: {err:#}"),
        }

        let init_memory = init_memory.into_iter().collect::<Vec<_>>();
        let training =
            trace_preflight_profile(platform, program.clone(), init_memory.iter().copied())?;
        let event_count = trace_preflight_event_count(
            platform,
            program.clone(),
            init_memory.iter().copied(),
            config,
        )?;
        let blocks = partition_basic_blocks_with_roots(&program, training.roots.clone())?;
        let layout_profile = build_layout_profile(&program, &blocks, &training)?;
        compile_cached_aot(
            program,
            training.roots.clone(),
            Some(layout_profile),
            trace_style,
            cache_dir,
            &key,
            event_count,
        )
    }

    fn compile_with_extra_roots_and_trace_style(
        program: Arc<Program>,
        extra_roots: Vec<u32>,
        trace_style: AssemblyTraceStyle,
    ) -> Result<Self> {
        let started = Instant::now();
        let blocks = partition_basic_blocks_with_roots(&program, extra_roots)?;
        let layout_profile = pc_order_layout(&blocks);
        let (library, entry) = compile_and_load_native(
            &program,
            &blocks,
            &layout_profile.emission_order,
            trace_style,
        )?;
        Ok(Self {
            program,
            blocks,
            layout_profile,
            _library: library,
            entry,
            compile_load_time: started.elapsed(),
            trace_style,
            next_access_capacity: 0,
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
            next_access_capacity: self.next_access_capacity,
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
        // Generic callback tracing cannot move a shard boundary ahead of a
        // native step after that step has already mutated access state. Keep
        // generic Preflight execution on the exact Rust path; production AOT
        // preflight uses the dedicated direct/block-planned style below.
        if trace_native_steps
            && TypeId::of::<T>() == TypeId::of::<PreflightTracer>()
            && self.trace_style == AssemblyTraceStyle::Generic
        {
            let mut executed_steps = 0;
            while executed_steps < max_steps && !vm.halted() {
                if vm.next_step_record()?.is_none() {
                    break;
                }
                executed_steps += 1;
            }
            return Ok(AotRunReport {
                executed_steps,
                fallback_steps: executed_steps,
                fallback: AotFallbackReport {
                    dynamic_pc_miss: executed_steps,
                    ..Default::default()
                },
                execute_time: started.elapsed(),
                next_access_events: 0,
                next_access_capacity: 0,
                next_access_growths: 0,
                next_access_growth_bytes: 0,
                next_access_growth_time: Duration::ZERO,
            });
        }
        LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = None);
        let mut executed_steps = 0u64;
        let memory_base_word = vm.memory_base_word().0;
        let memory_end_word = vm.memory_end_word().0;
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
        let mut preflight_latest_len = std::ptr::null_mut();
        let mut preflight_event_cursor = std::ptr::null_mut();
        let mut preflight_event_end = std::ptr::null_mut();
        let mut preflight_cycle = std::ptr::null_mut();
        let mut preflight_pc_before = std::ptr::null_mut();
        let mut preflight_pc_after = std::ptr::null_mut();
        let mut preflight_last_kind = std::ptr::null_mut();
        let mut preflight_current_shard_start = std::ptr::null();
        let mut preflight_planner_cur_cells = std::ptr::null_mut();
        let mut preflight_planner_cur_trace_cells = std::ptr::null_mut();
        let mut preflight_planner_cur_main_peak = std::ptr::null_mut();
        let mut preflight_planner_cur_tower_peak = std::ptr::null_mut();
        let mut preflight_planner_cur_cycle_in_shard = std::ptr::null_mut();
        let mut preflight_planner_cur_step_count = std::ptr::null_mut();
        let mut preflight_planner_max_step_shard = std::ptr::null_mut();
        let mut preflight_planner_shard_id = std::ptr::null_mut();
        let mut preflight_planner_num_instances = std::ptr::null_mut();
        let mut preflight_planner_num_chips = 0;
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
        let mut preflight_block_cost_descriptors = Vec::new();
        let mut preflight_chip_contributions = Vec::new();
        let mut preflight_cost_model = None;
        let mut fallback_ecall_codes = BTreeMap::new();
        if trace_native_steps && TypeId::of::<T>() == TypeId::of::<PreflightTracer>() {
            let preflight_vm = unsafe { &mut *(vm_ptr as *mut VMState<PreflightTracer>) };
            if preflight_vm.tracer().supports_direct_native_trace() {
                if self.trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
                    let model = preflight_vm.tracer().shard_cost_model().ok_or_else(|| {
                        anyhow!("preflight block AOT requires a shard cost model")
                    })?;
                    (
                        preflight_block_cost_descriptors,
                        preflight_chip_contributions,
                    ) = build_aot_block_cost_descriptors(&self.program, &self.blocks, &model)?;
                    preflight_cost_model = Some(model);
                } else {
                    preflight_step_cells = self
                        .program
                        .instructions
                        .iter()
                        .map(|insn| preflight_vm.tracer().native_step_cells_for_kind(insn.kind))
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
                let event_capacity = if self.next_access_capacity == 0 {
                    next_access_capacity(max_steps.saturating_add(15) / 16)
                } else {
                    self.next_access_capacity
                };
                preflight_vm
                    .tracer_mut()
                    .prepare_native_next_access_tape(event_capacity);
                (preflight_event_cursor, preflight_event_end) =
                    preflight_vm.tracer_mut().native_next_access_ptrs();
                let state = preflight_vm.tracer_mut().native_trace_state();
                trace_mode = AOT_TRACE_MODE_PREFLIGHT_DIRECT;
                preflight_latest_cells = state.latest_cells;
                preflight_latest_base = state.latest_base.0;
                preflight_latest_len = state.latest_len;
                preflight_cycle = state.cycle;
                preflight_pc_before = state.pc_before;
                preflight_pc_after = state.pc_after;
                preflight_last_kind = state.last_kind;
                preflight_current_shard_start = state.current_shard_start_cycle;
                preflight_planner_cur_cells = state.planner_cur_cells;
                preflight_planner_cur_trace_cells = state.planner_cur_trace_cells;
                preflight_planner_cur_main_peak = state.planner_cur_main_peak;
                preflight_planner_cur_tower_peak = state.planner_cur_tower_peak;
                preflight_planner_cur_cycle_in_shard = state.planner_cur_cycle_in_shard;
                preflight_planner_cur_step_count = state.planner_cur_step_count;
                preflight_planner_max_step_shard = state.planner_max_step_shard;
                preflight_planner_shard_id = state.planner_shard_id;
                preflight_planner_num_instances = state.planner_num_instances;
                preflight_planner_num_chips = state.planner_num_chips;
                preflight_max_cell_per_shard = state.planner_max_cell_per_shard;
                preflight_target_cell_first_shard = state.planner_target_cell_first_shard;
                preflight_max_cycle_per_shard = state.planner_max_cycle_per_shard;
            }
        }
        let mut fulltracer_records = std::ptr::null_mut();
        let mut fulltracer_len = std::ptr::null_mut();
        let mut fulltracer_pending_index = std::ptr::null_mut();
        let mut fulltracer_pending_cycle = std::ptr::null_mut();
        let mut fulltracer_latest_cells = std::ptr::null_mut();
        let mut fulltracer_latest_base = 0;
        let mut fulltracer_latest_len = std::ptr::null_mut();
        let mut fulltracer_max_heap = std::ptr::null_mut();
        let mut fulltracer_max_hint = std::ptr::null_mut();
        if trace_native_steps
            && !cfg!(debug_assertions)
            && TypeId::of::<T>() == TypeId::of::<crate::FullTracer>()
            && self.trace_style == AssemblyTraceStyle::FullTracerDirect
        {
            let fulltracer_vm = unsafe { &mut *(vm_ptr as *mut VMState<crate::FullTracer>) };
            let state = fulltracer_vm.tracer_mut().native_trace_state();
            trace_mode = AOT_TRACE_MODE_FULLTRACER_DIRECT;
            fulltracer_records = state.records;
            fulltracer_len = state.len;
            fulltracer_pending_index = state.pending_index;
            fulltracer_pending_cycle = state.pending_cycle;
            fulltracer_latest_cells = state.latest_cells;
            fulltracer_latest_base = state.latest_base.0;
            fulltracer_latest_len = state.latest_len;
            fulltracer_max_heap = state.max_heap_addr_access;
            fulltracer_max_hint = state.max_hint_addr_access;
        }
        let preflight_step_cells_table = if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            preflight_step_cells.as_ptr()
        } else {
            std::ptr::null()
        };
        let preflight_block_cells_table = std::ptr::null();
        let preflight_block_cost_descriptors_table =
            if self.trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
                preflight_block_cost_descriptors.as_ptr()
            } else {
                std::ptr::null()
            };
        let preflight_additive_cost_table = preflight_cost_model
            .as_ref()
            .map(|model| {
                model
                    .trace_cost_table()
                    .iter()
                    .copied()
                    .zip(model.main_cost_table().iter().copied())
                    .map(|(trace_cells, main_peak)| AotAdditiveCost {
                        trace_cells,
                        main_peak,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let (preflight_register_touched_mask, preflight_register_shard_start) =
            initial_preflight_register_touched_mask(
                preflight_latest_cells,
                preflight_current_shard_start,
            );
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
            preflight_block_cost_descriptors: preflight_block_cost_descriptors_table,
            preflight_chip_contributions: preflight_chip_contributions.as_ptr(),
            preflight_cost_table: preflight_additive_cost_table.as_ptr(),
            preflight_num_instances: preflight_planner_num_instances,
            preflight_num_chips: preflight_planner_num_chips,
            preflight_pending_block: usize::MAX,
            preflight_planner_cur_trace_cells,
            preflight_planner_cur_main_peak,
            preflight_planner_cur_tower_peak,
            preflight_tower_cost_table: preflight_cost_model
                .as_ref()
                .map_or(std::ptr::null(), |model| model.tower_cost_table().as_ptr()),
            fallback_dynamic_pc: 0,
            fallback_memory_guard: 0,
            fallback_ecall: 0,
            fallback_exceptional: 0,
            fallback_reason: 0,
            _fallback_padding: 0,
            fallback_ecall_codes: &mut fallback_ecall_codes,
            fallback_recovery_reason: 0,
            _fallback_recovery_padding: 0,
            preflight_event_cursor,
            preflight_event_end,
            preflight_latest_len,
            memory_end_word,
            _memory_end_padding: 0,
            fulltracer_records,
            fulltracer_len,
            fulltracer_pending_index,
            fulltracer_pending_cycle,
            fulltracer_latest_cells,
            fulltracer_latest_base,
            _fulltracer_latest_padding: 0,
            fulltracer_latest_len,
            fulltracer_max_heap,
            fulltracer_max_hint,
            preflight_register_touched_mask,
            preflight_register_shard_start,
        };
        let trace_fn = if trace_mode == AOT_TRACE_MODE_FULLTRACER_DIRECT {
            std::ptr::null()
        } else if trace_native_steps {
            if TypeId::of::<T>() == TypeId::of::<PreflightTracer>() {
                if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
                    (ceno_aot_preflight_direct_callback as AotTraceFn) as *const c_void
                } else {
                    (aot_trace_native_preflight as AotTraceFn) as *const c_void
                }
            } else {
                (aot_trace_native_compute::<T> as AotTraceFn) as *const c_void
            }
        } else {
            std::ptr::null()
        };
        let exec_fn = if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            ceno_aot_preflight_fallback_callback as AotInsnFn
        } else {
            aot_exec_one::<T>
        };
        let native_status = unsafe {
            (self.entry)(
                &mut context,
                exec_fn,
                trace_fn,
                max_steps as u64,
                &mut executed_steps,
                vm.get_pc().0,
            )
        };
        if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            let preflight_vm = unsafe { &mut *(vm_ptr as *mut VMState<PreflightTracer>) };
            unsafe {
                preflight_vm
                    .tracer_mut()
                    .sync_native_next_access_tape(context.preflight_event_cursor)
            };
        }
        if native_status == AOT_STATUS_ERROR {
            let err = LAST_AOT_ERROR
                .with(|slot| slot.borrow_mut().take())
                .unwrap_or_else(|| anyhow!("AOT native step failed without error detail"));
            return Err(err);
        }
        if native_status != AOT_STATUS_HALTED {
            bail!("AOT native entry returned invalid status {native_status}");
        }
        let (
            next_access_events,
            next_access_capacity,
            next_access_growths,
            next_access_growth_bytes,
            next_access_growth_time,
        ) = if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            let preflight_vm = unsafe { &*(vm_ptr as *const VMState<PreflightTracer>) };
            preflight_vm.tracer().next_access_tape_stats()
        } else {
            (0, 0, 0, 0, Duration::ZERO)
        };
        tracing::info!(
            "AOT next-access tape usage={next_access_events} capacity={next_access_capacity} growths={next_access_growths} growth_bytes={next_access_growth_bytes} growth_time={next_access_growth_time:?} normal_access_callbacks=0"
        );
        Ok(AotRunReport {
            executed_steps: executed_steps as usize,
            fallback_steps: context.fallback_steps as usize,
            fallback: AotFallbackReport {
                dynamic_pc_miss: context.fallback_dynamic_pc as usize,
                memory_guard: context.fallback_memory_guard as usize,
                ecall_by_code: fallback_ecall_codes,
                exceptional_jump_or_trap: context.fallback_exceptional as usize,
            },
            execute_time: started.elapsed(),
            next_access_events,
            next_access_capacity,
            next_access_growths,
            next_access_growth_bytes,
            next_access_growth_time,
        })
    }
}

#[derive(Debug)]
pub struct AotRunReport {
    pub executed_steps: usize,
    pub fallback_steps: usize,
    pub fallback: AotFallbackReport,
    pub execute_time: Duration,
    pub next_access_events: usize,
    pub next_access_capacity: usize,
    pub next_access_growths: usize,
    pub next_access_growth_bytes: usize,
    pub next_access_growth_time: Duration,
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
                if matches!(insn.kind, InsnKind::ECALL | InsnKind::INVALID) {
                    leaders.insert(pc);
                }
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

fn is_static_conditional_branch(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::BEQ
            | InsnKind::BNE
            | InsnKind::BLT
            | InsnKind::BGE
            | InsnKind::BLTU
            | InsnKind::BGEU
    )
}

fn pc_order_layout(blocks: &[BasicBlock]) -> AotLayoutProfile {
    let emission_order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let mut profile = AotLayoutProfile {
        block_counts: vec![0; blocks.len()],
        edge_counts: BTreeMap::new(),
        emission_order,
        digest: [0; 32],
    };
    profile.digest = layout_profile_digest(&profile);
    profile
}

fn build_layout_profile(
    program: &Program,
    blocks: &[BasicBlock],
    training: &AotTrainingProfile,
) -> Result<AotLayoutProfile> {
    let block_by_pc = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_pc, index))
        .collect::<BTreeMap<_, _>>();
    let instruction_index =
        |pc: u32| (pc.wrapping_sub(program.base_address) / PC_STEP_SIZE as u32) as usize;
    let block_counts = blocks
        .iter()
        .map(|block| {
            training
                .instruction_counts
                .get(instruction_index(block.start_pc))
                .copied()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    let mut edge_counts = BTreeMap::new();
    for block in blocks {
        let terminal_pc = block.end_pc - PC_STEP_SIZE as u32;
        let insn = instruction_at(program, terminal_pc)?;
        let terminal_index = instruction_index(terminal_pc);
        let execution_count = training
            .instruction_counts
            .get(terminal_index)
            .copied()
            .unwrap_or(0);
        if is_static_conditional_branch(insn.kind) {
            let counts = training
                .branch_counts
                .get(terminal_index)
                .copied()
                .unwrap_or_default();
            let target = branch_target(terminal_pc, insn)?;
            if block_by_pc.contains_key(&target) {
                edge_counts
                    .entry((block.start_pc, target))
                    .and_modify(|count: &mut u64| *count = count.saturating_add(counts.taken))
                    .or_insert(counts.taken);
            }
            if let Some(fallthrough) = fallthrough_pc(program, terminal_pc) {
                if block_by_pc.contains_key(&fallthrough) {
                    edge_counts
                        .entry((block.start_pc, fallthrough))
                        .and_modify(|count| *count = count.saturating_add(counts.not_taken))
                        .or_insert(counts.not_taken);
                }
            }
        } else {
            for successor in static_successors(program, terminal_pc, insn)? {
                if block_by_pc.contains_key(&successor) {
                    edge_counts.insert((block.start_pc, successor), execution_count);
                }
            }
        }
    }

    let emission_order = hot_chain_emission_order(blocks, &block_counts, &edge_counts);
    let total_edge_frequency = edge_counts
        .values()
        .fold(0u64, |total, count| total.saturating_add(*count));
    let adjacent_edge_frequency = emission_order.windows(2).fold(0u64, |total, pair| {
        total.saturating_add(edge_counts.get(&(pair[0], pair[1])).copied().unwrap_or(0))
    });
    let observed_blocks = block_counts.iter().filter(|&&count| count > 0).count();
    tracing::info!(
        "AOT layout profile observed_blocks={}/{} static_edge_frequency={} adjacent_edge_frequency={} fallthrough_coverage={:.2}%",
        observed_blocks,
        blocks.len(),
        total_edge_frequency,
        adjacent_edge_frequency,
        if total_edge_frequency == 0 {
            0.0
        } else {
            100.0 * adjacent_edge_frequency as f64 / total_edge_frequency as f64
        }
    );
    let mut profile = AotLayoutProfile {
        block_counts,
        edge_counts,
        emission_order,
        digest: [0; 32],
    };
    profile.digest = layout_profile_digest(&profile);
    Ok(profile)
}

fn hot_chain_emission_order(
    blocks: &[BasicBlock],
    block_counts: &[u64],
    edge_counts: &BTreeMap<(u32, u32), u64>,
) -> Vec<u32> {
    let block_by_pc = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_pc, index))
        .collect::<BTreeMap<_, _>>();
    let mut chains = blocks
        .iter()
        .enumerate()
        .map(|(index, _)| vec![index])
        .collect::<Vec<_>>();
    let mut chain_of = (0..blocks.len()).collect::<Vec<_>>();
    let mut edges = edge_counts
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(&(from, to), &count)| (count, from, to))
        .collect::<Vec<_>>();
    edges.sort_unstable_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });

    for (_, from_pc, to_pc) in edges {
        let (Some(&from), Some(&to)) = (block_by_pc.get(&from_pc), block_by_pc.get(&to_pc)) else {
            continue;
        };
        let from_chain = chain_of[from];
        let to_chain = chain_of[to];
        if from_chain == to_chain
            || chains[from_chain].last() != Some(&from)
            || chains[to_chain].first() != Some(&to)
        {
            continue;
        }
        let appended = std::mem::take(&mut chains[to_chain]);
        for &index in &appended {
            chain_of[index] = from_chain;
        }
        chains[from_chain].extend(appended);
    }

    let mut hot_chains = chains
        .into_iter()
        .filter(|chain| !chain.is_empty())
        .filter_map(|chain| {
            let count = chain.iter().fold(0u64, |count, &index| {
                count.saturating_add(block_counts.get(index).copied().unwrap_or(0))
            });
            (count > 0).then_some((count, chain))
        })
        .collect::<Vec<_>>();
    hot_chains.sort_unstable_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| blocks[a.1[0]].start_pc.cmp(&blocks[b.1[0]].start_pc))
    });
    let mut emission_order = hot_chains
        .into_iter()
        .flat_map(|(_, chain)| chain)
        .map(|index| blocks[index].start_pc)
        .collect::<Vec<_>>();
    let emitted = emission_order.iter().copied().collect::<BTreeSet<_>>();
    emission_order.extend(
        blocks
            .iter()
            .filter(|block| !emitted.contains(&block.start_pc))
            .map(|block| block.start_pc),
    );
    emission_order
}

fn layout_profile_digest(profile: &AotLayoutProfile) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(profile.block_counts.len() as u64).to_le_bytes());
    for &count in &profile.block_counts {
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    bytes.extend_from_slice(&(profile.edge_counts.len() as u64).to_le_bytes());
    for (&(from, to), &count) in &profile.edge_counts {
        bytes.extend_from_slice(&from.to_le_bytes());
        bytes.extend_from_slice(&to.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    bytes.extend_from_slice(&(profile.emission_order.len() as u64).to_le_bytes());
    for &pc in &profile.emission_order {
        bytes.extend_from_slice(&pc.to_le_bytes());
    }
    keccak256(&bytes)
}

fn validate_emission_order(blocks: &[BasicBlock], emission_order: &[u32]) -> Result<()> {
    let canonical = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<BTreeSet<_>>();
    let emitted = emission_order.iter().copied().collect::<BTreeSet<_>>();
    if emission_order.len() != blocks.len() || emitted != canonical {
        bail!("AOT emission order is not a permutation of canonical blocks");
    }
    Ok(())
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
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
) -> Result<(Library, NativeEntry)> {
    let dir = tempfile::Builder::new()
        .prefix("ceno-aot-")
        .tempdir()
        .context("create AOT tempdir")?;
    let asm_path = dir.path().join("program.S");
    let so_path = dir.path().join("program.so");
    compile_native_to(
        program,
        blocks,
        emission_order,
        trace_style,
        &asm_path,
        &so_path,
    )?;
    load_native(&so_path)
}

fn compile_native_to(
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
    asm_path: &Path,
    so_path: &Path,
) -> Result<()> {
    write_assembly(asm_path, program, blocks, emission_order, trace_style)?;
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
    Ok(())
}

fn load_native(so_path: &Path) -> Result<(Library, NativeEntry)> {
    let library = unsafe { Library::new(so_path) }.context("load AOT shared object")?;
    let entry = unsafe {
        let symbol: Symbol<'_, NativeEntry> = library
            .get(b"ceno_aot_entry")
            .context("load ceno_aot_entry")?;
        *symbol
    };
    Ok((library, entry))
}

fn default_aot_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("CENO_AOT_CACHE_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(path).join("ceno/aot");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path).join(".cache/ceno/aot");
    }
    std::env::temp_dir().join("ceno-aot-cache")
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn program_digest(program: &Program) -> [u8; 32] {
    let mut bytes =
        Vec::with_capacity(16 + program.instructions.len() * 16 + program.image.len() * 8);
    bytes.extend_from_slice(&program.entry.to_le_bytes());
    bytes.extend_from_slice(&program.base_address.to_le_bytes());
    bytes.extend_from_slice(&program.sheap.to_le_bytes());
    bytes.extend_from_slice(&(program.instructions.len() as u64).to_le_bytes());
    for insn in &program.instructions {
        bytes.push(insn.kind as u8);
        bytes.push(insn.rs1);
        bytes.push(insn.rs2);
        bytes.push(insn.rd);
        bytes.extend_from_slice(&insn.imm.to_le_bytes());
        bytes.extend_from_slice(&insn.raw.to_le_bytes());
    }
    for (&addr, &value) in &program.image {
        bytes.extend_from_slice(&addr.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    keccak256(&bytes)
}

fn aot_cache_key(program: &Program, trace_style: AssemblyTraceStyle) -> String {
    format!(
        "{}-abi{}-{}-{}-{}",
        hex_digest(&program_digest(program)),
        AOT_ABI_VERSION,
        trace_style.cache_name(),
        std::env::consts::ARCH,
        std::env::consts::OS,
    )
}

fn artifact_digest(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("read AOT artifact {}", path.display()))?;
    Ok(keccak256(&bytes))
}

fn cache_paths(cache_dir: &Path, key: &str) -> (PathBuf, PathBuf) {
    (
        cache_dir.join(format!("{key}.so")),
        cache_dir.join(format!("{key}.meta")),
    )
}

fn encode_cache_metadata(
    key: &str,
    so_digest: &[u8; 32],
    roots: &[u32],
    layout_profile: &AotLayoutProfile,
    event_count: usize,
    event_capacity: usize,
) -> String {
    let roots = roots
        .iter()
        .map(|pc| format!("{pc:08x}"))
        .collect::<Vec<_>>()
        .join(",");
    let emission_order = layout_profile
        .emission_order
        .iter()
        .map(|pc| format!("{pc:08x}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{AOT_CACHE_MAGIC}\n{key}\n{}\n{event_count}\n{event_capacity}\n{roots}\n{}\n{emission_order}\n",
        hex_digest(so_digest),
        hex_digest(&layout_profile.digest),
    )
}

fn decode_cache_metadata(
    metadata: &str,
    expected_key: &str,
) -> Result<([u8; 32], Vec<u32>, usize, [u8; 32], Vec<u32>)> {
    let mut lines = metadata.lines();
    if lines.next() != Some(AOT_CACHE_MAGIC) || lines.next() != Some(expected_key) {
        bail!("AOT cache program/ABI identity mismatch");
    }
    let digest_hex = lines
        .next()
        .ok_or_else(|| anyhow!("AOT cache digest missing"))?;
    if digest_hex.len() != 64 {
        bail!("AOT cache digest has invalid length");
    }
    let digest = decode_hex_digest(digest_hex, "AOT cache digest")?;
    let event_count = lines
        .next()
        .ok_or_else(|| anyhow!("AOT cache event count missing"))?
        .parse::<usize>()
        .context("parse AOT cache event count")?;
    let event_capacity = lines
        .next()
        .ok_or_else(|| anyhow!("AOT cache event capacity missing"))?
        .parse::<usize>()
        .context("parse AOT cache event capacity")?;
    if event_capacity != next_access_capacity(event_count) {
        bail!("AOT cache next-access capacity does not match trained event count");
    }
    let roots = lines
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|root| !root.is_empty())
        .map(|root| u32::from_str_radix(root, 16).context("parse AOT cache root"))
        .collect::<Result<Vec<_>>>()?;
    let profile_digest = decode_hex_digest(
        lines
            .next()
            .ok_or_else(|| anyhow!("AOT cache profile digest missing"))?,
        "AOT cache profile digest",
    )?;
    let emission_order = lines
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|pc| !pc.is_empty())
        .map(|pc| u32::from_str_radix(pc, 16).context("parse AOT cache emission PC"))
        .collect::<Result<Vec<_>>>()?;
    Ok((
        digest,
        roots,
        event_capacity,
        profile_digest,
        emission_order,
    ))
}

fn decode_hex_digest(hex: &str, description: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        bail!("{description} has invalid length");
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("parse {description}"))?;
    }
    Ok(digest)
}

fn load_cached_aot(
    program: Arc<Program>,
    trace_style: AssemblyTraceStyle,
    cache_dir: &Path,
    key: &str,
) -> Result<Option<AotProgram>> {
    let (so_path, metadata_path) = cache_paths(cache_dir, key);
    if !so_path.exists() || !metadata_path.exists() {
        return Ok(None);
    }
    let metadata = fs::read_to_string(&metadata_path)
        .with_context(|| format!("read AOT metadata {}", metadata_path.display()))?;
    let (expected_digest, roots, event_capacity, profile_digest, emission_order) =
        decode_cache_metadata(&metadata, key)?;
    if artifact_digest(&so_path)? != expected_digest {
        bail!("AOT artifact checksum mismatch");
    }
    tracing::info!(
        "AOT cached artifact size={} profile_digest={}",
        fs::metadata(&so_path)?.len(),
        hex_digest(&profile_digest),
    );
    let blocks = partition_basic_blocks_with_roots(&program, roots)?;
    validate_emission_order(&blocks, &emission_order)?;
    let layout_profile = AotLayoutProfile {
        block_counts: Vec::new(),
        edge_counts: BTreeMap::new(),
        emission_order,
        digest: profile_digest,
    };
    let started = Instant::now();
    let (library, entry) = load_native(&so_path)?;
    Ok(Some(AotProgram {
        program,
        blocks,
        layout_profile,
        _library: library,
        entry,
        compile_load_time: started.elapsed(),
        trace_style,
        next_access_capacity: event_capacity,
    }))
}

fn compile_cached_aot(
    program: Arc<Program>,
    roots: Vec<u32>,
    layout_profile: Option<AotLayoutProfile>,
    trace_style: AssemblyTraceStyle,
    cache_dir: &Path,
    key: &str,
    event_count: usize,
) -> Result<AotProgram> {
    let started = Instant::now();
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("create AOT cache directory {}", cache_dir.display()))?;
    let blocks = partition_basic_blocks_with_roots(&program, roots.clone())?;
    let layout_profile = layout_profile.unwrap_or_else(|| pc_order_layout(&blocks));
    validate_emission_order(&blocks, &layout_profile.emission_order)?;
    let nonce = format!("{}.{}", std::process::id(), started.elapsed().as_nanos());
    let asm_tmp = cache_dir.join(format!(".{key}.{nonce}.S"));
    let so_tmp = cache_dir.join(format!(".{key}.{nonce}.so"));
    let meta_tmp = cache_dir.join(format!(".{key}.{nonce}.meta"));
    let (so_path, metadata_path) = cache_paths(cache_dir, key);
    let result = (|| -> Result<()> {
        compile_native_to(
            &program,
            &blocks,
            &layout_profile.emission_order,
            trace_style,
            &asm_tmp,
            &so_tmp,
        )?;
        tracing::info!(
            "AOT generated artifact size={} profile_digest={}",
            fs::metadata(&so_tmp)?.len(),
            hex_digest(&layout_profile.digest),
        );
        let digest = artifact_digest(&so_tmp)?;
        let event_capacity = next_access_capacity(event_count);
        fs::write(
            &meta_tmp,
            encode_cache_metadata(
                key,
                &digest,
                &roots,
                &layout_profile,
                event_count,
                event_capacity,
            ),
        )?;
        fs::rename(&so_tmp, &so_path)?;
        fs::rename(&meta_tmp, &metadata_path)?;
        Ok(())
    })();
    let _ = fs::remove_file(&asm_tmp);
    if let Err(err) = result {
        let _ = fs::remove_file(&so_tmp);
        let _ = fs::remove_file(&meta_tmp);
        return Err(err.context("compile and atomically cache AOT artifact"));
    }
    let (library, entry) = load_native(&so_path)?;
    Ok(AotProgram {
        program,
        blocks,
        layout_profile,
        _library: library,
        entry,
        compile_load_time: started.elapsed(),
        trace_style,
        next_access_capacity: next_access_capacity(event_count),
    })
}

fn write_assembly(
    path: &Path,
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    validate_emission_order(blocks, emission_order)?;
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
    writeln!(file, "    subq $72, %rsp")?;
    writeln!(file, "    movq %rdi, %r12")?;
    writeln!(file, "    movq %rsi, %r13")?;
    writeln!(file, "    movq %rdx, %r14")?;
    writeln!(file, "    movq %rcx, %rbp")?;
    // Keep the preflight tape cursor in a callee-saved register. The executed
    // step output pointer is cold and fits in the otherwise-unused final stack
    // slot.
    writeln!(file, "    movq %r8, 48(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET}(%r12), %rbx"
    )?;
    writeln!(file, "    movl %r9d, %r15d")?;
    writeln!(file, "    movq $0, 0(%rsp)")?;
    writeln!(file, "    movl %r15d, 8(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq %rax, 56(%rsp)")?;
    emit_assembly_profile_symbol(&mut file, "ceno_aot_dispatch")?;
    writeln!(file, "L_dispatch:")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    jae L_done")?;
    emit_dispatch_tree(&mut file, blocks, &labels, 0, blocks.len())?;
    let blocks_by_pc = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_pc, (index, block)))
        .collect::<BTreeMap<_, _>>();
    for (emission_index, block_pc) in emission_order.iter().enumerate() {
        let &(block_idx, block) = blocks_by_pc
            .get(block_pc)
            .expect("validated emission block must exist");
        let next_block_pc = emission_order.get(emission_index + 1).copied();
        let label = labels.get(&block.start_pc).expect("block label must exist");
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{:08x}_guards", block.start_pc),
        )?;
        writeln!(file, "{label}:")?;
        // Reaching a native block leader ends any Rust fallback recovery run.
        writeln!(
            file,
            "    movl $0, {AOT_CTX_FALLBACK_RECOVERY_REASON_OFFSET}(%r12)"
        )?;
        let block_plan = if trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
            preflight_block_plan_kind(program, block)?
        } else {
            None
        };
        let adaptive_exact_access_plan = block_plan.is_none()
            && trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan
            && block_supports_adaptive_cost_plan(program, block)?;
        if block_plan.is_none()
            && !adaptive_exact_access_plan
            && trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan
        {
            let reason = if instruction_at(program, block.start_pc)?.kind == InsnKind::ECALL {
                AOT_FALLBACK_ECALL
            } else {
                AOT_FALLBACK_EXCEPTIONAL
            };
            emit_call_current_pc(&mut file, reason)?;
            writeln!(file, "    jmp L_dispatch")?;
            continue;
        }
        if adaptive_exact_access_plan {
            emit_preflight_direct_block_budget_guard(&mut file, block)?;
            emit_preflight_direct_block_event_capacity_guard(
                &mut file,
                program,
                block_idx,
                block,
                PreflightAccessMode::BlockAtomic,
            )?;
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_accounting", block.start_pc),
            )?;
            emit_preflight_adaptive_block_plan_entry(&mut file, block_idx, block)?;
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_register_first_checks", block.start_pc),
            )?;
            emit_preflight_direct_block_access_entry(&mut file, program, block_idx, block)?;
        }
        if block_plan.is_some() {
            emit_preflight_direct_block_budget_guard(&mut file, block)?;
            if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess)) {
                emit_preflight_direct_block_memory_fast_path_guard(&mut file, program, block)?;
            }
            emit_preflight_direct_block_event_capacity_guard(
                &mut file,
                program,
                block_idx,
                block,
                PreflightAccessMode::BlockAtomic,
            )?;
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_accounting", block.start_pc),
            )?;
            emit_preflight_adaptive_block_plan_entry(&mut file, block_idx, block)?;
            if block_plan.is_some() {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_register_first_checks", block.start_pc),
                )?;
                emit_preflight_direct_block_access_entry(&mut file, program, block_idx, block)?;
            }
        }
        let mut pc = block.start_pc;
        let mut last_profile_region = None;
        while pc < block.end_pc {
            let insn = instruction_at(program, pc)?;
            let step_trace_style =
                if matches!(block_plan, Some(PreflightBlockPlanKind::RegisterOnly)) {
                    AssemblyTraceStyle::PreflightDirectBlockPlan
                } else if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess)) {
                    AssemblyTraceStyle::PreflightDirectBlockPlanMemoryAtomicRegisters
                } else if adaptive_exact_access_plan {
                    AssemblyTraceStyle::PreflightDirectBlockPlanMemoryAtomicRegisters
                } else if trace_style == AssemblyTraceStyle::PreflightDirectBlockPlan {
                    AssemblyTraceStyle::PreflightDirect
                } else {
                    trace_style
                };
            let region = if native_opcode_family(insn.kind) == Some(NativeOpcodeFamily::Memory) {
                "memory"
            } else {
                "guest"
            };
            if last_profile_region != Some(region) {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_{region}_{pc:08x}", block.start_pc),
                )?;
                last_profile_region = Some(region);
            }
            emit_instruction_body(&mut file, program, pc, insn, step_trace_style)?;
            pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        }
        if let Some(prev_pc) = pc.checked_sub(PC_STEP_SIZE as u32) {
            let insn = instruction_at(program, prev_pc)?;
            if block_plan.is_some() {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_register_latest_commit", block.start_pc),
                )?;
                emit_preflight_direct_block_register_access_exit(&mut file, program, block)?;
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_plan_commit", block.start_pc),
                )?;
                emit_preflight_direct_block_plan_exit(&mut file, block)?;
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_guards_exit", block.start_pc),
                )?;
                emit_preflight_direct_busy_loop_guard(&mut file, prev_pc)?;
            } else if adaptive_exact_access_plan {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_register_latest_commit", block.start_pc),
                )?;
                emit_preflight_direct_block_register_access_exit(&mut file, program, block)?;
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_plan_commit", block.start_pc),
                )?;
                emit_preflight_adaptive_exact_access_plan_exit(&mut file, block)?;
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_guards_exit", block.start_pc),
                )?;
                emit_preflight_direct_busy_loop_guard(&mut file, prev_pc)?;
            }
            emit_successor_jump(&mut file, program, &labels, next_block_pc, prev_pc, insn)?;
        }
    }
    emit_assembly_profile_symbol(&mut file, "ceno_aot_dynamic_fallback")?;
    writeln!(file, "L_dynamic:")?;
    emit_call_current_pc(&mut file, AOT_FALLBACK_DYNAMIC_PC)?;
    writeln!(file, "    jmp L_dispatch")?;
    writeln!(file, "L_memory_guard:")?;
    emit_call_current_pc(&mut file, AOT_FALLBACK_MEMORY_GUARD)?;
    writeln!(file, "    jmp L_dispatch")?;
    writeln!(file, "L_exceptional:")?;
    emit_call_current_pc(&mut file, AOT_FALLBACK_EXCEPTIONAL)?;
    writeln!(file, "    jmp L_dispatch")?;
    writeln!(file, "L_done:")?;
    emit_sync_preflight_direct(&mut file)?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
    writeln!(file, "    movl %r15d, (%rdx)")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    movq 48(%rsp), %rdx")?;
    writeln!(file, "    movq %rax, (%rdx)")?;
    writeln!(file, "    movl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    jmp L_return")?;
    writeln!(file, "L_error:")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
    writeln!(file, "    movl %r15d, (%rdx)")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    movq 48(%rsp), %rdx")?;
    writeln!(file, "    movq %rax, (%rdx)")?;
    writeln!(file, "    movl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "L_return:")?;
    writeln!(file, "    addq $72, %rsp")?;
    writeln!(file, "    popq %rbp")?;
    writeln!(file, "    popq %r15")?;
    writeln!(file, "    popq %r14")?;
    writeln!(file, "    popq %r13")?;
    writeln!(file, "    popq %r12")?;
    writeln!(file, "    popq %rbx")?;
    writeln!(file, "    ret")?;
    if trace_style == AssemblyTraceStyle::FullTracerDirect {
        emit_fulltracer_shared_recorder(&mut file)?;
    }
    writeln!(file, ".section .note.GNU-stack,\"\",@progbits")?;
    Ok(())
}

fn emit_assembly_profile_symbol(mut file: impl Write, name: &str) -> Result<()> {
    writeln!(file, ".type {name}, @function")?;
    writeln!(file, "{name}:")?;
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

fn emit_call_one(mut file: impl Write, pc: u32, reason: u32) -> Result<()> {
    emit_sync_preflight_direct(&mut file)?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(
        file,
        "    movl ${reason}, {AOT_CTX_FALLBACK_REASON_OFFSET}(%r12)"
    )?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl ${pc:#010x}, %esi")?;
    writeln!(file, "    call *%r13")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    emit_after_step(&mut file)?;
    Ok(())
}

fn emit_call_current_pc(mut file: impl Write, reason: u32) -> Result<()> {
    emit_sync_preflight_direct(&mut file)?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(
        file,
        "    movl ${reason}, {AOT_CTX_FALLBACK_REASON_OFFSET}(%r12)"
    )?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl %r15d, %esi")?;
    writeln!(file, "    call *%r13")?;
    emit_reload_preflight_event_cursor(&mut file)?;
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

fn emit_fulltracer_shared_recorder(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
.macro FULLTRACER_ACCESS op_offset, previous_offset, subcycle, done_label
    movl %edx, \op_offset(%r10)
    movq {AOT_CTX_FULLTRACER_LATEST_CELLS_OFFSET}(%r12), %r8
    movl %edx, %ecx
    subl {AOT_CTX_FULLTRACER_LATEST_BASE_OFFSET}(%r12), %ecx
    movq (%r8,%rcx,8), %r9
    leaq \subcycle(%rax), %rsi
    movq %rsi, (%r8,%rcx,8)
    movq %r9, \previous_offset(%r10)
    testq %r9, %r9
    jne \done_label
    movq {AOT_CTX_FULLTRACER_LATEST_LEN_OFFSET}(%r12), %r8
    incq (%r8)
\done_label:
.endm

.type L_fulltracer_emit_step, @function
L_fulltracer_emit_step:
    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    movq (%r8), %rcx
    imulq $136, %rcx, %r9
    addq %r9, %r10
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    movq (%r8), %rax
    movq %rax, 0(%r10)
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %ecx
    movl %ecx, 8(%r10)
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %ecx
    movl %ecx, 12(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 16(%r10)
    movl %ecx, 20(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 24(%r10)
    movl %ecx, 28(%r10)

    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %ecx
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %ecx
    shrl $2, %ecx
    imulq $12, %rcx, %rcx
    movq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %r8
    addq %rcx, %r8
    movq 0(%r8), %rcx
    movq %rcx, 32(%r10)
    movl 8(%r8), %ecx
    movl %ecx, 40(%r10)
    movl $0, 44(%r10)
    movl $-1, 128(%r10)
    movl $0, 132(%r10)

    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_fulltracer_rs1_skip
    movb $1, 44(%r10)
    movl {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12), %edx
    shll $6, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %ecx
    movl %ecx, 52(%r10)
    FULLTRACER_ACCESS 48, 56, 0, .L_fulltracer_rs1_done
.L_fulltracer_rs1_skip:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_fulltracer_rs2_skip
    movb $1, 45(%r10)
    movl {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12), %edx
    shll $6, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %ecx
    movl %ecx, 68(%r10)
    FULLTRACER_ACCESS 64, 72, 1, .L_fulltracer_rs2_done
.L_fulltracer_rs2_skip:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_fulltracer_rd_skip
    movb $1, 46(%r10)
    movl {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12), %edx
    shll $6, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %ecx
    movl %ecx, 84(%r10)
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %ecx
    movl %ecx, 88(%r10)
    FULLTRACER_ACCESS 80, 96, 2, .L_fulltracer_rd_done
.L_fulltracer_rd_skip:
    testl $24, %edi
    je .L_fulltracer_mem_skip
    movb $1, 47(%r10)
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %ecx
    movl %ecx, 108(%r10)
    movl {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12), %ecx
    movl %ecx, 112(%r10)
    FULLTRACER_ACCESS 104, 120, 3, .L_fulltracer_mem_done

    leal (,%rdx,4), %esi
    leal 4(%rsi), %ecx
    cmpl {AOT_CTX_HEAP_START_OFFSET}(%r12), %esi
    jb .L_fulltracer_heap_done
    cmpl {AOT_CTX_HEAP_END_OFFSET}(%r12), %esi
    jae .L_fulltracer_heap_done
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8
    cmpl (%r8), %ecx
    jbe .L_fulltracer_heap_done
    movl %ecx, (%r8)
.L_fulltracer_heap_done:
    cmpl {AOT_CTX_HINTS_START_OFFSET}(%r12), %esi
    jb .L_fulltracer_hint_done
    cmpl {AOT_CTX_HINTS_END_OFFSET}(%r12), %esi
    jae .L_fulltracer_hint_done
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8
    cmpl (%r8), %ecx
    jbe .L_fulltracer_hint_done
    movl %ecx, (%r8)
.L_fulltracer_hint_done:
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 20(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 28(%r10)
.L_fulltracer_mem_skip:
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    movq (%r8), %rcx
    incq %rcx
    movq %rcx, (%r8)
    movq {AOT_CTX_FULLTRACER_LEN_OFFSET}(%r12), %r8
    movq %rcx, (%r8)
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10
    imulq $136, %rcx, %r9
    addq %r9, %r10
    movq (%r8), %rax
    movq %rax, 0(%r10)
    movl $0, 44(%r10)
    movl $-1, 128(%r10)
    movl $0, 132(%r10)
    ret
"#
    )?;
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
            insn,
            preflight_memory_bounds_updated,
            if matches!(
                trace_style,
                AssemblyTraceStyle::PreflightDirectBlockPlan
                    | AssemblyTraceStyle::PreflightDirectBlockPlanMemoryAtomicRegisters
            ) {
                PreflightAccessMode::BlockAtomic
            } else {
                PreflightAccessMode::Exact
            },
            matches!(trace_style, AssemblyTraceStyle::PreflightDirect),
        )?;
        emit_after_step(&mut file)?;
        return Ok(());
    }

    if trace_style == AssemblyTraceStyle::FullTracerDirect {
        let callback_label = format!(".L_fulltracer_callback_{pc:x}");
        let done_label = format!(".L_fulltracer_direct_done_{pc:x}");
        writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
        writeln!(file, "    movl %r15d, 8(%rsp)")?;
        writeln!(
            file,
            "    cmpl ${AOT_TRACE_MODE_FULLTRACER_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
        )?;
        writeln!(file, "    jne {callback_label}")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        writeln!(file, "    call L_fulltracer_emit_step")?;
        writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{callback_label}:")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        writeln!(file, "    movq %r12, %rdi")?;
        writeln!(file, "    call *%r14")?;
        writeln!(file, "{done_label}:")?;
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
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{no_trace_label}:")?;
    writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{direct_label}:")?;
    emit_preflight_direct_step_static(
        &mut file,
        pc,
        insn,
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
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "1:")?;
    Ok(())
}

fn emit_flush_preflight_event_cursor(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movq %rbx, {AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movq 56(%rsp), %rax\n    movq %rax, {AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET}(%r12)"
    )?;
    Ok(())
}

fn emit_reload_preflight_event_cursor(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET}(%r12), %rbx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET}(%r12), %rcx\n    movq %rcx, 56(%rsp)"
    )?;
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

/// Adaptive costing depends only on the statically known opcode mix. Blocks
/// whose memory address is computed inside the block can therefore retain
/// exact per-step access tracking while still using a block-entry cost guard.
/// Truly dynamic control flow and unsupported instructions stay on the Rust
/// fallback path.
fn block_supports_adaptive_cost_plan(program: &Program, block: &BasicBlock) -> Result<bool> {
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        if native_opcode_family(insn.kind).is_none() {
            return Ok(false);
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(true)
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

fn preflight_register_bit(reg_idx: u32) -> u64 {
    1u64 << reg_idx
}

fn initial_preflight_register_touched_mask(
    latest_cells: *const Cycle,
    current_shard_start: *const Cycle,
) -> (u64, Cycle) {
    if latest_cells.is_null() || current_shard_start.is_null() {
        return (0, 0);
    }
    let shard_start = unsafe { *current_shard_start };
    let mut mask = 0u64;
    for reg_idx in 0..VMState::<PreflightTracer>::REG_COUNT as u32 {
        let addr = reg_idx << 6;
        let cycle = unsafe { *latest_cells.add(addr as usize) };
        if cycle != 0 && cycle >= shard_start {
            mask |= preflight_register_bit(reg_idx);
        }
    }
    (mask, shard_start)
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

fn preflight_block_last_accesses(
    program: &Program,
    block: &BasicBlock,
) -> Result<Vec<PreflightBlockAccess>> {
    let mut last_accesses = BTreeMap::new();
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        let insn_cycle_offset = (pc - block.start_pc) as u64;
        for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
            last_accesses.insert(reg_idx << 6, insn_cycle_offset + subcycle.value());
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(last_accesses
        .into_iter()
        .map(|(addr, cycle_offset)| PreflightBlockAccess { addr, cycle_offset })
        .collect())
}

fn build_aot_block_cost_descriptors(
    program: &Program,
    blocks: &[BasicBlock],
    model: &ShardCostModel,
) -> Result<(Vec<AotBlockCostDescriptor>, Vec<AotChipContribution>)> {
    let mut descriptors = Vec::with_capacity(blocks.len());
    let mut contributions = Vec::new();
    let mut counts = vec![0u64; model.chip_count()];
    for block in blocks {
        let offset = contributions.len();
        // Compilation/setup only: a dense chip-indexed array avoids sorting
        // and guarantees stable descriptor order. Execution touches only the
        // resulting sparse descriptor, never a map.
        counts.fill(0);
        let mut pc = block.start_pc;
        while pc < block.end_pc {
            let insn = instruction_at(program, pc)?;
            for &chip in model.chips_for_step(insn.kind, None) {
                let chip = chip as usize;
                counts[chip] = counts[chip].saturating_add(1);
            }
            pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        }
        let mut standalone_trace_cells = 0u64;
        let mut standalone_main_peak = 0u64;
        let mut standalone_tower_peak = 0u64;
        for (chip, &count) in counts.iter().enumerate().filter(|(_, count)| **count != 0) {
            let cost = model.chip_cost(chip, count);
            standalone_trace_cells = standalone_trace_cells.saturating_add(cost.trace_cells);
            standalone_main_peak = standalone_main_peak.saturating_add(cost.main_peak);
            standalone_tower_peak = standalone_tower_peak.max(cost.tower_peak);
            contributions.push(AotChipContribution {
                chip_index: chip as u32,
                cost_row_byte_offset: (chip
                    * SHARD_COST_BUCKETS
                    * std::mem::size_of::<AotAdditiveCost>())
                    as u32,
                instance_delta: count,
            });
        }
        descriptors.push(AotBlockCostDescriptor {
            contribution_offset: offset as u32,
            contribution_count: (contributions.len() - offset) as u32,
            standalone_trace_cells,
            standalone_main_peak,
            standalone_tower_peak,
        });
    }
    Ok((descriptors, contributions))
}

fn emit_preflight_direct_block_budget_guard(
    mut file: impl Write,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    addq ${block_steps}, %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    ja L_exceptional")?;
    Ok(())
}

fn preflight_block_event_capacity(
    program: &Program,
    block: &BasicBlock,
    access_mode: PreflightAccessMode,
) -> Result<usize> {
    let mut memory_accesses = 0usize;
    let mut exact_register_accesses = 0usize;
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        exact_register_accesses += preflight_static_register_accesses(insn).len();
        memory_accesses += usize::from(
            native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
        );
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(memory_accesses
        + match access_mode {
            PreflightAccessMode::Exact => exact_register_accesses,
            PreflightAccessMode::BlockAtomic => {
                preflight_block_first_accesses(program, block)?.len()
            }
        })
}

fn emit_preflight_direct_block_event_capacity_guard(
    mut file: impl Write,
    program: &Program,
    block_idx: usize,
    block: &BasicBlock,
    access_mode: PreflightAccessMode,
) -> Result<()> {
    let event_capacity = preflight_block_event_capacity(program, block, access_mode)?;
    if event_capacity == 0 {
        return Ok(());
    }
    writeln!(file, ".L_preflight_block_capacity_retry_{block_idx}:")?;
    writeln!(file, "    leaq {}(%rbx), %rax", event_capacity * 24)?;
    writeln!(
        file,
        "    cmpq {AOT_CTX_PREFLIGHT_EVENT_END_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    jbe .L_preflight_block_capacity_ok_{block_idx}")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_GROW_TAPE}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(
        file,
        "    jmp .L_preflight_block_capacity_retry_{block_idx}"
    )?;
    writeln!(file, ".L_preflight_block_capacity_ok_{block_idx}:")?;
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
            writeln!(file, "    jne L_memory_guard")?;
        }
        InsnKind::LW | InsnKind::SW => {
            writeln!(file, "    testl $3, %edx")?;
            writeln!(file, "    jne L_memory_guard")?;
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
    writeln!(file, "    movl %edx, %eax")?;
    writeln!(file, "    shrl $2, %eax")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    jb L_memory_guard")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    jb {done_label}")?;
    writeln!(file, "    jmp L_memory_guard")?;
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
    let register_mask = accesses.iter().fold(0u64, |mask, access| {
        mask | preflight_register_bit(access.addr >> 6)
    });
    let all_touched_label = format!(".L_preflight_block_access_all_touched_{block_idx}");

    writeln!(file, "    movq 56(%rsp), %rax")?;
    writeln!(file, "    movabsq ${register_mask:#018x}, %rcx")?;
    writeln!(file, "    andq %rcx, %rax")?;
    writeln!(file, "    cmpq %rcx, %rax")?;
    writeln!(file, "    je {all_touched_label}")?;
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

    writeln!(file, "    xorq %rdi, %rdi")?;
    for (access_idx, access) in accesses.iter().enumerate() {
        let done_label = format!(".L_preflight_block_access_done_{block_idx}_{access_idx}");
        let event_label = format!(".L_preflight_block_access_event_{block_idx}_{access_idx}");
        let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{block_idx}_register_first_check_{access_idx}"),
        )?;
        writeln!(file, "    movq {offset}(%rdx), %r11")?;
        writeln!(file, "    testq %r11, %r11")?;
        writeln!(file, "    je {event_label}")?;
        writeln!(file, "    cmpq %r10, %r11")?;
        writeln!(file, "    jae {done_label}")?;
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{block_idx}_register_tape_append_{access_idx}"),
        )?;
        writeln!(file, "{event_label}:")?;
        writeln!(file, "    movq %r8, %rax")?;
        writeln!(file, "    addq ${}, %rax", access.cycle_offset)?;
        writeln!(file, "    movq %r11, 0(%rbx)")?;
        writeln!(file, "    movq %rax, 8(%rbx)")?;
        writeln!(file, "    movl ${}, 16(%rbx)", access.addr)?;
        writeln!(file, "    addq $24, %rbx")?;
        writeln!(file, "    testq %r11, %r11")?;
        writeln!(file, "    jne {done_label}")?;
        if cfg!(debug_assertions) {
            writeln!(
                file,
                "    movl ${}, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)",
                access.addr
            )?;
            writeln!(
                file,
                "    movl ${AOT_PREFLIGHT_HELPER_FIRST_TOUCH}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
            )?;
            emit_flush_preflight_event_cursor(&mut file)?;
            writeln!(file, "    movq %r12, %rdi")?;
            writeln!(file, "    call *%r14")?;
            emit_reload_preflight_event_cursor(&mut file)?;
            writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
            writeln!(file, "    je L_error")?;
            emit_preflight_direct_access_cache_load(&mut file)?;
            writeln!(file, "    xorq %rdi, %rdi")?;
        } else {
            writeln!(file, "    incq %rdi")?;
        }
        writeln!(file, "{done_label}:")?;
    }
    emit_assembly_profile_symbol(
        &mut file,
        &format!("ceno_aot_bb_{block_idx}_register_first_publish"),
    )?;
    if !cfg!(debug_assertions) {
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET}(%r12), %rsi"
        )?;
        writeln!(file, "    addq %rdi, (%rsi)")?;
    }
    writeln!(file, "    movabsq ${register_mask:#018x}, %rax")?;
    writeln!(file, "    orq %rax, 56(%rsp)")?;
    writeln!(file, "{all_touched_label}:")?;
    Ok(())
}

fn emit_preflight_direct_block_register_access_exit(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    let accesses = preflight_block_last_accesses(program, block)?;
    if accesses.is_empty() {
        return Ok(());
    }
    let block_cycles = block_instruction_count(block) * PC_STEP_SIZE as u64;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r8")?;
    for access in accesses {
        let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
        let from_end = block_cycles - access.cycle_offset;
        writeln!(file, "    leaq -{from_end}(%r8), %rax")?;
        writeln!(file, "    movq %rax, {offset}(%rdx)")?;
    }
    Ok(())
}

fn emit_preflight_adaptive_block_plan_entry(
    mut file: impl Write,
    block_idx: usize,
    block: &BasicBlock,
) -> Result<()> {
    let loop_label = format!(".L_preflight_cost_loop_{block_idx}");
    let loop_done_label = format!(".L_preflight_cost_loop_done_{block_idx}");
    let accept_label = format!(".L_preflight_cost_accept_{block_idx}");
    let first_shard_label = format!(".L_preflight_cost_first_shard_{block_idx}");
    let target_done_label = format!(".L_preflight_cost_target_done_{block_idx}");
    let split_label = format!(".L_preflight_cost_split_{block_idx}");
    let done_label = format!(".L_preflight_cost_done_{block_idx}");
    let block_cycles = block_instruction_count(block) * PC_STEP_SIZE as u64;
    let descriptor_offset = block_idx * std::mem::size_of::<AotBlockCostDescriptor>();
    let has_lzcnt = std::is_x86_feature_detected!("lzcnt");

    // Speculatively update all affected chip counts while accumulating trace
    // and main deltas and the largest absolute tower peak. The only loop
    // branch depends on descriptor size; bucket selection and max use cmov.
    writeln!(file, "    pxor %xmm0, %xmm0")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %rax")?;
    writeln!(file, "    movq %rax, 32(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    movl {descriptor_offset}(%r10), %eax")?;
    writeln!(file, "    movl {}(%r10), %ecx", descriptor_offset + 4)?;
    writeln!(file, "    shlq $4, %rax")?;
    writeln!(
        file,
        "    addq {AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq %rax, %r10")?;
    writeln!(file, "    testl %ecx, %ecx")?;
    writeln!(file, "    je {loop_done_label}")?;
    writeln!(file, "{loop_label}:")?;
    writeln!(file, "    movl (%r10), %eax")?;
    writeln!(file, "    movl 4(%r10), %edx")?;
    writeln!(file, "    movq %rdx, 40(%rsp)")?;
    writeln!(file, "    movq 8(%r10), %r11")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdi"
    )?;
    writeln!(file, "    leaq (%rdi,%rax,8), %rsi")?;
    writeln!(file, "    movq (%rsi), %r9")?;
    writeln!(file, "    addq %r9, %r11")?;
    writeln!(file, "    movq %r11, (%rsi)")?;
    // Point at this chip's precomputed cost-table row. Keeping the row
    // offset in the descriptor avoids two serialized multiplies per chip.
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET}(%r12), %rdi"
    )?;
    writeln!(file, "    addq %rdx, %rdi")?;
    if has_lzcnt {
        writeln!(file, "    leaq -1(%r9), %rdx")?;
        writeln!(file, "    lzcntq %rdx, %rdx")?;
        writeln!(file, "    movq $65, %r8")?;
        writeln!(file, "    subq %rdx, %r8")?;
        writeln!(file, "    testq %r9, %r9")?;
        writeln!(file, "    cmovz %r9, %r8")?;
        writeln!(file, "    movq %r8, %rdx")?;
        writeln!(file, "    leaq -1(%r11), %r9")?;
        writeln!(file, "    lzcntq %r9, %r9")?;
        writeln!(file, "    negq %r9")?;
        writeln!(file, "    addq $65, %r9")?;
    } else {
        writeln!(file, "    movq %r9, %rdx")?;
        writeln!(file, "    decq %rdx")?;
        writeln!(file, "    orq $1, %rdx")?;
        writeln!(file, "    bsrq %rdx, %rdx")?;
        writeln!(file, "    addq $2, %rdx")?;
        writeln!(file, "    movq $1, %r8")?;
        writeln!(file, "    cmpq $1, %r9")?;
        writeln!(file, "    cmovbe %r8, %rdx")?;
        writeln!(file, "    xorq %r8, %r8")?;
        writeln!(file, "    testq %r9, %r9")?;
        writeln!(file, "    cmovz %r8, %rdx")?;
        writeln!(file, "    movq %r11, %r9")?;
        writeln!(file, "    decq %r9")?;
        writeln!(file, "    orq $1, %r9")?;
        writeln!(file, "    bsrq %r9, %r9")?;
        writeln!(file, "    addq $2, %r9")?;
        writeln!(file, "    cmpq $1, %r11")?;
        writeln!(file, "    movq $1, %r8")?;
        writeln!(file, "    cmovbe %r8, %r9")?;
    }
    // Trace and main are adjacent table lanes. Accumulate both deltas in one
    // SIMD register, avoiding four scalar loads and stack updates per chip.
    writeln!(file, "    movq %rdx, %r8")?;
    writeln!(file, "    shlq $4, %r8")?;
    writeln!(file, "    movq %r9, %rax")?;
    writeln!(file, "    shlq $4, %rax")?;
    writeln!(file, "    movdqu (%rdi,%r8), %xmm1")?;
    writeln!(file, "    movdqu (%rdi,%rax), %xmm2")?;
    writeln!(file, "    psubq %xmm1, %xmm2")?;
    writeln!(file, "    paddq %xmm2, %xmm0")?;
    // Tower tasks do not coexist across chips: retain only the largest new
    // absolute per-chip peak, rather than summing tower deltas.
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_TOWER_COST_TABLE_OFFSET}(%r12), %rdi"
    )?;
    writeln!(file, "    movq 40(%rsp), %r8")?;
    writeln!(file, "    shrq $1, %r8")?;
    writeln!(file, "    addq %r8, %rdi")?;
    writeln!(file, "    movq (%rdi,%r9,8), %rax")?;
    writeln!(file, "    movq 32(%rsp), %r8")?;
    writeln!(file, "    cmpq %r8, %rax")?;
    writeln!(file, "    cmovaq %rax, %r8")?;
    writeln!(file, "    movq %r8, 32(%rsp)")?;
    writeln!(file, "    addq $16, %r10")?;
    writeln!(file, "    decl %ecx")?;
    writeln!(file, "    jne {loop_label}")?;
    writeln!(file, "{loop_done_label}:")?;
    writeln!(file, "    movdqu %xmm0, 16(%rsp)")?;
    // candidate = trace_total + max(main_total, tower_peak)
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TRACE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r9")?;
    writeln!(file, "    addq 16(%rsp), %r9")?;
    writeln!(file, "    movq %r9, 16(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_MAIN_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r11")?;
    writeln!(file, "    addq 24(%rsp), %r11")?;
    writeln!(file, "    movq %r11, 24(%rsp)")?;
    writeln!(file, "    movq 32(%rsp), %r8")?;
    writeln!(file, "    cmpq %r8, %r11")?;
    writeln!(file, "    cmovbq %r8, %r11")?;
    writeln!(file, "    addq %r11, %r9")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    cmpq $0, (%r10)")?;
    writeln!(file, "    je {accept_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_SHARD_ID_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    cmpq $0, (%r10)")?;
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
    writeln!(file, "    cmpq %r10, %r9")?;
    writeln!(file, "    ja {split_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    movq (%r10), %r11")?;
    writeln!(file, "    addq ${block_cycles}, %r11")?;
    writeln!(
        file,
        "    cmpq {AOT_CTX_PREFLIGHT_MAX_CYCLE_PER_SHARD_OFFSET}(%r12), %r11"
    )?;
    writeln!(file, "    jae {split_label}")?;
    writeln!(file, "{accept_label}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CELLS_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq %r9, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TRACE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq 16(%rsp), %r8")?;
    writeln!(file, "    movq %r8, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_MAIN_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq 24(%rsp), %r8")?;
    writeln!(file, "    movq %r8, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq 32(%rsp), %r8")?;
    writeln!(file, "    movq %r8, (%rax)")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{split_label}:")?;
    writeln!(
        file,
        "    movq ${block_idx}, {AOT_CTX_PREFLIGHT_PENDING_BLOCK_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_SHARD_SPLIT}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_block_plan_exit(mut file: impl Write, block: &BasicBlock) -> Result<()> {
    let block_steps = block_instruction_count(block);
    let block_cycles = block_steps * PC_STEP_SIZE as u64;
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

fn emit_preflight_adaptive_exact_access_plan_exit(
    mut file: impl Write,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    let block_cycles = block_steps * PC_STEP_SIZE as u64;
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
    insn: Instruction,
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
            if has_memory_access {
                emit_preflight_direct_access_cache_load(&mut file)?;
                writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                emit_preflight_direct_access_cached(&mut file, "%eax", PreflightSubcycle::Mem)?;
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
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
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

fn emit_preflight_direct_event_append(
    mut file: impl Write,
    source_reg: &str,
    target_reg: &str,
    addr_reg: &str,
) -> Result<()> {
    writeln!(file, "    movq {source_reg}, 0(%rbx)")?;
    writeln!(file, "    movq {target_reg}, 8(%rbx)")?;
    writeln!(file, "    movl {addr_reg}, 16(%rbx)")?;
    writeln!(file, "    addq $24, %rbx")?;
    writeln!(file, "    testq {source_reg}, {source_reg}")?;
    writeln!(file, "    jne 4f")?;
    if cfg!(debug_assertions) {
        writeln!(
            file,
            "    movl ${AOT_PREFLIGHT_HELPER_FIRST_TOUCH}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movq %r12, %rdi")?;
        emit_flush_preflight_event_cursor(&mut file)?;
        writeln!(file, "    call *%r14")?;
        emit_reload_preflight_event_cursor(&mut file)?;
        writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
        writeln!(file, "    je L_error")?;
        emit_preflight_direct_access_cache_load(&mut file)?;
    } else {
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET}(%r12), %rsi"
        )?;
        writeln!(file, "    incq (%rsi)")?;
    }
    writeln!(file, "4:")?;
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
    emit_preflight_direct_event_append(&mut file, "%r11", "%r9", "%ecx")?;
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
    emit_preflight_direct_event_append(&mut file, "%r11", "%rax", &format!("${addr}"))?;
    writeln!(file, "2:")?;
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
        None => emit_call_one(
            &mut file,
            pc,
            if insn.kind == InsnKind::ECALL {
                AOT_FALLBACK_ECALL
            } else {
                AOT_FALLBACK_EXCEPTIONAL
            },
        ),
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
        emit_call_one(&mut file, pc, AOT_FALLBACK_EXCEPTIONAL)?;
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
    let dense_ok_label = format!(".L_memory_dense_ok_{pc:x}");
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
    writeln!(file, "    movl %edx, %eax")?;
    writeln!(file, "    shrl $2, %eax")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    jb {slow_label}")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    jb {dense_ok_label}")?;
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

    writeln!(file, "{dense_ok_label}:")?;
    writeln!(file, "    movl %edx, %r8d")?;
    writeln!(file, "    andl $3, %r8d")?;
    writeln!(file, "    shll $3, %r8d")?;
    writeln!(file, "    shrl $2, %edx")?;
    writeln!(file, "    movl %edx, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
    writeln!(file, "    jmp {body_label}")?;

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
    emit_call_one(&mut file, pc, AOT_FALLBACK_MEMORY_GUARD)?;
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
    next_block_pc: Option<u32>,
    pc: u32,
    insn: Instruction,
) -> Result<()> {
    let successors = static_successors(program, pc, insn)?;
    let adjacent = next_block_pc.filter(|next| successors.contains(next));
    for &successor in successors
        .iter()
        .filter(|successor| Some(**successor) != adjacent)
    {
        if let Some(label) = labels.get(&successor) {
            writeln!(file, "    cmpl ${successor:#010x}, %r15d")?;
            writeln!(file, "    je {label}")?;
        }
    }
    if let Some(adjacent) = adjacent {
        if is_static_conditional_branch(insn.kind) {
            writeln!(file, "    cmpl ${adjacent:#010x}, %r15d")?;
            writeln!(file, "    jne L_dispatch")?;
        }
        return Ok(());
    }
    writeln!(file, "    jmp L_dispatch")?;
    Ok(())
}

#[inline(always)]
unsafe extern "C" fn aot_exec_one<T: Tracer>(
    context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let context = unsafe { &mut *(context as *mut AotRuntimeContext) };
    let vm = unsafe { &mut *(context.vm as *mut VMState<T>) };
    context.fallback_steps += 1;
    let reason = if context.fallback_reason == AOT_FALLBACK_DYNAMIC_PC
        && context.fallback_recovery_reason != 0
    {
        context.fallback_recovery_reason
    } else {
        context.fallback_reason
    };
    if reason != AOT_FALLBACK_DYNAMIC_PC {
        context.fallback_recovery_reason = reason;
    }
    match reason {
        AOT_FALLBACK_DYNAMIC_PC => context.fallback_dynamic_pc += 1,
        AOT_FALLBACK_MEMORY_GUARD => context.fallback_memory_guard += 1,
        AOT_FALLBACK_ECALL => {
            context.fallback_ecall += 1;
            let code = vm.peek_register(Platform::reg_ecall());
            unsafe { &mut *context.fallback_ecall_codes }
                .entry(code)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
        AOT_FALLBACK_EXCEPTIONAL => context.fallback_exceptional += 1,
        other => {
            LAST_AOT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(anyhow!("unknown AOT fallback reason {other}"))
            });
            return AOT_STATUS_ERROR;
        }
    }
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

    if context.trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
        let preflight_vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
        (context.preflight_event_cursor, context.preflight_event_end) =
            preflight_vm.tracer_mut().native_next_access_ptrs();
        let shard_start = unsafe { *context.preflight_current_shard_start };
        if shard_start != context.preflight_register_shard_start {
            context.preflight_register_touched_mask = 0;
            context.preflight_register_shard_start = shard_start;
        }
    }

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

/// Stable symbol covering the Rust fallback path, including syscall bodies.
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn ceno_aot_preflight_fallback_callback(
    context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    unsafe { aot_exec_one::<PreflightTracer>(context, pc, next_pc) }
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

    let step = NativeTraceStep {
        pc_before: ByteAddr(context.trace_pc),
        pc_after: ByteAddr(context.trace_next_pc),
        kind: native_trace_kind(context.trace_kind),
        flags: context.trace_flags,
        rs1_idx: context.trace_rs1_idx as RegIdx,
        rs2_idx: context.trace_rs2_idx as RegIdx,
        rd_idx: context.trace_rd_idx as RegIdx,
        memory_addr: WordAddr(context.trace_mem_addr),
    };
    let busy_loop = vm.trace_preflight_native_step(step);
    if busy_loop && !vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!("Stuck in loop {}", "{}")));
        AOT_STATUS_ERROR
    } else {
        AOT_STATUS_CONTINUE
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn ceno_aot_preflight_direct_callback(context: *mut AotRuntimeContext) -> u32 {
    let context = unsafe { &mut *context };
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    if !context.preflight_event_cursor.is_null() {
        unsafe {
            vm.tracer_mut()
                .sync_native_next_access_tape(context.preflight_event_cursor)
        };
    }
    if vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        return AOT_STATUS_HALTED;
    }

    let status = match context.preflight_helper_kind {
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
            let adaptive_descriptor = (!context.preflight_block_cost_descriptors.is_null()
                && context.preflight_pending_block != usize::MAX)
                .then(|| unsafe {
                    *context
                        .preflight_block_cost_descriptors
                        .add(context.preflight_pending_block)
                });
            if let Some(descriptor) = adaptive_descriptor {
                // Restore the accepted shard's counts before finalizing it;
                // the native entry speculatively stored this block's candidate.
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                let contributions = unsafe {
                    std::slice::from_raw_parts(
                        context
                            .preflight_chip_contributions
                            .add(descriptor.contribution_offset as usize),
                        descriptor.contribution_count as usize,
                    )
                };
                for contribution in contributions {
                    counts[contribution.chip_index as usize] = counts
                        [contribution.chip_index as usize]
                        .saturating_sub(contribution.instance_delta);
                }
            }
            vm.tracer_mut().record_native_shard_split();
            if let Some(descriptor) = adaptive_descriptor {
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                let contributions = unsafe {
                    std::slice::from_raw_parts(
                        context
                            .preflight_chip_contributions
                            .add(descriptor.contribution_offset as usize),
                        descriptor.contribution_count as usize,
                    )
                };
                for contribution in contributions {
                    counts[contribution.chip_index as usize] = contribution.instance_delta;
                }
                unsafe {
                    *context.preflight_planner_cur_trace_cells = descriptor.standalone_trace_cells;
                    *context.preflight_planner_cur_main_peak = descriptor.standalone_main_peak;
                    *context.preflight_planner_cur_tower_peak = descriptor.standalone_tower_peak;
                    *context.preflight_planner_cur_cells =
                        descriptor.standalone_trace_cells.saturating_add(
                            descriptor
                                .standalone_main_peak
                                .max(descriptor.standalone_tower_peak),
                        );
                }
                context.preflight_pending_block = usize::MAX;
            }
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_FIRST_TOUCH => {
            vm.tracer_mut()
                .record_native_first_touch(WordAddr(context.preflight_event_addr));
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_GROW_TAPE => {
            let (old_capacity, new_capacity) = vm.tracer_mut().grow_native_next_access_tape();
            tracing::warn!(
                "AOT next-access tape grew from {old_capacity} to {new_capacity} events"
            );
            AOT_STATUS_CONTINUE
        }
        other => {
            LAST_AOT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(anyhow!("unknown AOT Preflight helper kind {other}"))
            });
            AOT_STATUS_ERROR
        }
    };
    (context.preflight_event_cursor, context.preflight_event_end) =
        vm.tracer_mut().native_next_access_ptrs();
    let shard_start = unsafe { *context.preflight_current_shard_start };
    if shard_start != context.preflight_register_shard_start {
        context.preflight_register_touched_mask = 0;
        context.preflight_register_shard_start = shard_start;
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CENO_PLATFORM, ChipCostSpec, EmuContext, ShardCostModel, encode_rv32};
    use std::sync::Arc;
    use strum::EnumCount;

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
    fn coverage_roots_include_entry_and_observed_jump_target() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JAL, 0, 0, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let roots = trace_preflight_roots(&CENO_PLATFORM, program, []).unwrap();

        assert_eq!(roots[0], base);
        assert!(roots.contains(&(base + 8)));
    }

    #[test]
    fn coverage_training_counts_instructions_and_branch_directions() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let training = trace_preflight_profile(&CENO_PLATFORM, program.clone(), []).unwrap();
        assert_eq!(training.instruction_counts, vec![1, 3, 3, 1]);
        assert_eq!(
            training.branch_counts[2],
            BranchCounts {
                taken: 2,
                not_taken: 1,
            }
        );

        let blocks = partition_basic_blocks_with_roots(&program, training.roots.clone()).unwrap();
        let layout = build_layout_profile(&program, &blocks, &training).unwrap();
        assert_eq!(layout.block_counts, vec![1, 3, 1]);
        assert_eq!(layout.edge_counts[&(base, base + 4)], 1);
        assert_eq!(layout.edge_counts[&(base + 4, base + 4)], 2);
        assert_eq!(layout.edge_counts[&(base + 4, base + 12)], 1);
    }

    #[test]
    fn hot_chains_are_deterministic_and_do_not_form_cycles() {
        let blocks = (0..4)
            .map(|index| BasicBlock {
                start_pc: 0x1000 + index * 4,
                end_pc: 0x1004 + index * 4,
            })
            .collect::<Vec<_>>();
        let edges = BTreeMap::from([
            ((0x1000, 0x1004), 30),
            ((0x1004, 0x1008), 20),
            ((0x1008, 0x1000), 10),
        ]);

        let first = hot_chain_emission_order(&blocks, &[30, 20, 10, 0], &edges);
        let second = hot_chain_emission_order(&blocks, &[30, 20, 10, 0], &edges);
        assert_eq!(first, second);
        assert_eq!(first, vec![0x1000, 0x1004, 0x1008, 0x100c]);
        assert_eq!(first.iter().copied().collect::<BTreeSet<_>>().len(), 4);
    }

    #[test]
    fn cache_metadata_round_trips_layout_digest_and_emission_order() {
        let profile = AotLayoutProfile {
            block_counts: vec![9, 4, 0],
            edge_counts: BTreeMap::from([((0x1000, 0x1008), 7)]),
            emission_order: vec![0x1000, 0x1008, 0x1004],
            digest: [0x5a; 32],
        };
        let artifact_digest = [0xa5; 32];
        let event_count = 17;
        let event_capacity = next_access_capacity(event_count);
        let encoded = encode_cache_metadata(
            "test-key",
            &artifact_digest,
            &[0x1000, 0x1008],
            &profile,
            event_count,
            event_capacity,
        );

        let (decoded_artifact, roots, capacity, profile_digest, emission_order) =
            decode_cache_metadata(&encoded, "test-key").unwrap();
        assert_eq!(decoded_artifact, artifact_digest);
        assert_eq!(roots, vec![0x1000, 0x1008]);
        assert_eq!(capacity, event_capacity);
        assert_eq!(profile_digest, profile.digest);
        assert_eq!(emission_order, profile.emission_order);
    }

    #[test]
    fn successor_emission_falls_through_to_adjacent_hot_edge() {
        let base = CENO_PLATFORM.pc_base();
        let program = program(vec![
            encode_rv32(InsnKind::BNE, 1, 0, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);
        let labels = BTreeMap::from([
            (base + 4, "L_cold".to_owned()),
            (base + 8, "L_hot".to_owned()),
        ]);
        let mut conditional = Vec::new();
        emit_successor_jump(
            &mut conditional,
            &program,
            &labels,
            Some(base + 8),
            base,
            program.instructions[0],
        )
        .unwrap();
        let conditional = String::from_utf8(conditional).unwrap();
        assert!(conditional.contains("je L_cold"));
        assert!(!conditional.contains("je L_hot"));
        assert!(conditional.contains("jne L_dispatch"));

        let jump = encode_rv32(InsnKind::JAL, 0, 0, 0, 8);
        let mut unconditional = Vec::new();
        emit_successor_jump(
            &mut unconditional,
            &program,
            &labels,
            Some(base + 8),
            base,
            jump,
        )
        .unwrap();
        assert!(unconditional.is_empty());
    }

    #[test]
    fn coverage_roots_include_late_indirect_target_and_post_ecall_continuation() {
        let base = CENO_PLATFORM.pc_base();
        let indirect = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let mut vm = VMState::<CoverageTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            indirect.clone(),
            CoverageTracerConfig {
                entry: base,
                program_base: indirect.base_address,
                instruction_count: indirect.instructions.len(),
            },
        );
        vm.init_register_unsafe(1, base + 16);
        while vm.next_step_record().unwrap().is_some() {}
        let roots = &vm.tracer().roots;
        assert!(roots.contains(&(base + 16)), "roots={roots:#x?}");

        let mut platform = CENO_PLATFORM.clone();
        platform.unsafe_ecall_nop = true;
        let post_ecall = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_ecall().into(), 123),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_ecall().into(), 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let roots = trace_preflight_roots(&platform, post_ecall, []).unwrap();
        assert!(roots.contains(&(base + 8)));
    }

    #[test]
    fn coverage_roots_preserve_canonical_whole_blocks() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ADDI, 1, 0, 2, 2),
            encode_rv32(InsnKind::ADDI, 2, 0, 3, 3),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let roots = trace_preflight_roots(&CENO_PLATFORM, program.clone(), []).unwrap();
        let blocks = partition_basic_blocks_with_roots(&program, roots).unwrap();
        assert_eq!(
            blocks[0],
            BasicBlock {
                start_pc: base,
                end_pc: base + 12
            }
        );
        assert_eq!(blocks.len(), 2);
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
            vec![
                BasicBlock {
                    start_pc: base,
                    end_pc: base + 4,
                },
                BasicBlock {
                    start_pc: base + 4,
                    end_pc: base + 8,
                },
            ]
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
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_block_cost_descriptors),
            AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_chip_contributions),
            AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_cost_table),
            AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_num_instances),
            AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_num_chips),
            AOT_CTX_PREFLIGHT_NUM_CHIPS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_block),
            AOT_CTX_PREFLIGHT_PENDING_BLOCK_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_planner_cur_trace_cells),
            AOT_CTX_PREFLIGHT_PLANNER_CUR_TRACE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_planner_cur_main_peak),
            AOT_CTX_PREFLIGHT_PLANNER_CUR_MAIN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_planner_cur_tower_peak),
            AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_tower_cost_table),
            AOT_CTX_PREFLIGHT_TOWER_COST_TABLE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_dynamic_pc),
            AOT_CTX_FALLBACK_DYNAMIC_PC_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_memory_guard),
            AOT_CTX_FALLBACK_MEMORY_GUARD_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_ecall),
            AOT_CTX_FALLBACK_ECALL_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_exceptional),
            AOT_CTX_FALLBACK_EXCEPTIONAL_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_reason),
            AOT_CTX_FALLBACK_REASON_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_ecall_codes),
            AOT_CTX_FALLBACK_ECALL_CODES_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fallback_recovery_reason),
            AOT_CTX_FALLBACK_RECOVERY_REASON_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_event_cursor),
            AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_event_end),
            AOT_CTX_PREFLIGHT_EVENT_END_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_latest_len),
            AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, memory_end_word),
            AOT_CTX_MEMORY_END_WORD_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_records),
            AOT_CTX_FULLTRACER_RECORDS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_len),
            AOT_CTX_FULLTRACER_LEN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_pending_index),
            AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_pending_cycle),
            AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_latest_cells),
            AOT_CTX_FULLTRACER_LATEST_CELLS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_latest_base),
            AOT_CTX_FULLTRACER_LATEST_BASE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_latest_len),
            AOT_CTX_FULLTRACER_LATEST_LEN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_max_heap),
            AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, fulltracer_max_hint),
            AOT_CTX_FULLTRACER_MAX_HINT_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_register_touched_mask),
            AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_register_shard_start),
            AOT_CTX_PREFLIGHT_REGISTER_SHARD_START_OFFSET
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

    #[test]
    fn aot_preflight_direct_grows_tape_without_changing_accesses() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
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

        let mut aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        aot.next_access_capacity = 1;
        let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert!(report.next_access_growths > 0);
        assert!(report.next_access_growth_bytes > 0);
        assert!(report.next_access_capacity > 1);
        let (interp_plan, interp_next) = interp.take_tracer().into_shard_plan();
        let (aot_plan, aot_next) = aot_vm.take_tracer().into_shard_plan();
        assert_eq!(aot_next, interp_next);
        assert_eq!(
            aot_plan.shard_cycle_boundaries(),
            interp_plan.shard_cycle_boundaries()
        );
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

        fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
            let mut opcodes = vec![vec![0]; InsnKind::COUNT];
            opcodes[InsnKind::ECALL as usize].clear();
            let mut ecalls = BTreeMap::new();
            ecalls.insert(Platform::ecall_halt(), vec![0]);
            Some(Arc::new(ShardCostModel::new(
                opcodes,
                ecalls,
                vec![ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 1,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                }],
                1,
            )))
        }
    }

    #[test]
    fn cached_aot_hit_and_corrupt_rebuild_match_preflight_state() {
        let cache = tempfile::tempdir().unwrap();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ADDI, 1, 0, 2, 9),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));

        let cold = AotProgram::load_or_train_preflight_in(
            &CENO_PLATFORM,
            program.clone(),
            [],
            config.clone(),
            cache.path(),
        )
        .unwrap();
        let warm = AotProgram::load_or_train_preflight_in(
            &CENO_PLATFORM,
            program.clone(),
            [],
            config.clone(),
            cache.path(),
        )
        .unwrap();
        let mut cold_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        let mut warm_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        let cold_report = cold.run_to_halt(&mut cold_vm, 10).unwrap();
        let warm_report = warm.run_to_halt(&mut warm_vm, 10).unwrap();
        assert_eq!(cold_report.executed_steps, warm_report.executed_steps);
        assert_eq!(cold_report.fallback, warm_report.fallback);
        assert_eq!(cold_report.fallback.dynamic_pc_miss, 0);
        assert_eq!(
            cold_report
                .fallback
                .ecall_by_code
                .get(&Platform::ecall_halt()),
            Some(&1)
        );
        for idx in 0..VMState::<crate::PreflightTracer>::REG_COUNT as u8 {
            assert_eq!(cold_vm.peek_register(idx), warm_vm.peek_register(idx));
        }
        for addr in cold_vm.tracer().final_accesses().addresses() {
            assert_eq!(
                cold_vm.tracer().final_accesses().cycle(*addr),
                warm_vm.tracer().final_accesses().cycle(*addr)
            );
        }
        let (cold_plan, cold_next) = cold_vm.take_tracer().into_shard_plan();
        let (warm_plan, warm_next) = warm_vm.take_tracer().into_shard_plan();
        assert_eq!(cold_next, warm_next);
        assert_eq!(
            cold_plan.shard_cycle_boundaries(),
            warm_plan.shard_cycle_boundaries()
        );
        let expected_steps = warm_report.executed_steps;
        let expected_fallback = warm_report.fallback.clone();
        drop(cold);
        drop(warm);

        let key = format!(
            "{}-cells{}-cycles{}",
            aot_cache_key(&program, AssemblyTraceStyle::PreflightDirectBlockPlan),
            config.max_cell_per_shard(),
            config.max_cycle_per_shard()
        );
        let (so_path, _) = cache_paths(cache.path(), &key);
        fs::write(&so_path, b"corrupt").unwrap();
        let rebuilt = AotProgram::load_or_train_preflight_in(
            &CENO_PLATFORM,
            program.clone(),
            [],
            config.clone(),
            cache.path(),
        )
        .unwrap();
        let mut rebuilt_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        let rebuilt_report = rebuilt.run_to_halt(&mut rebuilt_vm, 10).unwrap();
        assert_eq!(rebuilt_report.executed_steps, expected_steps);
        assert_eq!(rebuilt_report.fallback, expected_fallback);
        drop(rebuilt);

        let (_, metadata_path) = cache_paths(cache.path(), &key);
        let metadata = fs::read_to_string(&metadata_path).unwrap();
        fs::write(
            &metadata_path,
            metadata.replacen(&key, "wrong-program-or-abi", 1),
        )
        .unwrap();
        let identity_rebuilt = AotProgram::load_or_train_preflight_in(
            &CENO_PLATFORM,
            program.clone(),
            [],
            config.clone(),
            cache.path(),
        )
        .unwrap();
        let mut identity_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let identity_report = identity_rebuilt.run_to_halt(&mut identity_vm, 10).unwrap();
        assert_eq!(identity_report.executed_steps, expected_steps);
    }

    #[test]
    fn unseen_later_indirect_target_uses_dynamic_pc_fallback() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), vec![base + 4])
                .unwrap();
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        vm.init_register_unsafe(1, base + 8);
        let report = aot.run_to_halt(&mut vm, 10).unwrap();
        assert_eq!(report.fallback.dynamic_pc_miss, 1);
    }

    #[derive(Debug)]
    struct AdaptiveTestCost(Arc<ShardCostModel>);

    impl AdaptiveTestCost {
        fn new() -> Self {
            let mut opcodes = vec![Vec::new(); InsnKind::COUNT];
            opcodes[InsnKind::ADDI as usize] = vec![0];
            opcodes[InsnKind::ADD as usize] = vec![1];
            opcodes[InsnKind::JAL as usize] = vec![2];
            let mut ecalls = BTreeMap::new();
            ecalls.insert(Platform::ecall_halt(), vec![3]);
            Self(Arc::new(ShardCostModel::new(
                opcodes,
                ecalls,
                vec![
                    ChipCostSpec {
                        rotation: 0,
                        trace_cells_per_row: 1,
                        tower_peak_cells_per_row: 0,
                        tower_peak_cells_by_bucket: None,
                    },
                    ChipCostSpec {
                        rotation: 0,
                        trace_cells_per_row: 1,
                        tower_peak_cells_per_row: 8,
                        tower_peak_cells_by_bucket: None,
                    },
                    ChipCostSpec {
                        rotation: 0,
                        trace_cells_per_row: 1,
                        tower_peak_cells_per_row: 0,
                        tower_peak_cells_by_bucket: None,
                    },
                    ChipCostSpec {
                        rotation: 0,
                        trace_cells_per_row: 1,
                        tower_peak_cells_per_row: 0,
                        tower_peak_cells_by_bucket: None,
                    },
                ],
                4,
            )))
        }
    }

    impl crate::StepCellExtractor for AdaptiveTestCost {
        fn cells_for_kind(&self, _kind: InsnKind, _rs1_value: Option<Word>) -> u64 {
            0
        }

        fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
            Some(self.0.clone())
        }
    }

    fn adaptive_test_program() -> Arc<Program> {
        Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
            encode_rv32(InsnKind::JAL, 0, 0, 0, 4),
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
            encode_rv32(InsnKind::ADD, 2, 3, 4, 0),
            encode_rv32(InsnKind::JAL, 0, 0, 0, 4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]))
    }

    #[test]
    fn aot_adaptive_cost_splits_before_blocks_and_reinitializes_rejected_block() {
        let program = adaptive_test_program();
        // The first block exactly fills the limit and must be accepted. The
        // second block is oversized on an empty shard and must also run once.
        let config = crate::PreflightTracerConfig::new(true, 7, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(AdaptiveTestCost::new()));
        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let report = aot.run_to_halt(&mut vm, 100).unwrap();
        let (plan, _) = vm.take_tracer().into_shard_plan();
        assert_eq!(plan.shard_cycle_boundaries(), &[4, 16, 28, 32]);
        assert_eq!(plan.predicted_shard_costs(), &[7, 19, 1]);
        assert_eq!(report.fallback.dynamic_pc_miss, 0);
    }

    #[test]
    fn aot_adaptive_cost_honors_cycle_limit_at_block_boundaries() {
        let program = adaptive_test_program();
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, 16)
            .with_step_cell_extractor(Arc::new(AdaptiveTestCost::new()));
        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        aot.run_to_halt(&mut vm, 100).unwrap();
        let (plan, _) = vm.take_tracer().into_shard_plan();
        assert_eq!(plan.shard_cycle_boundaries(), &[4, 16, 28, 32]);
        assert_eq!(plan.predicted_shard_costs(), &[7, 19, 1]);
    }

    #[test]
    fn preflight_block_aot_requires_shard_cost_model() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::ADDI, 0, 0, 1, 1)]));
        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        let mut vm =
            VMState::<crate::PreflightTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);

        let err = aot.run_to_halt(&mut vm, 10).unwrap_err().to_string();
        assert!(err.contains("preflight block AOT requires a shard cost model"));
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
    fn preflight_register_mask_covers_internal_x0_sink() {
        assert_eq!(preflight_register_bit(32), 1u64 << 32);
    }

    #[test]
    fn initial_register_touched_mask_is_shard_local() {
        let mut latest = vec![0; (VMState::<PreflightTracer>::REG_COUNT - 1) * 64 + 1];
        latest[1 << 6] = 9;
        latest[2 << 6] = 10;
        latest[32 << 6] = 12;
        let shard_start = 10;

        let (mask, observed_start) =
            initial_preflight_register_touched_mask(latest.as_ptr(), &shard_start);

        assert_eq!(observed_start, shard_start);
        assert_eq!(mask, (1u64 << 2) | (1u64 << 32));
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
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        aot_vm.init_register_unsafe(20, base);

        let err = aot.run_to_halt(&mut aot_vm, 10).unwrap_err().to_string();

        assert!(err.contains("LoadAddressMisaligned"));
    }

    #[test]
    fn dense_non_mmio_memory_stays_native() {
        let data_addr = CENO_PLATFORM.heap.end;
        let mut platform = CENO_PLATFORM.clone();
        platform.prog_data = Arc::new(BTreeSet::from([data_addr]));
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 2, 1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let aot =
            AotProgram::compile_preflight_direct_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let mut vm =
            VMState::<crate::PreflightTracer>::new_with_tracer_config(platform, program, config);
        vm.init_register_unsafe(20, data_addr);
        vm.init_memory(ByteAddr(data_addr).waddr(), 41);

        let report = aot.run_to_halt(&mut vm, 10).unwrap();

        assert_eq!(vm.peek_register(2), 42);
        assert_eq!(report.fallback.dynamic_pc_miss, 0);
        assert_eq!(report.fallback.memory_guard, 0);
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

    #[test]
    #[cfg(not(debug_assertions))]
    fn fulltracer_direct_records_match_interpreter() {
        let base = CENO_PLATFORM.stack.start + 64;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
            encode_rv32(InsnKind::SW, 20, 2, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::BEQ, 2, 3, 0, 4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::FullTracerConfig { max_step_shard: 16 };

        let mut interp = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config,
        );
        interp.init_register_unsafe(20, base);
        interp.init_memory(ByteAddr(base).waddr(), 0);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let mut direct = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        direct.init_register_unsafe(20, base);
        direct.init_memory(ByteAddr(base).waddr(), 0);
        let report = aot.run_to_halt(&mut direct, 16).unwrap();

        assert_eq!(report.fallback_steps, 1, "only the halt ecall falls back");
        assert_eq!(direct.peek_register(3), interp.peek_register(3));
        assert_eq!(direct.peek_memory(ByteAddr(base).waddr()), 10);
        assert_eq!(
            direct.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
        assert_eq!(
            direct.tracer().syscall_witnesses(),
            interp.tracer().syscall_witnesses()
        );
    }
}
