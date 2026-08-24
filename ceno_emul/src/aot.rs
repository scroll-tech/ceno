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
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use strum::EnumCount;
use tiny_keccak::{Hasher, Keccak};

mod assembly;
mod cache;
mod runtime;
#[cfg(test)]
mod tests;

use assembly::*;
use cache::*;
use runtime::*;

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
    /// Benchmark-only value execution with no trace or access bookkeeping.
    Pure,
    /// Pure execution inside an entry-guarded block. The caller has proved
    /// that the complete block fits the remaining instruction budget and all
    /// memory accesses are valid, so steps are reserved once at block entry.
    PureBlock,
    /// Pure execution in a block whose instruction budget is reserved at
    /// entry, while dynamic memory guards remain exact.
    PureCountedBlock,
    /// Native code emits ordinary `GpuReplayTracer` rows directly into the
    /// current preallocated typed-SoA range. The same image retains the
    /// FullTracer direct lane for the environment-gated CPU control.
    GpuReplayDirect,
    /// Native code updates `PreflightTracer` state directly for per-step access
    /// accounting, avoiding the generic callback value path.
    PreflightScalar,
    /// Native code additionally maintains shard planner counters for blocks
    /// that have statically known access cost.
    PreflightAdmittedRegisterBlock,
    /// Exact dynamic-memory tracking with block-atomic static registers.
    PreflightAdmittedMemoryBlock,
    /// Production preflight execution. Block admission selects the private
    /// register-only, memory, or scalar emission strategy per block.
    PreflightProduction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreflightFeature {
    RegisterLatest,
    MemoryLatest,
    MmioBounds,
    EventCapacity,
    RegisterEvents,
    MemoryEvents,
}

impl AssemblyTraceStyle {
    fn needs_callback_values(self) -> bool {
        self == Self::GpuReplayDirect
    }

    fn is_pure(self) -> bool {
        matches!(self, Self::Pure | Self::PureBlock | Self::PureCountedBlock)
    }

    fn is_preflight_direct(self) -> bool {
        matches!(
            self,
            Self::PreflightScalar
                | Self::PreflightAdmittedRegisterBlock
                | Self::PreflightAdmittedMemoryBlock
                | Self::PreflightProduction
        )
    }

    fn uses_preflight_block_plan(self) -> bool {
        matches!(
            self,
            Self::PreflightAdmittedRegisterBlock
                | Self::PreflightAdmittedMemoryBlock
                | Self::PreflightProduction
        )
    }

    fn carries_next_pc_in_register(self) -> bool {
        self.is_pure()
    }

    fn preflight_feature_enabled(self, feature: PreflightFeature) -> bool {
        !(matches!(
            self,
            Self::PreflightProduction
                | Self::PreflightScalar
                | Self::PreflightAdmittedRegisterBlock
                | Self::PreflightAdmittedMemoryBlock
        ) && feature == PreflightFeature::MmioBounds)
    }

    fn cache_name(self) -> &'static str {
        match self {
            Self::Pure | Self::PureBlock | Self::PureCountedBlock => "pure",
            Self::GpuReplayDirect => "gpu-replay-direct",
            Self::PreflightScalar => "preflight-scalar",
            Self::PreflightAdmittedRegisterBlock => "preflight-admitted-register-block",
            Self::PreflightAdmittedMemoryBlock => "preflight-block-memory-atomic-registers",
            Self::PreflightProduction => "preflight-production",
        }
    }

    fn is_preflight_production(self) -> bool {
        self == Self::PreflightProduction
    }

    fn uses_pure_block_admission(self) -> bool {
        self == Self::Pure
    }
}

const fn production_preflight_trace_style() -> AssemblyTraceStyle {
    AssemblyTraceStyle::PreflightProduction
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
const AOT_CTX_PREFLIGHT_PC_BEFORE_OFFSET: usize = 160;
const AOT_CTX_PREFLIGHT_PC_AFTER_OFFSET: usize = 168;
const AOT_CTX_PREFLIGHT_LAST_KIND_OFFSET: usize = 176;
const AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET: usize = 184;
const AOT_CTX_MEMORY_PREV_STAMP_OFFSET: usize = 192;
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
const AOT_CTX_MEMORY_START_ORDINAL_OFFSET: usize = 648;
const AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET: usize = 680;
const AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET: usize = 688;
const AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET: usize = 696;
const AOT_CTX_PREFLIGHT_PENDING_SPECIALIZED_OFFSET: usize = 704;
const AOT_CTX_PREFLIGHT_PENDING_CHIPS_OFFSET: usize = 712;
const AOT_CTX_PREFLIGHT_PENDING_DELTAS_OFFSET: usize = 720;
const AOT_CTX_PREFLIGHT_PENDING_TRACE_OFFSET: usize = 736;
const AOT_CTX_PREFLIGHT_PENDING_MAIN_OFFSET: usize = 744;
const AOT_CTX_PREFLIGHT_PENDING_TOWER_OFFSET: usize = 752;
const AOT_CTX_PREFLIGHT_MEMORY_SHARD_START_ORDINAL_OFFSET: usize = 760;
#[cfg(test)]
const AOT_CTX_PREFLIGHT_BLOCK_KIND_HISTOGRAMS_OFFSET: usize = 768;
#[cfg(test)]
const AOT_CTX_PREFLIGHT_BLOCK_KIND_HISTOGRAM_COUNT_OFFSET: usize = 776;
const AOT_CTX_PREFLIGHT_REPLAY_RANGE_LEN_OFFSET: usize = 784;
const AOT_CTX_PREFLIGHT_REPLAY_FAMILY_COUNTS_OFFSET: usize = 792;
const AOT_CTX_PREFLIGHT_REPLAY_FALLBACK_COUNT_OFFSET: usize = 800;
const AOT_CTX_PREFLIGHT_REPLAY_UNSUPPORTED_COUNT_OFFSET: usize = 808;
const AOT_CTX_PREFLIGHT_REPLAY_RANGE_CAPACITY_OFFSET: usize = 816;
const AOT_CTX_GPU_REPLAY_KINDS_OFFSET: usize = 824;
const AOT_CTX_GPU_REPLAY_KIND_COUNT_OFFSET: usize = 832;
const AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET: usize = 840;
const AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET: usize = 848;
const AOT_CTX_GPU_REPLAY_LATEST_CELLS_OFFSET: usize = 856;
const AOT_CTX_GPU_REPLAY_LATEST_BASE_OFFSET: usize = 864;
const AOT_CTX_GPU_REPLAY_LATEST_LEN_OFFSET: usize = 872;
const AOT_CTX_GPU_REPLAY_MAX_HEAP_OFFSET: usize = 880;
const AOT_CTX_GPU_REPLAY_MAX_HINT_OFFSET: usize = 888;
const AOT_CTX_GPU_REPLAY_EVENTS_OFFSET: usize = 896;
const AOT_CTX_GPU_REPLAY_EVENTS_LEN_OFFSET: usize = 904;
const AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET: usize = 912;
const AOT_CTX_GPU_REPLAY_ERROR_OFFSET: usize = 920;
#[cfg(test)]
const AOT_CTX_GPU_REPLAY_ORDINARY_CALLBACKS_OFFSET: usize = 928;

const AOT_FALLBACK_DYNAMIC_PC: u32 = 1;
const AOT_FALLBACK_MEMORY_GUARD: u32 = 2;
const AOT_FALLBACK_ECALL: u32 = 3;
const AOT_FALLBACK_EXCEPTIONAL: u32 = 4;
const AOT_ABI_VERSION: u32 = 80;
const AOT_CACHE_MAGIC: &str = "ceno-aot-cache-v7";
const AOT_EMITTER_SCHEMA: &str = "replay-emitter-schema2";
const AOT_INITIAL_EVENT_SEED: usize = 20_000_000;
const AOT_MAX_COMPILE_JOBS: usize = 32;
const AOT_BLOCK_COMPILE_OVERHEAD: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AotEmitterVariant {
    Standard,
    SharedPacked,
}

impl AotEmitterVariant {
    fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::SharedPacked => "shared-packed",
        }
    }
}

fn selected_emitter_variant(trace_style: AssemblyTraceStyle) -> AotEmitterVariant {
    if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        AotEmitterVariant::SharedPacked
    } else {
        AotEmitterVariant::Standard
    }
}

const AOT_TRACE_MODE_NONE: u32 = 0;
const AOT_TRACE_MODE_CALLBACK: u32 = 1;
const AOT_TRACE_MODE_PREFLIGHT_DIRECT: u32 = 2;
const AOT_TRACE_MODE_FULLTRACER_DIRECT: u32 = 3;
const AOT_TRACE_MODE_GPU_REPLAY_DIRECT: u32 = 4;

const AOT_PREFLIGHT_HELPER_SYNC: u32 = 1;
const AOT_PREFLIGHT_HELPER_BUSY_LOOP: u32 = 2;
const AOT_PREFLIGHT_HELPER_CALLBACK: u32 = 3;
const AOT_PREFLIGHT_HELPER_SHARD_SPLIT: u32 = 4;
const AOT_PREFLIGHT_HELPER_FIRST_TOUCH: u32 = 5;
const AOT_PREFLIGHT_HELPER_MEMORY_FIRST_TOUCH: u32 = 6;
const AOT_PREFLIGHT_HELPER_REPLAY_BLOCK_CUT: u32 = 7;
const AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_ENTRY: u32 = 8;
const AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_EXIT: u32 = 9;
const AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_ENTRY: u32 = 10;
const AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_EXIT: u32 = 11;
const AOT_PREFLIGHT_HELPER_GROW_TAPE: u32 = u32::MAX;

thread_local! {
    static LAST_AOT_ERROR: RefCell<Option<anyhow::Error>> = const { RefCell::new(None) };
}

static AOT_STARTUP_DIAGNOSTIC_ONLY: OnceLock<bool> = OnceLock::new();
static AOT_DIAGNOSTIC_EPOCH: OnceLock<Instant> = OnceLock::new();
static AOT_DIAGNOSTIC_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static AOT_NATIVE_DIAGNOSTIC_ONLY: OnceLock<bool> = OnceLock::new();
static AOT_NATIVE_DIAGNOSTIC_EPOCH: OnceLock<Instant> = OnceLock::new();
static AOT_NATIVE_DIAGNOSTIC_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static AOT_NATIVE_CALLBACK_FALLBACK: AtomicU64 = AtomicU64::new(0);
static AOT_NATIVE_CALLBACK_TRACE: AtomicU64 = AtomicU64::new(0);
static AOT_NATIVE_CALLBACK_PREFLIGHT: AtomicU64 = AtomicU64::new(0);
static AOT_CACHE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn aot_startup_diagnostic_only() -> bool {
    *AOT_STARTUP_DIAGNOSTIC_ONLY.get_or_init(|| {
        std::env::var_os("CENO_AOT_STARTUP_DIAGNOSTIC_ONLY").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    })
}

/// Private, fail-closed diagnostic gate for bounded native execution.
pub fn aot_native_diagnostic_only() -> bool {
    *AOT_NATIVE_DIAGNOSTIC_ONLY.get_or_init(|| {
        let native = std::env::var_os("CENO_AOT_NATIVE_DIAGNOSTIC_ONLY");
        let startup = std::env::var_os("CENO_AOT_STARTUP_DIAGNOSTIC_ONLY");
        match (native.as_deref(), startup.as_deref()) {
            (None, _) => false,
            (Some(value), None) if value == std::ffi::OsStr::new("1") => true,
            (Some(_), None) => panic!("CENO_AOT_NATIVE_DIAGNOSTIC_ONLY must be exactly 1"),
            (Some(_), Some(_)) => panic!(
                "CENO_AOT_NATIVE_DIAGNOSTIC_ONLY and CENO_AOT_STARTUP_DIAGNOSTIC_ONLY are mutually exclusive"
            ),
        }
    })
}

pub fn aot_native_diagnostic_boundary(phase: &str, state: &str, counts: &str) {
    aot_native_diagnostic_marker(phase, state, "caller", "-", Path::new("-"), 0, counts);
}

fn aot_native_diagnostic_marker(
    phase: &str,
    state: &str,
    role: &str,
    key: &str,
    path: &Path,
    bytes: u64,
    counts: &str,
) {
    if !aot_native_diagnostic_only() {
        return;
    }
    let sequence = AOT_NATIVE_DIAGNOSTIC_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    let monotonic_ns = AOT_NATIVE_DIAGNOSTIC_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos();
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "CENO_AOT_NATIVE_DIAGNOSTIC seq={sequence} monotonic_ns={monotonic_ns} phase={phase} state={state} pid={} tid={:?} role={role} key={key} path={} bytes={bytes} counts={counts}",
        std::process::id(),
        std::thread::current().id(),
        path.display(),
    );
    let _ = stderr.flush();
}

fn aot_native_callback_event(counter: &AtomicU64, category: &str) {
    if !aot_native_diagnostic_only() {
        return;
    }
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() || count % 65_536 == 0 {
        aot_native_diagnostic_boundary(
            "CALLBACK_CATEGORY",
            "SAMPLE",
            &format!("category={category},count={count}"),
        );
    }
}

fn aot_plan_commit_diagnostic_state(phase: &str, variant: &str, context: &AotRuntimeContext) {
    if !aot_native_diagnostic_only() {
        return;
    }
    let read_usize = |pointer: *const usize| {
        if pointer.is_null() {
            None
        } else {
            Some(unsafe { *pointer })
        }
    };
    let read_cycle = |pointer: *const Cycle| {
        if pointer.is_null() {
            None
        } else {
            Some(unsafe { *pointer })
        }
    };
    let family = context.preflight_replay_family_counts;
    let auipc_pointer = if family.is_null() {
        std::ptr::null()
    } else {
        unsafe { family.add(InsnKind::AUIPC as usize) }
    };
    aot_native_diagnostic_boundary(
        "FIRST_PLAN_COMMIT_STATE",
        phase,
        &format!(
            "variant={variant},block_idx=0,context={context:p},trace_mode={},next_pc={:#010x},cycle_ptr={:p},cycle={:?},step_ptr={:p},step={:?},range_ptr={:p},range={:?},family_ptr={:p},auipc_ptr={:p},auipc={:?},fallback_ptr={:p},fallback={:?},unsupported_ptr={:p},unsupported={:?},capacity={},offset_trace_mode={},offset_cycle={},offset_step={},offset_range={},offset_family={},offset_fallback={},offset_unsupported={},offset_capacity={}",
            context.trace_mode,
            context.trace_next_pc,
            context.preflight_planner_cur_cycle_in_shard,
            read_cycle(context.preflight_planner_cur_cycle_in_shard),
            context.preflight_planner_cur_step_count,
            read_usize(context.preflight_planner_cur_step_count),
            context.preflight_replay_range_len,
            read_usize(context.preflight_replay_range_len),
            family,
            auipc_pointer,
            read_usize(auipc_pointer),
            context.preflight_replay_fallback_count,
            read_usize(context.preflight_replay_fallback_count),
            context.preflight_replay_unsupported_count,
            read_usize(context.preflight_replay_unsupported_count),
            context.preflight_replay_range_capacity,
            AOT_CTX_TRACE_MODE_OFFSET,
            AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET,
            AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET,
            AOT_CTX_PREFLIGHT_REPLAY_RANGE_LEN_OFFSET,
            AOT_CTX_PREFLIGHT_REPLAY_FAMILY_COUNTS_OFFSET,
            AOT_CTX_PREFLIGHT_REPLAY_FALLBACK_COUNT_OFFSET,
            AOT_CTX_PREFLIGHT_REPLAY_UNSUPPORTED_COUNT_OFFSET,
            AOT_CTX_PREFLIGHT_REPLAY_RANGE_CAPACITY_OFFSET,
        ),
    );
}

struct AotNativeDiagnosticWatchdog {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AotNativeDiagnosticWatchdog {
    fn start(role: &str, key: &str, max_steps: usize) -> Option<Self> {
        if !aot_native_diagnostic_only() {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let role = role.to_owned();
        let key = key.to_owned();
        let thread = std::thread::spawn(move || {
            let started = Instant::now();
            while !thread_stop.load(Ordering::Acquire) {
                for _ in 0..50 {
                    if thread_stop.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                aot_native_diagnostic_marker(
                    "NATIVE_WATCHDOG",
                    "SAMPLE",
                    &role,
                    &key,
                    Path::new("-"),
                    0,
                    &format!(
                        "elapsed_ms={},max_steps={max_steps},fallback={},trace={},preflight={}",
                        started.elapsed().as_millis(),
                        AOT_NATIVE_CALLBACK_FALLBACK.load(Ordering::Relaxed),
                        AOT_NATIVE_CALLBACK_TRACE.load(Ordering::Relaxed),
                        AOT_NATIVE_CALLBACK_PREFLIGHT.load(Ordering::Relaxed),
                    ),
                );
            }
        });
        Some(Self {
            stop,
            thread: Some(thread),
        })
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for AotNativeDiagnosticWatchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

fn aot_diagnostic_marker(
    phase: &str,
    state: &str,
    role: &str,
    key: &str,
    path: &Path,
    bytes: u64,
    counts: &str,
) {
    if !aot_startup_diagnostic_only() {
        return;
    }
    let sequence = AOT_DIAGNOSTIC_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    let monotonic_ns = AOT_DIAGNOSTIC_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos();
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "CENO_AOT_STARTUP_DIAGNOSTIC seq={sequence} monotonic_ns={monotonic_ns} phase={phase} state={state} pid={} tid={:?} role={role} key={key} path={} bytes={bytes} counts={counts}",
        std::process::id(),
        std::thread::current().id(),
        path.display(),
    );
    let _ = stderr.flush();
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
    memory_cells: *mut u64,
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
    memory_prev_stamp: u64,
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
    memory_start_ordinal: u64,
    fallback_time_ns: u64,
    pure_ecall_counts: *mut [u64; PURE_ECALL_CODES.len()],
    pure_double_cache: *mut crate::syscalls::pure::DoubleCache,
    preflight_bucket_ceilings: *mut u64,
    preflight_bucket_generations: *mut u64,
    preflight_bucket_generation: u64,
    preflight_pending_specialized: u64,
    preflight_pending_chips: [u32; 2],
    preflight_pending_deltas: [u64; 2],
    preflight_pending_trace: u64,
    preflight_pending_main: u64,
    preflight_pending_tower: u64,
    preflight_memory_shard_start_ordinal: u64,
    preflight_block_kind_histograms: *const AotBlockKindHistogram,
    preflight_block_kind_histogram_count: usize,
    preflight_replay_range_len: *mut usize,
    preflight_replay_family_counts: *mut usize,
    preflight_replay_fallback_count: *mut usize,
    preflight_replay_unsupported_count: *mut usize,
    preflight_replay_range_capacity: usize,
    gpu_replay_kinds: *mut crate::gpu_typed_ingress::GpuTypedNativeKindState,
    gpu_replay_kind_count: usize,
    gpu_replay_ordinal: *mut usize,
    gpu_replay_pending_cycle: *mut Cycle,
    gpu_replay_latest_cells: *mut Cycle,
    gpu_replay_latest_base: u32,
    _gpu_replay_latest_padding: u32,
    gpu_replay_latest_len: *mut usize,
    gpu_replay_max_heap: *mut ByteAddr,
    gpu_replay_max_hint: *mut ByteAddr,
    gpu_replay_events: *const NextAccessEvent,
    gpu_replay_events_len: usize,
    gpu_replay_event_cursor: *mut usize,
    gpu_replay_error: *mut u32,
    gpu_replay_ordinary_callbacks: u64,
}

const PURE_ECALL_CODES: [u32; 11] = [
    crate::SECP256K1_DOUBLE,
    crate::SECP256K1_ADD,
    crate::KECCAK_PERMUTE,
    crate::KECCAK_XORIN,
    crate::SECP256K1_DECOMPRESS,
    crate::SECP256K1_SCALAR_INVERT,
    crate::BN254_FP_ADD,
    crate::BN254_FP_MUL,
    crate::BN254_FP2_ADD,
    crate::BN254_FP2_MUL,
    crate::SECP256R1_SCALAR_INVERT,
];

#[inline(always)]
fn pure_ecall_index(code: u32) -> Option<usize> {
    match code {
        crate::SECP256K1_DOUBLE => Some(0),
        crate::SECP256K1_ADD => Some(1),
        crate::KECCAK_PERMUTE => Some(2),
        crate::KECCAK_XORIN => Some(3),
        crate::SECP256K1_DECOMPRESS => Some(4),
        crate::SECP256K1_SCALAR_INVERT => Some(5),
        crate::BN254_FP_ADD => Some(6),
        crate::BN254_FP_MUL => Some(7),
        crate::BN254_FP2_ADD => Some(8),
        crate::BN254_FP2_MUL => Some(9),
        crate::SECP256R1_SCALAR_INVERT => Some(10),
        _ => None,
    }
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

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct AotBlockKindHistogram {
    counts: [u32; InsnKind::COUNT],
    instruction_offset: u32,
    instruction_count: u32,
}

#[derive(Clone, Debug, Default)]
struct AotPlannerMetadata {
    descriptors: Vec<AotBlockCostDescriptor>,
    contributions: Vec<AotChipContribution>,
}

impl AotPlannerMetadata {
    fn contributions_for(&self, descriptor: &AotBlockCostDescriptor) -> &[AotChipContribution] {
        let start = descriptor.contribution_offset as usize;
        &self.contributions[start..start + descriptor.contribution_count as usize]
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct AotAdditiveCost {
    trace_cells: u64,
    main_peak: u64,
}

fn next_cost_bucket_ceiling(count: u64) -> u64 {
    if count == 0 {
        1
    } else {
        count
            .checked_next_power_of_two()
            .unwrap_or(u64::MAX)
            .saturating_add(1)
    }
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

/// State-only tracer used by benchmark-only pure AOT execution.
#[derive(Debug)]
pub struct PureAotTracer {
    pc_before: ByteAddr,
    pc_after: ByteAddr,
    executed_fallbacks: usize,
}

impl Tracer for PureAotTracer {
    type Record = (ByteAddr, ByteAddr);
    type Config = ();

    const TRACK_MEMORY_ACCESSES: bool = false;

    fn new(_platform: &Platform, _config: Self::Config) -> Self {
        Self {
            pc_before: 0.into(),
            pc_after: 0.into(),
            executed_fallbacks: 0,
        }
    }

    fn advance(&mut self) -> Self::Record {
        self.executed_fallbacks += 1;
        (self.pc_before, self.pc_after)
    }

    fn is_busy_loop(&self, record: &Self::Record) -> bool {
        record.0 == record.1
    }

    fn store_pc(&mut self, pc: ByteAddr) {
        self.pc_after = pc;
    }

    fn fetch(&mut self, pc: WordAddr, _value: Instruction) {
        self.pc_before = pc.baddr();
        self.pc_after = self.pc_before + PC_STEP_SIZE;
    }

    fn track_mmu_maxtouch_before(&mut self) {}
    fn track_mmu_maxtouch_after(&mut self) {}
    fn load_register(&mut self, _idx: RegIdx, _value: Word) {}
    fn store_register(&mut self, _idx: RegIdx, _value: Change<Word>) {}
    fn load_memory(&mut self, _addr: WordAddr, _value: Word, _previous_cycle: Cycle) {}
    fn store_memory(&mut self, _addr: WordAddr, _value: Change<Word>, _previous_cycle: Cycle) {}
    fn track_syscall(&mut self, effects: SyscallEffects) {
        effects.finalize(self);
    }
    fn track_access(&mut self, _addr: WordAddr, _subcycle: Cycle) -> Cycle {
        0
    }
    fn final_register_accesses(&self) -> &LatestAccesses {
        panic!("pure AOT execution has no access history")
    }
    fn into_next_accesses(self) -> NextCycleAccess {
        NextCycleAccess::default()
    }
    fn cycle(&self) -> Cycle {
        (self.executed_fallbacks as Cycle + 1) * Self::SUBCYCLES_PER_INSN
    }
    fn executed_insts(&self) -> usize {
        self.executed_fallbacks
    }
    fn probe_min_max_address_by_start_addr(
        &self,
        _start_addr: WordAddr,
    ) -> Option<(WordAddr, WordAddr)> {
        None
    }

    fn track_memory_accesses(&self) -> bool {
        false
    }
}

/// Loaded native image for one guest program.
///
/// `AotProgram` owns the generated shared library so the entry symbol stays
/// valid. It can execute against any compatible `VMState` for the same
/// `Program`; execution still uses Rust callbacks/fallbacks for cases outside
/// the selected `AssemblyTraceStyle`.
pub struct AotProgram {
    program: Arc<Program>,
    cache_identity: String,
    artifact_path: Option<PathBuf>,
    blocks: Vec<BasicBlock>,
    layout_profile: AotLayoutProfile,
    _library: Library,
    entry: NativeEntry,
    compile_load_time: Duration,
    trace_style: AssemblyTraceStyle,
    next_access_capacity: usize,
    planner_fingerprint: Option<[u8; 32]>,
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
    fn load_memory(&mut self, _addr: WordAddr, _value: Word, _previous_cycle: Cycle) {}
    fn store_memory(&mut self, _addr: WordAddr, _value: Change<Word>, _previous_cycle: Cycle) {}
    fn track_syscall(&mut self, effects: SyscallEffects) {
        let _witness: SyscallWitness = effects.finalize(self);
    }
    fn track_access(&mut self, _addr: WordAddr, _subcycle: Cycle) -> Cycle {
        0
    }
    fn final_register_accesses(&self) -> &LatestAccesses {
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
    /// Load or build the benchmark-only value-execution image.
    pub fn load_or_train_pure(
        platform: &Platform,
        program: Arc<Program>,
        init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
    ) -> Result<Self> {
        let cache_dir = default_aot_cache_dir();
        let trace_style = AssemblyTraceStyle::Pure;
        let key = aot_cache_key(&program, trace_style);
        match load_cached_aot(program.clone(), trace_style, &cache_dir, &key, None) {
            Ok(Some(aot)) => {
                tracing::info!("Pure AOT artifact cache hit: {key}");
                return Ok(aot);
            }
            Ok(None) => {
                if aot_startup_diagnostic_only() {
                    bail!("diagnostic-only Pure AOT cache miss: {key}");
                }
                tracing::info!("Pure AOT artifact cache miss: {key}");
            }
            Err(err) => {
                if aot_startup_diagnostic_only() {
                    return Err(err.context("diagnostic-only Pure AOT cache invalid"));
                }
                tracing::warn!("Pure AOT artifact cache invalid, rebuilding: {err:#}");
            }
        }

        let init_memory = init_memory.into_iter().collect::<Vec<_>>();
        let training =
            trace_preflight_profile(platform, program.clone(), init_memory.iter().copied())?;
        let blocks = partition_basic_blocks_with_roots(&program, training.roots.clone())?;
        let layout_profile = build_layout_profile(&program, &blocks, &training)?;
        compile_cached_aot(
            program,
            training.roots,
            Some(layout_profile),
            trace_style,
            &cache_dir,
            &key,
            0,
            None,
        )
    }

    pub fn cache_identity(&self) -> String {
        self.cache_identity.clone()
    }

    pub const fn abi_version() -> u32 {
        AOT_ABI_VERSION
    }

    #[cfg(test)]
    fn compile_preflight_with_extra_roots(
        program: Arc<Program>,
        extra_roots: Vec<u32>,
    ) -> Result<Self> {
        Self::compile_with_extra_roots_and_trace_style(
            program,
            extra_roots,
            production_preflight_trace_style(),
        )
    }

    #[cfg(test)]
    fn compile_fulltracer(program: Arc<Program>) -> Result<Self> {
        Self::compile_with_extra_roots_and_trace_style(
            program,
            Vec::new(),
            AssemblyTraceStyle::GpuReplayDirect,
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
    /// replay. It reuses the static preflight image's block leaders and has its
    /// own cache entry.
    pub fn load_or_compile_fulltracer_replay(&self) -> Result<Self> {
        let cache_dir = default_aot_cache_dir();
        let trace_style = AssemblyTraceStyle::GpuReplayDirect;
        let key = format!(
            "{}-layout{}-{}",
            aot_cache_key(&self.program, trace_style),
            hex_digest(&self.layout_profile.digest),
            trace_style.cache_name(),
        );
        match load_cached_aot(self.program.clone(), trace_style, &cache_dir, &key, None) {
            Ok(Some(aot)) => {
                tracing::info!("FullTracer replay AOT artifact cache hit: {key}");
                return Ok(aot);
            }
            Ok(None) => {
                if aot_startup_diagnostic_only() {
                    bail!("diagnostic-only FullTracer AOT replay cache miss: {key}");
                }
                tracing::info!("FullTracer replay AOT artifact cache miss: {key}");
            }
            Err(err) => {
                if aot_startup_diagnostic_only() {
                    return Err(err.context("diagnostic-only GPU replay direct AOT cache invalid"));
                }
                tracing::warn!("GPU replay direct AOT artifact cache invalid, rebuilding: {err:#}")
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
            None,
        )
    }

    fn load_or_train_preflight_in(
        platform: &Platform,
        program: Arc<Program>,
        init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
        config: PreflightTracerConfig,
        cache_dir: &Path,
    ) -> Result<Self> {
        Self::load_or_train_preflight_style_in(
            platform,
            program,
            init_memory,
            config,
            cache_dir,
            production_preflight_trace_style(),
        )
    }

    fn load_or_train_preflight_style_in(
        _platform: &Platform,
        program: Arc<Program>,
        _init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
        config: PreflightTracerConfig,
        cache_dir: &Path,
        trace_style: AssemblyTraceStyle,
    ) -> Result<Self> {
        let planner_model = config
            .step_cell_extractor()
            .and_then(|extractor| extractor.shard_cost_model())
            .ok_or_else(|| anyhow!("preflight block AOT requires a shard cost model"))?;
        let key = format!(
            "{}-cells{}-cycles{}",
            planner_cache_key(&program, trace_style, &planner_model),
            config.max_cell_per_shard(),
            config.max_cycle_per_shard()
        );
        match load_cached_aot(
            program.clone(),
            trace_style,
            cache_dir,
            &key,
            Some(planner_model.fingerprint()),
        ) {
            Ok(Some(aot)) => {
                tracing::info!("AOT artifact cache hit: {}", key);
                return Ok(aot);
            }
            Ok(None) => {
                if aot_startup_diagnostic_only() {
                    bail!("diagnostic-only preflight AOT cache miss: {key}");
                }
                tracing::info!("AOT artifact cache miss: {}", key);
            }
            Err(err) => {
                if aot_startup_diagnostic_only() {
                    return Err(err.context("diagnostic-only preflight AOT cache invalid"));
                }
                tracing::warn!("AOT artifact cache invalid, rebuilding: {err:#}");
            }
        }

        let roots = static_preflight_roots(&program)?;
        let blocks = partition_basic_blocks_with_roots(&program, roots.clone())?;
        let layout_profile = pc_order_layout(&blocks);
        let event_count = AOT_INITIAL_EVENT_SEED;
        tracing::info!(
            "AOT static roots={} blocks={} event_seed={event_count}",
            roots.len(),
            blocks.len(),
        );
        compile_cached_aot(
            program,
            roots,
            Some(layout_profile),
            trace_style,
            cache_dir,
            &key,
            event_count,
            Some(&planner_model),
        )
    }

    #[cfg(test)]
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
            cache_identity: aot_cache_key(&program, trace_style),
            artifact_path: None,
            program,
            blocks,
            layout_profile,
            _library: library,
            entry,
            compile_load_time: started.elapsed(),
            trace_style,
            next_access_capacity: 0,
            planner_fingerprint: None,
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
        let diagnostic_role = self.trace_style.cache_name();
        let diagnostic_path = self
            .artifact_path
            .as_deref()
            .unwrap_or_else(|| Path::new("-"));
        let diagnostic_bytes = self
            .artifact_path
            .as_deref()
            .and_then(|path| fs::metadata(path).ok())
            .map_or(0, |metadata| metadata.len());
        aot_diagnostic_marker(
            "RUNTIME_IDENTITY_POINTERS",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("max_steps={max_steps},trace_native_steps={trace_native_steps}"),
        );
        if !std::ptr::eq(vm.program(), self.program.as_ref()) {
            bail!("AOT program does not match VM program");
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
        let memory_start_ordinal = if self.trace_style.is_pure() {
            0
        } else {
            vm.tracer().cycle() >> 2
        };
        if memory_start_ordinal > u64::from(u32::MAX) {
            bail!("packed memory access stamp exceeds u32::MAX");
        }
        // Bound the whole native invocation once, rather than checking every
        // memory instruction. A step at the final ordinal is representable.
        let packed_step_limit = if self.trace_style.is_pure() {
            usize::MAX
        } else {
            (u64::from(u32::MAX) - memory_start_ordinal + 1) as usize
        };
        let native_max_steps = max_steps.min(packed_step_limit);
        let instructions = self.program.instructions.as_ptr();
        let program_base = self.program.base_address;
        aot_diagnostic_marker(
            "RUNTIME_IDENTITY_POINTERS",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!(
                "instructions={},memory_words={},native_max_steps={native_max_steps}",
                self.program.instructions.len(),
                memory_end_word.saturating_sub(memory_base_word)
            ),
        );
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
        let mut preflight_replay_range_len = std::ptr::null_mut();
        let mut preflight_replay_family_counts = std::ptr::null_mut();
        let mut preflight_replay_fallback_count = std::ptr::null_mut();
        let mut preflight_replay_unsupported_count = std::ptr::null_mut();
        let mut preflight_replay_range_capacity = 0;
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
        aot_diagnostic_marker(
            "RUNTIME_HISTOGRAMS",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("blocks={}", self.blocks.len()),
        );
        let preflight_block_kind_histograms = if self.trace_style.uses_preflight_block_plan() {
            build_aot_block_kind_histograms(&self.program, &self.blocks)?
        } else {
            Vec::new()
        };
        aot_diagnostic_marker(
            "RUNTIME_HISTOGRAMS",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("histograms={}", preflight_block_kind_histograms.len()),
        );
        let mut preflight_chip_contributions = Vec::new();
        let mut preflight_cost_model = None;
        let mut fallback_ecall_codes = BTreeMap::new();
        let mut pure_ecall_counts = [0u64; PURE_ECALL_CODES.len()];
        let mut pure_double_cache = (self.trace_style.is_pure()
            || self.trace_style.uses_preflight_block_plan())
        .then(crate::syscalls::pure::DoubleCache::new);
        aot_diagnostic_marker(
            "RUNTIME_COST_DESCRIPTORS",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            "descriptors=0,contributions=0",
        );
        if trace_native_steps && TypeId::of::<T>() == TypeId::of::<PreflightTracer>() {
            let preflight_vm = unsafe { &mut *(vm_ptr as *mut VMState<PreflightTracer>) };
            if preflight_vm.tracer().supports_direct_native_trace() {
                if self.trace_style.uses_preflight_block_plan() {
                    let model = preflight_vm.tracer().shard_cost_model().ok_or_else(|| {
                        anyhow!("preflight block AOT requires a shard cost model")
                    })?;
                    if self
                        .planner_fingerprint
                        .is_some_and(|fingerprint| fingerprint != model.fingerprint())
                    {
                        bail!("AOT artifact shard-cost-model identity mismatch");
                    }
                    let metadata =
                        build_aot_block_cost_descriptors(&self.program, &self.blocks, &model)?;
                    preflight_block_cost_descriptors = metadata.descriptors;
                    preflight_chip_contributions = metadata.contributions;
                    preflight_cost_model = Some(model);
                } else {
                    preflight_step_cells = self
                        .program
                        .instructions
                        .iter()
                        .map(|insn| preflight_vm.tracer().native_step_cells_for_kind(insn.kind))
                        .collect();
                }
                aot_diagnostic_marker(
                    "RUNTIME_COST_DESCRIPTORS",
                    "END",
                    diagnostic_role,
                    &self.cache_identity,
                    diagnostic_path,
                    diagnostic_bytes,
                    &format!(
                        "descriptors={},contributions={},step_cells={}",
                        preflight_block_cost_descriptors.len(),
                        preflight_chip_contributions.len(),
                        preflight_step_cells.len()
                    ),
                );
                aot_diagnostic_marker(
                    "RUNTIME_MMIO",
                    "BEGIN",
                    diagnostic_role,
                    &self.cache_identity,
                    diagnostic_path,
                    diagnostic_bytes,
                    "regions=3",
                );
                if self.trace_style.is_preflight_production() {
                    preflight_vm.tracer_mut().begin_deferred_mmio_bounds();
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
                aot_diagnostic_marker(
                    "RUNTIME_MMIO",
                    "END",
                    diagnostic_role,
                    &self.cache_identity,
                    diagnostic_path,
                    diagnostic_bytes,
                    "regions=3",
                );
                aot_diagnostic_marker(
                    "RUNTIME_NEXT_ACCESS",
                    "BEGIN",
                    diagnostic_role,
                    &self.cache_identity,
                    diagnostic_path,
                    diagnostic_bytes,
                    &format!("configured_capacity={}", self.next_access_capacity),
                );
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
                preflight_replay_range_len = state.replay_range_len;
                preflight_replay_family_counts = state.replay_family_counts;
                preflight_replay_fallback_count = state.replay_fallback_count;
                preflight_replay_unsupported_count = state.replay_unsupported_count;
                preflight_replay_range_capacity = state.replay_range_capacity;
                preflight_max_cell_per_shard = state.planner_max_cell_per_shard;
                preflight_target_cell_first_shard = state.planner_target_cell_first_shard;
                preflight_max_cycle_per_shard = state.planner_max_cycle_per_shard;
                aot_diagnostic_marker(
                    "RUNTIME_NEXT_ACCESS",
                    "END",
                    diagnostic_role,
                    &self.cache_identity,
                    diagnostic_path,
                    diagnostic_bytes,
                    &format!(
                        "event_capacity={event_capacity},replay_range_capacity={preflight_replay_range_capacity}"
                    ),
                );
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
            && self.trace_style == AssemblyTraceStyle::GpuReplayDirect
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
        let mut gpu_replay_kinds = std::ptr::null_mut();
        let mut gpu_replay_kind_count = 0;
        let mut gpu_replay_ordinal = std::ptr::null_mut();
        let mut gpu_replay_pending_cycle = std::ptr::null_mut();
        let mut gpu_replay_latest_cells = std::ptr::null_mut();
        let mut gpu_replay_latest_base = 0;
        let mut gpu_replay_latest_len = std::ptr::null_mut();
        let mut gpu_replay_max_heap = std::ptr::null_mut();
        let mut gpu_replay_max_hint = std::ptr::null_mut();
        let mut gpu_replay_events = std::ptr::null();
        let mut gpu_replay_events_len = 0;
        let mut gpu_replay_event_cursor = std::ptr::null_mut();
        let mut gpu_replay_error = std::ptr::null_mut();
        if trace_native_steps
            && !cfg!(debug_assertions)
            && TypeId::of::<T>() == TypeId::of::<crate::GpuReplayTracer>()
            && self.trace_style == AssemblyTraceStyle::GpuReplayDirect
        {
            let replay_vm = unsafe { &mut *(vm_ptr as *mut VMState<crate::GpuReplayTracer>) };
            let state = replay_vm.tracer_mut().prepare_native_range();
            trace_mode = AOT_TRACE_MODE_GPU_REPLAY_DIRECT;
            gpu_replay_kinds = state.kinds;
            gpu_replay_kind_count = state.kind_count;
            gpu_replay_ordinal = state.ordinal;
            gpu_replay_pending_cycle = state.pending_cycle;
            gpu_replay_latest_cells = state.latest_cells;
            gpu_replay_latest_base = state.latest_base.0;
            gpu_replay_latest_len = state.latest_len;
            gpu_replay_max_heap = state.max_heap_addr_access;
            gpu_replay_max_hint = state.max_hint_addr_access;
            gpu_replay_events = state.next_access_events;
            gpu_replay_events_len = state.next_access_len;
            gpu_replay_event_cursor = state.next_access_cursor;
            gpu_replay_error = state.error;
        }
        let preflight_step_cells_table = if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            preflight_step_cells.as_ptr()
        } else {
            std::ptr::null()
        };
        let preflight_block_cells_table = std::ptr::null();
        let preflight_block_cost_descriptors_table = if self.trace_style.uses_preflight_block_plan()
        {
            preflight_block_cost_descriptors.as_ptr()
        } else {
            std::ptr::null()
        };
        aot_diagnostic_marker(
            "RUNTIME_ADDITIVE_BUCKETS",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("chips={preflight_planner_num_chips}"),
        );
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
        let mut preflight_bucket_ceilings = vec![0u64; preflight_planner_num_chips];
        let mut preflight_bucket_generations = vec![1u64; preflight_planner_num_chips];
        if !preflight_planner_num_instances.is_null() {
            let counts = unsafe {
                std::slice::from_raw_parts(
                    preflight_planner_num_instances,
                    preflight_planner_num_chips,
                )
            };
            for (ceiling, &count) in preflight_bucket_ceilings.iter_mut().zip(counts) {
                *ceiling = next_cost_bucket_ceiling(count);
            }
        }
        aot_diagnostic_marker(
            "RUNTIME_ADDITIVE_BUCKETS",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!(
                "additive={},buckets={},chips={preflight_planner_num_chips}",
                preflight_additive_cost_table.len(),
                preflight_bucket_ceilings.len()
            ),
        );
        aot_diagnostic_marker(
            "RUNTIME_CONTEXT",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("context_bytes={}", std::mem::size_of::<AotRuntimeContext>()),
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
            memory_prev_stamp: 0,
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
            memory_start_ordinal,
            fallback_time_ns: 0,
            pure_ecall_counts: &mut pure_ecall_counts,
            pure_double_cache: pure_double_cache
                .as_mut()
                .map_or(std::ptr::null_mut(), |cache| cache as *mut _),
            preflight_bucket_ceilings: preflight_bucket_ceilings.as_mut_ptr(),
            preflight_bucket_generations: preflight_bucket_generations.as_mut_ptr(),
            preflight_bucket_generation: 1,
            preflight_pending_specialized: 0,
            preflight_pending_chips: [0; 2],
            preflight_pending_deltas: [0; 2],
            preflight_pending_trace: 0,
            preflight_pending_main: 0,
            preflight_pending_tower: 0,
            preflight_memory_shard_start_ordinal: preflight_register_shard_start >> 2,
            preflight_block_kind_histograms: preflight_block_kind_histograms.as_ptr(),
            preflight_block_kind_histogram_count: preflight_block_kind_histograms.len(),
            preflight_replay_range_len,
            preflight_replay_family_counts,
            preflight_replay_fallback_count,
            preflight_replay_unsupported_count,
            preflight_replay_range_capacity,
            gpu_replay_kinds,
            gpu_replay_kind_count,
            gpu_replay_ordinal,
            gpu_replay_pending_cycle,
            gpu_replay_latest_cells,
            gpu_replay_latest_base,
            _gpu_replay_latest_padding: 0,
            gpu_replay_latest_len,
            gpu_replay_max_heap,
            gpu_replay_max_hint,
            gpu_replay_events,
            gpu_replay_events_len,
            gpu_replay_event_cursor,
            gpu_replay_error,
            gpu_replay_ordinary_callbacks: 0,
        };
        aot_diagnostic_marker(
            "RUNTIME_CONTEXT",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!(
                "context_bytes={},trace_mode={trace_mode}",
                std::mem::size_of::<AotRuntimeContext>()
            ),
        );
        aot_diagnostic_marker(
            "RUNTIME_CALLBACK",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("trace_mode={trace_mode}"),
        );
        let trace_fn = if matches!(
            trace_mode,
            AOT_TRACE_MODE_FULLTRACER_DIRECT | AOT_TRACE_MODE_GPU_REPLAY_DIRECT
        ) {
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
        let exec_fn = if self.trace_style.is_pure() && !trace_native_steps {
            ceno_aot_pure_ecall_callback as AotInsnFn
        } else if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            ceno_aot_preflight_fallback_callback as AotInsnFn
        } else {
            aot_exec_one::<T>
        };
        aot_diagnostic_marker(
            "RUNTIME_CALLBACK",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!(
                "trace_mode={trace_mode},trace_fn_null={}",
                trace_fn.is_null()
            ),
        );
        if aot_startup_diagnostic_only() {
            aot_diagnostic_marker(
                "PRE_NATIVE_DIAGNOSTIC_STOP",
                "STOP",
                diagnostic_role,
                &self.cache_identity,
                diagnostic_path,
                diagnostic_bytes,
                &format!("native_entries=0,executed_steps={executed_steps}"),
            );
            bail!("CENO_AOT_STARTUP_DIAGNOSTIC_ONLY: PRE_NATIVE_DIAGNOSTIC_STOP");
        }
        AOT_NATIVE_CALLBACK_FALLBACK.store(0, Ordering::Relaxed);
        AOT_NATIVE_CALLBACK_TRACE.store(0, Ordering::Relaxed);
        AOT_NATIVE_CALLBACK_PREFLIGHT.store(0, Ordering::Relaxed);
        aot_native_diagnostic_marker(
            "NATIVE_ENTRY",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!(
                "max_steps={native_max_steps},start_pc={:#010x},trace_mode={trace_mode}",
                vm.get_pc().0
            ),
        );
        if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            aot_plan_commit_diagnostic_state("HOST_BEFORE_NATIVE", "host", &context);
        }
        let started = Instant::now();
        let mut native_watchdog = AotNativeDiagnosticWatchdog::start(
            diagnostic_role,
            &self.cache_identity,
            native_max_steps,
        );
        let native_status = unsafe {
            (self.entry)(
                &mut context,
                exec_fn,
                trace_fn,
                native_max_steps as u64,
                &mut executed_steps,
                vm.get_pc().0,
            )
        };
        if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            aot_plan_commit_diagnostic_state("HOST_AFTER_NATIVE", "host", &context);
        }
        if let Some(watchdog) = native_watchdog.as_mut() {
            watchdog.stop();
        }
        aot_native_diagnostic_marker(
            "NATIVE_ENTRY",
            "RETURN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!(
                "status={native_status},elapsed_ms={},executed_steps={executed_steps},fallback={},trace={},preflight={}",
                started.elapsed().as_millis(),
                AOT_NATIVE_CALLBACK_FALLBACK.load(Ordering::Relaxed),
                AOT_NATIVE_CALLBACK_TRACE.load(Ordering::Relaxed),
                AOT_NATIVE_CALLBACK_PREFLIGHT.load(Ordering::Relaxed),
            ),
        );
        aot_native_diagnostic_marker(
            "POST_RETURN_NEXT_ACCESS",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("trace_mode={trace_mode}"),
        );
        if trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            let preflight_vm = unsafe { &mut *(vm_ptr as *mut VMState<PreflightTracer>) };
            unsafe {
                preflight_vm
                    .tracer_mut()
                    .sync_native_next_access_tape(context.preflight_event_cursor)
            };
            preflight_vm.tracer_mut().finish_deferred_mmio_bounds();
        } else if trace_mode == AOT_TRACE_MODE_GPU_REPLAY_DIRECT {
            let replay_vm = unsafe { &mut *(vm_ptr as *mut VMState<crate::GpuReplayTracer>) };
            replay_vm
                .tracer_mut()
                .sync_native_range()
                .map_err(|message| anyhow!(message))?;
        }
        aot_native_diagnostic_marker(
            "POST_RETURN_NEXT_ACCESS",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("trace_mode={trace_mode}"),
        );
        aot_native_diagnostic_marker(
            "POST_RETURN_STATUS",
            "BEGIN",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("status={native_status}"),
        );
        if native_status == AOT_STATUS_ERROR {
            let err = LAST_AOT_ERROR
                .with(|slot| slot.borrow_mut().take())
                .unwrap_or_else(|| anyhow!("AOT native step failed without error detail"));
            return Err(err);
        }
        if trace_mode == AOT_TRACE_MODE_GPU_REPLAY_DIRECT {
            tracing::info!(
                "GPU_REPLAY_DIRECT tracer=GpuReplayTracer native_mode=gpu-replay-direct ordinary_callbacks={} fallback_dynamic_pc={} fallback_memory_guard={} fallback_ecall={} fallback_exceptional={}",
                context.gpu_replay_ordinary_callbacks,
                context.fallback_dynamic_pc,
                context.fallback_memory_guard,
                context.fallback_ecall,
                context.fallback_exceptional,
            );
        }
        if native_status != AOT_STATUS_HALTED {
            bail!("AOT native entry returned invalid status {native_status}");
        }
        aot_native_diagnostic_marker(
            "POST_RETURN_STATUS",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!("status={native_status}"),
        );
        if let Some(cache) = pure_double_cache.as_ref() {
            let (hits, misses) = cache.stats();
            tracing::info!("Pure AOT secp double cache hits={hits} misses={misses}");
        }
        if native_max_steps < max_steps && executed_steps == native_max_steps as u64 && !vm.halted()
        {
            bail!("packed memory access stamp exceeds u32::MAX");
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
        aot_native_diagnostic_marker(
            "POST_RETURN_TAPE_REPORT",
            "END",
            diagnostic_role,
            &self.cache_identity,
            diagnostic_path,
            diagnostic_bytes,
            &format!(
                "events={next_access_events},capacity={next_access_capacity},growths={next_access_growths}"
            ),
        );
        tracing::info!(
            "AOT next-access tape usage={next_access_events} capacity={next_access_capacity} growths={next_access_growths} growth_bytes={next_access_growth_bytes} growth_time={next_access_growth_time:?} normal_access_callbacks=0"
        );
        for (code, count) in PURE_ECALL_CODES.into_iter().zip(pure_ecall_counts) {
            if count != 0 {
                fallback_ecall_codes
                    .entry(code)
                    .and_modify(|existing| *existing += count as usize)
                    .or_insert(count as usize);
            }
        }
        Ok(AotRunReport {
            executed_steps: executed_steps as usize,
            fallback_steps: context.fallback_steps as usize,
            fallback: AotFallbackReport {
                dynamic_pc_miss: context.fallback_dynamic_pc as usize,
                memory_guard: context.fallback_memory_guard as usize,
                ecall_by_code: fallback_ecall_codes,
                exceptional_jump_or_trap: context.fallback_exceptional as usize,
            },
            fallback_time: Duration::from_nanos(context.fallback_time_ns),
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
    pub fallback_time: Duration,
    pub execute_time: Duration,
    pub next_access_events: usize,
    pub next_access_capacity: usize,
    pub next_access_growths: usize,
    pub next_access_growth_bytes: usize,
    pub next_access_growth_time: Duration,
}

impl AotRunReport {
    pub fn native_time(&self) -> Duration {
        self.execute_time.saturating_sub(self.fallback_time)
    }
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

    let mut roots = BTreeSet::from([program.entry]);
    roots.extend(program.static_aot_roots.iter().flatten().copied());
    roots.extend(extra_roots);
    let mut leaders = roots.clone();
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
    let mut pending = roots
        .into_iter()
        .filter(|pc| valid_leaders.contains(pc))
        .collect::<Vec<_>>();
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

/// Complete, input-independent entry set for production preflight artifacts.
///
/// LLVM supplies function/basic-block entries and call return addresses. Add
/// every possible native resume point after link-producing indirect calls and
/// syscalls so Rust fallback can always re-enter compiled code without training
/// on a particular input. Returns and tail calls write no link (`rd == x0`), so
/// their fallthrough PCs are not legal resume points.
fn static_preflight_roots(program: &Program) -> Result<Vec<u32>> {
    let mut roots = match &program.static_aot_roots {
        Some(roots) => roots.clone(),
        #[cfg(test)]
        None => vec![program.entry],
        #[cfg(not(test))]
        None => {
            bail!("AOT requires an ELF .llvm_bb_addr_map generated by cargo ceno build")
        }
    };
    roots.push(program.entry);
    roots.extend(
        program
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, insn)| {
                (insn.kind == InsnKind::JALR && insn.rd != 0)
                    || matches!(insn.kind, InsnKind::ECALL | InsnKind::INVALID)
            })
            .filter_map(|(idx, _)| {
                let pc = program.base_address + idx as u32 * PC_STEP_SIZE as u32;
                fallthrough_pc(program, pc)
            }),
    );
    roots.sort_unstable();
    roots.dedup();
    Ok(roots)
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

#[cfg(test)]
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
        None,
        &asm_path,
        &so_path,
    )?;
    load_native(&so_path, trace_style.cache_name(), "uncached-test")
}

fn compile_native_to(
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
    planner_metadata: Option<&AotPlannerMetadata>,
    asm_path: &Path,
    so_path: &Path,
) -> Result<()> {
    let jobs = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(AOT_MAX_COMPILE_JOBS)
        .min(blocks.len().max(1));
    compile_native_to_with_jobs(
        program,
        blocks,
        emission_order,
        trace_style,
        planner_metadata,
        asm_path,
        so_path,
        jobs,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_native_to_with_jobs(
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
    planner_metadata: Option<&AotPlannerMetadata>,
    asm_path: &Path,
    so_path: &Path,
    jobs: usize,
) -> Result<()> {
    validate_emission_order(blocks, emission_order)?;
    let started = Instant::now();
    let shards = shard_emission_order(blocks, emission_order, jobs)?;
    let path_digest = hex_digest(&keccak256(asm_path.to_string_lossy().as_bytes()));
    let prefix = format!(".ceno-aot-{}", &path_digest[..16]);
    let parent = asm_path
        .parent()
        .context("AOT assembly path has no parent")?;
    let control_asm = parent.join(format!("{prefix}.control.S"));
    let control_obj = parent.join(format!("{prefix}.control.o"));
    let shard_paths = (0..shards.len())
        .map(|index| {
            (
                parent.join(format!("{prefix}.shard-{index:02}.S")),
                parent.join(format!("{prefix}.shard-{index:02}.o")),
            )
        })
        .collect::<Vec<_>>();
    let cleanup = || {
        let _ = fs::remove_file(&control_asm);
        let _ = fs::remove_file(&control_obj);
        for (assembly, object) in &shard_paths {
            let _ = fs::remove_file(assembly);
            let _ = fs::remove_file(object);
        }
    };

    let result = (|| -> Result<()> {
        write_assembly_part(
            &control_asm,
            program,
            blocks,
            &[],
            trace_style,
            planner_metadata,
            true,
        )?;
        assemble_object(&control_asm, &control_obj)?;
        fs::remove_file(&control_asm)?;

        std::thread::scope(|scope| -> Result<()> {
            let mut workers = Vec::with_capacity(shards.len());
            for ((assembly, object), shard) in shard_paths.iter().zip(&shards) {
                workers.push(scope.spawn(move || -> Result<()> {
                    write_assembly_part(
                        assembly,
                        program,
                        blocks,
                        shard,
                        trace_style,
                        planner_metadata,
                        false,
                    )?;
                    assemble_object(assembly, object)?;
                    fs::remove_file(assembly)?;
                    Ok(())
                }));
            }
            for worker in workers {
                worker
                    .join()
                    .map_err(|_| anyhow!("AOT assembly worker panicked"))??;
            }
            Ok(())
        })?;

        let object_paths = std::iter::once(&control_obj)
            .chain(shard_paths.iter().map(|(_, object)| object))
            .collect::<Vec<_>>();
        let peak_temporary_bytes = object_paths.iter().try_fold(0u64, |total, path| {
            Ok::<_, anyhow::Error>(total.saturating_add(fs::metadata(path)?.len()))
        })?;
        let output = Command::new("cc")
            .arg("-shared")
            .arg("-fPIC")
            .args(&object_paths)
            .arg("-o")
            .arg(so_path)
            .output()
            .context("link AOT objects")?;
        if !output.status.success() {
            bail!(
                "AOT object link failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        tracing::info!(
            "AOT static compile wall_time={:?} workers={} peak_temporary_bytes={}",
            started.elapsed(),
            shards.len(),
            peak_temporary_bytes,
        );
        Ok(())
    })();
    cleanup();
    result
}

fn assemble_object(asm_path: &Path, object_path: &Path) -> Result<()> {
    let output = Command::new("cc")
        .arg("-fPIC")
        .arg("-x")
        .arg("assembler")
        .arg("-c")
        .arg(asm_path)
        .arg("-o")
        .arg(object_path)
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

fn shard_emission_order(
    blocks: &[BasicBlock],
    emission_order: &[u32],
    requested_jobs: usize,
) -> Result<Vec<Vec<u32>>> {
    validate_emission_order(blocks, emission_order)?;
    let jobs = requested_jobs
        .clamp(1, AOT_MAX_COMPILE_JOBS)
        .min(blocks.len());
    let weights = blocks
        .iter()
        .map(|block| {
            (
                block.start_pc,
                ((block.end_pc - block.start_pc) / PC_STEP_SIZE as u32) as usize
                    + AOT_BLOCK_COMPILE_OVERHEAD,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let total_weight = emission_order.iter().try_fold(0usize, |total, pc| {
        Ok::<_, anyhow::Error>(
            total.saturating_add(
                *weights
                    .get(pc)
                    .ok_or_else(|| anyhow!("missing AOT block weight for {pc:#010x}"))?,
            ),
        )
    })?;
    let mut shards = Vec::with_capacity(jobs);
    let mut start = 0usize;
    let mut consumed_weight = 0usize;
    for shard_index in 0..jobs {
        let remaining_shards = jobs - shard_index;
        let end = if remaining_shards == 1 {
            emission_order.len()
        } else {
            let remaining_weight = total_weight.saturating_sub(consumed_weight);
            let target = remaining_weight.div_ceil(remaining_shards);
            let max_end = emission_order.len() - (remaining_shards - 1);
            let mut end = start;
            let mut shard_weight = 0usize;
            while end < max_end {
                let weight = weights[&emission_order[end]];
                if end > start && shard_weight.saturating_add(weight) > target {
                    break;
                }
                shard_weight = shard_weight.saturating_add(weight);
                end += 1;
            }
            consumed_weight = consumed_weight.saturating_add(shard_weight);
            end.max(start + 1)
        };
        shards.push(emission_order[start..end].to_vec());
        start = end;
    }
    Ok(shards)
}

fn load_native(so_path: &Path, role: &str, key: &str) -> Result<(Library, NativeEntry)> {
    let bytes = fs::metadata(so_path).map_or(0, |metadata| metadata.len());
    aot_diagnostic_marker(
        "LIBRARY_NEW",
        "BEGIN",
        role,
        key,
        so_path,
        bytes,
        "libraries=1",
    );
    let library = unsafe { Library::new(so_path) }.context("load AOT shared object")?;
    aot_diagnostic_marker(
        "LIBRARY_NEW",
        "END",
        role,
        key,
        so_path,
        bytes,
        "libraries=1",
    );
    aot_diagnostic_marker(
        "SYMBOL_LOOKUP",
        "BEGIN",
        role,
        key,
        so_path,
        bytes,
        "symbols=1",
    );
    let entry = unsafe {
        let symbol: Symbol<'_, NativeEntry> = library
            .get(b"ceno_aot_entry")
            .context("load ceno_aot_entry")?;
        *symbol
    };
    aot_diagnostic_marker(
        "SYMBOL_LOOKUP",
        "END",
        role,
        key,
        so_path,
        bytes,
        "symbols=1",
    );
    Ok((library, entry))
}
