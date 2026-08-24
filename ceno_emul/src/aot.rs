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
use strum::{EnumCount, IntoEnumIterator};
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
    /// I061-R L0: the production-preflight block image stripped to value-only
    /// execution. It deliberately owns no planner, access, or record state.
    PreflightPureL0,
    /// I061-R L1: L0 execution plus poison-initialized generic skeleton rows.
    PreflightSkeletonL1,
    /// I061-R L1C: L1 semantics emitted directly as compact AoS rows.
    PreflightCompactSkeletonL1C,
    /// I061-R L2C: L2 values emitted directly as compact family rows.
    PreflightCompactValuesL2C,
    /// I061-R L3C: L3 register predecessors appended to compact value families.
    PreflightCompactRegistersL3C,
    /// I061-R L4C: L3C plus memory predecessors and exact MMIO bounds.
    PreflightCompactMemoryL4C,
    /// I061-R L5C: L4C plus direct compact future-access masks.
    PreflightCompactFutureAccessL5C,
    /// I061-R L6C: L5C plus exact exceptional and syscall side streams.
    PreflightCompactExceptionalL6C,
    /// I061-R L7: retained GPU compact bytes routed directly by family while
    /// preserving the L6C exceptional side streams.
    PreflightCompactClosureL7,
    /// I061-R L2: L1 skeleton rows plus operand and memory values.
    PreflightValuesL2,
    /// I061-R L3: L2 rows plus exact register predecessor stamps.
    PreflightRegistersL3,
    /// I061-R L4: L3 rows plus packed-memory predecessor stamps and exact
    /// heap/hint maximum-touch bounds.
    PreflightMemoryL4,
    /// I061-R L5: L4 rows plus authoritative cross-shard future-access masks.
    PreflightFutureAccessL5,
    /// Native code emits `StepRecord`s and maintains FullTracer access state
    /// directly. Rust is entered only for fallback instructions and syscalls.
    #[cfg_attr(not(test), allow(dead_code))]
    FullTracerDirect,
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
        matches!(
            self,
            Self::PreflightValuesL2
                | Self::PreflightCompactValuesL2C
                | Self::PreflightCompactRegistersL3C
                | Self::PreflightCompactMemoryL4C
                | Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
                | Self::PreflightRegistersL3
                | Self::PreflightMemoryL4
                | Self::PreflightFutureAccessL5
                | Self::FullTracerDirect
                | Self::GpuReplayDirect
        )
    }

    fn is_pure(self) -> bool {
        matches!(
            self,
            Self::Pure
                | Self::PureBlock
                | Self::PureCountedBlock
                | Self::PreflightPureL0
                | Self::PreflightSkeletonL1
                | Self::PreflightCompactSkeletonL1C
                | Self::PreflightCompactValuesL2C
                | Self::PreflightCompactRegistersL3C
                | Self::PreflightCompactMemoryL4C
                | Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
                | Self::PreflightValuesL2
                | Self::PreflightRegistersL3
                | Self::PreflightMemoryL4
                | Self::PreflightFutureAccessL5
        )
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
            Self::PreflightPureL0 => "preflight-pure-l0-schema3",
            Self::PreflightSkeletonL1 => "preflight-skeleton-l1-schema1",
            Self::PreflightCompactSkeletonL1C => "preflight-compact-skeleton-l1c-schema1",
            Self::PreflightCompactValuesL2C => "preflight-compact-values-l2c-schema1",
            Self::PreflightCompactRegistersL3C => "preflight-compact-registers-l3c-schema1",
            Self::PreflightCompactMemoryL4C => "preflight-compact-memory-l4c-schema1",
            Self::PreflightCompactFutureAccessL5C => "preflight-compact-future-access-l5c-schema2",
            Self::PreflightCompactExceptionalL6C => "preflight-compact-exceptional-l6c-schema2",
            Self::PreflightCompactClosureL7 => "preflight-compact-closure-l7-schema1",
            Self::PreflightValuesL2 => "preflight-values-l2-schema1",
            Self::PreflightRegistersL3 => "preflight-registers-l3-schema1",
            Self::PreflightMemoryL4 => "preflight-memory-l4-schema1",
            Self::PreflightFutureAccessL5 => "preflight-future-access-l5-schema1",
            Self::FullTracerDirect => "fulltracer-direct",
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
        matches!(
            self,
            Self::Pure
                | Self::PreflightPureL0
                | Self::PreflightSkeletonL1
                | Self::PreflightCompactSkeletonL1C
                | Self::PreflightCompactValuesL2C
                | Self::PreflightCompactRegistersL3C
                | Self::PreflightCompactMemoryL4C
                | Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
                | Self::PreflightValuesL2
                | Self::PreflightRegistersL3
                | Self::PreflightMemoryL4
                | Self::PreflightFutureAccessL5
        )
    }

    fn is_layered_record(self) -> bool {
        matches!(
            self,
            Self::PreflightSkeletonL1
                | Self::PreflightCompactSkeletonL1C
                | Self::PreflightCompactValuesL2C
                | Self::PreflightCompactRegistersL3C
                | Self::PreflightCompactMemoryL4C
                | Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
                | Self::PreflightValuesL2
                | Self::PreflightRegistersL3
                | Self::PreflightMemoryL4
                | Self::PreflightFutureAccessL5
        )
    }

    fn is_generic_layered_record(self) -> bool {
        self.is_layered_record()
            && !matches!(
                self,
                Self::PreflightCompactSkeletonL1C
                    | Self::PreflightCompactValuesL2C
                    | Self::PreflightCompactRegistersL3C
                    | Self::PreflightCompactMemoryL4C
                    | Self::PreflightCompactFutureAccessL5C
                    | Self::PreflightCompactExceptionalL6C
                    | Self::PreflightCompactClosureL7
            )
    }

    fn is_compact_skeleton(self) -> bool {
        self == Self::PreflightCompactSkeletonL1C
    }

    fn is_compact_values(self) -> bool {
        self == Self::PreflightCompactValuesL2C
    }

    fn is_compact_registers(self) -> bool {
        self == Self::PreflightCompactRegistersL3C
    }

    fn is_compact_memory(self) -> bool {
        self == Self::PreflightCompactMemoryL4C
    }

    fn is_compact_future_access(self) -> bool {
        matches!(
            self,
            Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
        )
    }

    fn is_compact_exceptional(self) -> bool {
        matches!(
            self,
            Self::PreflightCompactExceptionalL6C | Self::PreflightCompactClosureL7
        )
    }

    fn is_compact_layered(self) -> bool {
        self.is_compact_skeleton()
            || self.is_compact_values()
            || self.is_compact_registers()
            || self.is_compact_memory()
            || self.is_compact_future_access()
    }

    fn has_layered_registers(self) -> bool {
        matches!(
            self,
            Self::PreflightCompactRegistersL3C
                | Self::PreflightCompactMemoryL4C
                | Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
                | Self::PreflightRegistersL3
                | Self::PreflightMemoryL4
                | Self::PreflightFutureAccessL5
        )
    }

    fn has_layered_memory(self) -> bool {
        matches!(
            self,
            Self::PreflightCompactMemoryL4C
                | Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
                | Self::PreflightMemoryL4
                | Self::PreflightFutureAccessL5
        )
    }

    fn has_layered_future_access(self) -> bool {
        matches!(
            self,
            Self::PreflightFutureAccessL5
                | Self::PreflightCompactFutureAccessL5C
                | Self::PreflightCompactExceptionalL6C
                | Self::PreflightCompactClosureL7
        )
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
const AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET: usize = 936;
const AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET: usize = 944;
const AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET: usize = 952;
const AOT_CTX_COMPACT_BYTES_CURSOR_OFFSET: usize = 960;
const AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_OFFSET: usize = 968;
const AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_LEN_OFFSET: usize = 976;
const AOT_CTX_LAYERED_NEXT_ACCESS_CURSOR_OFFSET: usize = 984;
const AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET: usize = 992;

const AOT_FALLBACK_DYNAMIC_PC: u32 = 1;
const AOT_FALLBACK_MEMORY_GUARD: u32 = 2;
const AOT_FALLBACK_ECALL: u32 = 3;
const AOT_FALLBACK_EXCEPTIONAL: u32 = 4;
const AOT_ABI_VERSION: u32 = 79;
const AOT_CACHE_MAGIC: &str = "ceno-aot-cache-v6";
const AOT_EMITTER_SCHEMA: &str = "replay-emitter-schema1";
const AOT_INITIAL_EVENT_SEED: usize = 20_000_000;
const AOT_MAX_COMPILE_JOBS: usize = 32;
const AOT_BLOCK_COMPILE_OVERHEAD: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AotEmitterVariant {
    Standard,
    SharedPacked,
    FullyInlinedDiagnostic,
}

impl AotEmitterVariant {
    fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::SharedPacked => "shared-packed",
            Self::FullyInlinedDiagnostic => "fully-inlined-diagnostic",
        }
    }
}

fn selected_emitter_variant(trace_style: AssemblyTraceStyle) -> AotEmitterVariant {
    if trace_style != AssemblyTraceStyle::GpuReplayDirect {
        return AotEmitterVariant::Standard;
    }
    match std::env::var("CENO_AOT_GPU_REPLAY_EMITTER").as_deref() {
        Ok("fully-inlined-diagnostic") => AotEmitterVariant::FullyInlinedDiagnostic,
        _ => AotEmitterVariant::SharedPacked,
    }
}

const AOT_TRACE_MODE_NONE: u32 = 0;
const AOT_TRACE_MODE_CALLBACK: u32 = 1;
const AOT_TRACE_MODE_PREFLIGHT_DIRECT: u32 = 2;
const AOT_TRACE_MODE_FULLTRACER_DIRECT: u32 = 3;
const AOT_TRACE_MODE_GPU_REPLAY_DIRECT: u32 = 4;
const AOT_TRACE_MODE_SKELETON_L1: u32 = 6;
const AOT_TRACE_MODE_VALUES_L2: u32 = 7;
const AOT_TRACE_MODE_REGISTERS_L3: u32 = 8;
const AOT_TRACE_MODE_MEMORY_L4: u32 = 9;
const AOT_TRACE_MODE_FUTURE_ACCESS_L5: u32 = 10;
const AOT_TRACE_MODE_COMPACT_SKELETON_L1C: u32 = 11;
const AOT_TRACE_MODE_COMPACT_VALUES_L2C: u32 = 12;
const AOT_TRACE_MODE_COMPACT_REGISTERS_L3C: u32 = 13;
const AOT_TRACE_MODE_COMPACT_MEMORY_L4C: u32 = 14;
const AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C: u32 = 15;
const AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C: u32 = 16;
const AOT_TRACE_MODE_COMPACT_CLOSURE_L7: u32 = 17;

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
    layered_rs1_previous: Cycle,
    layered_rs2_previous: Cycle,
    layered_rd_previous: Cycle,
    compact_bytes_cursor: *mut usize,
    layered_next_access_events: *const NextAccessEvent,
    layered_next_access_events_len: usize,
    layered_next_access_cursor: *mut usize,
    gpu_replay_packed_block: u32,
    _gpu_replay_packed_block_padding: u32,
}

/// L1C's complete physical row. Disabled L1 fields are absent and are
/// synthesized only by the test decoder. Native code commits these words once
/// in representation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct CompactSkeletonRecord {
    ordinal: u32,
    pc_before: u32,
    pc_after: u32,
    memory_addr: u32,
}

const COMPACT_SKELETON_NO_MEMORY: u32 = u32::MAX;
const _: () = assert!(std::mem::size_of::<CompactSkeletonRecord>() == 16);
const _: () = assert!(std::mem::offset_of!(CompactSkeletonRecord, ordinal) == 0);
const _: () = assert!(std::mem::offset_of!(CompactSkeletonRecord, pc_before) == 4);
const _: () = assert!(std::mem::offset_of!(CompactSkeletonRecord, pc_after) == 8);
const _: () = assert!(std::mem::offset_of!(CompactSkeletonRecord, memory_addr) == 12);

impl CompactSkeletonRecord {
    fn new(ordinal: usize, pc_before: u32, pc_after: u32, memory_addr: Option<WordAddr>) -> Self {
        Self {
            ordinal: u32::try_from(ordinal).expect("L1C ordinal exceeds u32"),
            pc_before,
            pc_after,
            memory_addr: memory_addr.map_or(COMPACT_SKELETON_NO_MEMORY, |addr| addr.0),
        }
    }

    #[cfg(test)]
    fn decode(&self, program: &Program, cycle_start: Cycle) -> crate::StepRecord {
        let instruction_index = self
            .pc_before
            .checked_sub(program.base_address)
            .filter(|offset| offset % PC_STEP_SIZE as u32 == 0)
            .map(|offset| offset as usize / PC_STEP_SIZE)
            .expect("L1C PC is outside the program image");
        let insn = *program
            .instructions
            .get(instruction_index)
            .expect("L1C PC is outside the program image");
        crate::StepRecord::l1_skeleton(
            cycle_start + Cycle::from(self.ordinal) * crate::FullTracer::SUBCYCLES_PER_INSN,
            Change::new(self.pc_before.into(), self.pc_after.into()),
            insn,
            (self.memory_addr != COMPACT_SKELETON_NO_MEMORY).then_some(WordAddr(self.memory_addr)),
        )
    }
}

/// L2C rows share the L1C header and append only the pre-state words required
/// by their instruction family. Post-state is an immutable function of these
/// words and the decoded instruction, so it is reconstructed by the test
/// oracle without adding hot-path stores.
#[derive(Clone, Copy)]
#[repr(C)]
struct CompactValuesR {
    header: CompactSkeletonRecord,
    rs1: Word,
    rs2: Word,
    rd_before: Word,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactValuesI {
    header: CompactSkeletonRecord,
    rs1: Word,
    rd_before: Word,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactValuesBranch {
    header: CompactSkeletonRecord,
    rs1: Word,
    rs2: Word,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactValuesJ {
    header: CompactSkeletonRecord,
    rd_before: Word,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactValuesLoad {
    header: CompactSkeletonRecord,
    rs1: Word,
    rd_before: Word,
    memory_before: Word,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactValuesStore {
    header: CompactSkeletonRecord,
    rs1: Word,
    rs2: Word,
    memory_before: Word,
}

const COMPACT_VALUES_MAX_BYTES: usize = 28;
const _: () = assert!(std::mem::size_of::<CompactValuesR>() == 28);
const _: () = assert!(std::mem::size_of::<CompactValuesI>() == 24);
const _: () = assert!(std::mem::size_of::<CompactValuesBranch>() == 24);
const _: () = assert!(std::mem::size_of::<CompactValuesJ>() == 20);
const _: () = assert!(std::mem::size_of::<CompactValuesLoad>() == 28);
const _: () = assert!(std::mem::size_of::<CompactValuesStore>() == 28);
const _: () = assert!(std::mem::offset_of!(CompactValuesR, rs1) == 16);
const _: () = assert!(std::mem::offset_of!(CompactValuesR, rs2) == 20);
const _: () = assert!(std::mem::offset_of!(CompactValuesR, rd_before) == 24);
const _: () = assert!(std::mem::offset_of!(CompactValuesLoad, memory_before) == 24);
const _: () = assert!(std::mem::offset_of!(CompactValuesStore, memory_before) == 24);

/// L3C uses the established 27-bit predecessor-cycle encoding. Execution order
/// is authoritative, so the row ordinal is carried by the independent row
/// cursor rather than repeated in every physical row.
#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersHeader([u8; 6]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersExceptional([u8; 10]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersR([u8; 28]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersI([u8; 21]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersBranch([u8; 21]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersJ([u8; 13]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersLoad([u8; 25]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactRegistersStore([u8; 25]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactMemoryExceptional([u8; 18]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactMemoryLoad([u8; 28]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactMemoryStore([u8; 28]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactFutureJ([u8; 14]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactFutureLoad([u8; 29]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactFutureStore([u8; 29]);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactFutureR([u8; 29]);

const COMPACT_FUTURE_SYSCALL_MASK_BYTES: usize = 9;

/// L5C syscall masks are kept in one compact arena rather than allocating the
/// generic witness's two `Vec<u8>` masks. Address order and lengths are
/// validated while the authoritative tape cursor is consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct CompactFutureSyscallMask {
    reg_count: u8,
    mem_count: u8,
    bits: [u8; COMPACT_FUTURE_SYSCALL_MASK_BYTES],
}

/// One fixed record per ECALL. The row stays in the L5C arena; this side
/// record supplies the ECALL-code read and either a complete generic syscall
/// index plus a slice in the compact operation stream, or `NO_SYSCALL` for an
/// ECALL such as HALT that produces no witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct CompactL6SyscallHeader([u8; 30]);

/// Packed `WriteOp` representation used by the L6C variable syscall stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct CompactL6WriteOp([u8; 20]);

impl CompactL6SyscallHeader {
    fn new(
        cycle: Cycle,
        syscall_index: u32,
        op_offset: u32,
        reg_count: u8,
        mem_count: u8,
        ecall_code: Word,
        ecall_previous_cycle: Cycle,
    ) -> Self {
        let mut bytes = [0; 30];
        bytes[0..8].copy_from_slice(&cycle.to_le_bytes());
        bytes[8..12].copy_from_slice(&syscall_index.to_le_bytes());
        bytes[12..16].copy_from_slice(&op_offset.to_le_bytes());
        bytes[16] = reg_count;
        bytes[17] = mem_count;
        bytes[18..22].copy_from_slice(&ecall_code.to_le_bytes());
        bytes[22..30].copy_from_slice(&ecall_previous_cycle.to_le_bytes());
        Self(bytes)
    }

    #[cfg(test)]
    fn cycle(self) -> Cycle {
        Cycle::from_le_bytes(self.0[0..8].try_into().unwrap())
    }

    #[cfg(test)]
    fn syscall_index(self) -> u32 {
        u32::from_le_bytes(self.0[8..12].try_into().unwrap())
    }

    #[cfg(test)]
    fn op_offset(self) -> usize {
        u32::from_le_bytes(self.0[12..16].try_into().unwrap()) as usize
    }

    #[cfg(test)]
    fn reg_count(self) -> usize {
        self.0[16] as usize
    }

    #[cfg(test)]
    fn mem_count(self) -> usize {
        self.0[17] as usize
    }

    #[cfg(test)]
    fn ecall_code(self) -> Word {
        Word::from_le_bytes(self.0[18..22].try_into().unwrap())
    }

    #[cfg(test)]
    fn ecall_previous_cycle(self) -> Cycle {
        Cycle::from_le_bytes(self.0[22..30].try_into().unwrap())
    }
}

impl CompactL6WriteOp {
    fn new(op: crate::WriteOp) -> Self {
        let mut bytes = [0; 20];
        bytes[0..4].copy_from_slice(&op.addr.0.to_le_bytes());
        bytes[4..8].copy_from_slice(&op.value.before.to_le_bytes());
        bytes[8..12].copy_from_slice(&op.value.after.to_le_bytes());
        bytes[12..20].copy_from_slice(&op.previous_cycle.to_le_bytes());
        Self(bytes)
    }

    #[cfg(test)]
    fn decode(self) -> crate::WriteOp {
        crate::WriteOp {
            addr: WordAddr(u32::from_le_bytes(self.0[0..4].try_into().unwrap())),
            value: Change::new(
                Word::from_le_bytes(self.0[4..8].try_into().unwrap()),
                Word::from_le_bytes(self.0[8..12].try_into().unwrap()),
            ),
            previous_cycle: Cycle::from_le_bytes(self.0[12..20].try_into().unwrap()),
        }
    }
}

const COMPACT_REGISTERS_PC_BITS: usize = 20;
const COMPACT_REGISTERS_RAW_BITS: usize = 25;
const COMPACT_REGISTERS_CYCLE_BITS: usize = 27;
const COMPACT_REGISTERS_MAX_BYTES: usize = 28;
const _: () = assert!(std::mem::size_of::<CompactRegistersHeader>() == 6);
const _: () = assert!(std::mem::size_of::<CompactRegistersExceptional>() == 10);
const _: () = assert!(std::mem::size_of::<CompactRegistersR>() == 28);
const _: () = assert!(std::mem::size_of::<CompactRegistersI>() == 21);
const _: () = assert!(std::mem::size_of::<CompactRegistersBranch>() == 21);
const _: () = assert!(std::mem::size_of::<CompactRegistersJ>() == 13);
const _: () = assert!(std::mem::size_of::<CompactRegistersLoad>() == 25);
const _: () = assert!(std::mem::size_of::<CompactRegistersStore>() == 25);
const _: () = assert!(std::mem::size_of::<CompactMemoryExceptional>() == 18);
const _: () = assert!(std::mem::size_of::<CompactMemoryLoad>() == 28);
const _: () = assert!(std::mem::size_of::<CompactMemoryStore>() == 28);
const _: () = assert!(std::mem::size_of::<CompactFutureJ>() == 14);
const _: () = assert!(std::mem::size_of::<CompactFutureLoad>() == 29);
const _: () = assert!(std::mem::size_of::<CompactFutureStore>() == 29);
const _: () = assert!(std::mem::size_of::<CompactFutureR>() == 29);
const _: () = assert!(std::mem::size_of::<CompactFutureSyscallMask>() == 11);
const _: () = assert!(std::mem::size_of::<CompactL6SyscallHeader>() == 30);
const _: () = assert!(std::mem::size_of::<CompactL6WriteOp>() == 20);
const _: () = assert!(std::mem::size_of::<NextAccessEvent>() == 24);
const _: () = assert!(std::mem::offset_of!(NextAccessEvent, source_cycle) == 0);
const _: () = assert!(std::mem::offset_of!(NextAccessEvent, address) == 16);

fn compact_values_row_size(insn: Instruction) -> usize {
    16 + 4 * usize::from(native_step_reads_rs1(insn.kind))
        + 4 * usize::from(native_step_reads_rs2(insn.kind))
        + 4 * usize::from(native_step_writes_rd(insn.kind))
        + 4 * usize::from(
            native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
        )
}

fn compact_registers_row_size(insn: Instruction) -> usize {
    let bits = COMPACT_REGISTERS_PC_BITS
        + COMPACT_REGISTERS_RAW_BITS
        + (COMPACT_REGISTERS_CYCLE_BITS + 32)
            * (usize::from(native_step_reads_rs1(insn.kind))
                + usize::from(native_step_reads_rs2(insn.kind))
                + usize::from(native_step_writes_rd(insn.kind)))
        + 32 * usize::from(
            native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
        )
        + 32 * usize::from(insn.kind == InsnKind::ECALL);
    bits.div_ceil(8)
}

fn compact_memory_row_size(insn: Instruction) -> usize {
    let memory =
        usize::from(native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind));
    let bits = COMPACT_REGISTERS_PC_BITS
        + COMPACT_REGISTERS_RAW_BITS
        + (COMPACT_REGISTERS_CYCLE_BITS + 32)
            * (usize::from(native_step_reads_rs1(insn.kind))
                + usize::from(native_step_reads_rs2(insn.kind))
                + usize::from(native_step_writes_rd(insn.kind)))
        + (32 + COMPACT_REGISTERS_CYCLE_BITS) * memory
        + 96 * usize::from(insn.kind == InsnKind::ECALL);
    bits.div_ceil(8)
}

fn compact_future_access_row_size(insn: Instruction) -> usize {
    let row_mask_bits = usize::from(native_step_reads_rs1(insn.kind))
        + usize::from(native_step_reads_rs2(insn.kind))
        + usize::from(native_step_writes_rd(insn.kind))
        + usize::from(native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind));
    let memory =
        usize::from(native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind));
    let bits = COMPACT_REGISTERS_PC_BITS
        + COMPACT_REGISTERS_RAW_BITS
        + (COMPACT_REGISTERS_CYCLE_BITS + 32)
            * (usize::from(native_step_reads_rs1(insn.kind))
                + usize::from(native_step_reads_rs2(insn.kind))
                + usize::from(native_step_writes_rd(insn.kind)))
        + (32 + COMPACT_REGISTERS_CYCLE_BITS) * memory
        + 96 * usize::from(insn.kind == InsnKind::ECALL)
        + row_mask_bits;
    bits.div_ceil(8)
}

#[cfg(test)]
fn compact_values_rd_after(
    insn: Instruction,
    pc: u32,
    rs1: Word,
    rs2: Word,
    memory_before: Word,
    memory_addr: Option<WordAddr>,
) -> Word {
    let imm = insn.imm as u32;
    match insn.kind {
        InsnKind::ADD => rs1.wrapping_add(rs2),
        InsnKind::SUB => rs1.wrapping_sub(rs2),
        InsnKind::XOR => rs1 ^ rs2,
        InsnKind::OR => rs1 | rs2,
        InsnKind::AND => rs1 & rs2,
        InsnKind::SLL => rs1 << (rs2 & 0x1f),
        InsnKind::SRL => rs1 >> (rs2 & 0x1f),
        InsnKind::SRA => ((rs1 as i32) >> (rs2 & 0x1f)) as u32,
        InsnKind::SLT => u32::from((rs1 as i32) < (rs2 as i32)),
        InsnKind::SLTU => u32::from(rs1 < rs2),
        InsnKind::MUL => rs1.wrapping_mul(rs2),
        InsnKind::MULH => (((rs1 as i32 as i64).wrapping_mul(rs2 as i32 as i64)) >> 32) as u32,
        InsnKind::MULHSU => ((rs1 as i32 as i64).wrapping_mul(rs2 as i64) >> 32) as u32,
        InsnKind::MULHU => ((rs1 as u64).wrapping_mul(rs2 as u64) >> 32) as u32,
        InsnKind::DIV => {
            if rs2 == 0 {
                u32::MAX
            } else {
                (rs1 as i32).wrapping_div(rs2 as i32) as u32
            }
        }
        InsnKind::DIVU => {
            if rs2 == 0 {
                u32::MAX
            } else {
                rs1 / rs2
            }
        }
        InsnKind::REM => {
            if rs2 == 0 {
                rs1
            } else {
                (rs1 as i32).wrapping_rem(rs2 as i32) as u32
            }
        }
        InsnKind::REMU => {
            if rs2 == 0 {
                rs1
            } else {
                rs1 % rs2
            }
        }
        InsnKind::ADDI => rs1.wrapping_add(imm),
        InsnKind::XORI => rs1 ^ imm,
        InsnKind::ORI => rs1 | imm,
        InsnKind::ANDI => rs1 & imm,
        InsnKind::SLLI => rs1 << (imm & 0x1f),
        InsnKind::SRLI => rs1 >> (imm & 0x1f),
        InsnKind::SRAI => ((rs1 as i32) >> (imm & 0x1f)) as u32,
        InsnKind::SLTI => u32::from((rs1 as i32) < (imm as i32)),
        InsnKind::SLTIU => u32::from(rs1 < imm),
        InsnKind::JAL | InsnKind::JALR => pc.wrapping_add(PC_STEP_SIZE as u32),
        InsnKind::LB | InsnKind::LH | InsnKind::LW | InsnKind::LBU | InsnKind::LHU => {
            let byte_addr = rs1.wrapping_add(imm);
            debug_assert_eq!(memory_addr, Some(ByteAddr(byte_addr).waddr()));
            let shift = 8 * (byte_addr & 3);
            match insn.kind {
                InsnKind::LB => ((memory_before >> shift) as u8 as i8 as i32) as u32,
                InsnKind::LH => ((memory_before >> shift) as u16 as i16 as i32) as u32,
                InsnKind::LW => memory_before,
                InsnKind::LBU => (memory_before >> shift) & 0xff,
                InsnKind::LHU => (memory_before >> shift) & 0xffff,
                _ => unreachable!(),
            }
        }
        #[cfg(feature = "u16limb_circuit")]
        InsnKind::LUI => imm,
        #[cfg(feature = "u16limb_circuit")]
        InsnKind::AUIPC => pc.wrapping_add(imm),
        _ => crate::StepRecord::L1_POISON_WORD,
    }
}

#[cfg(test)]
fn compact_values_memory_after(
    insn: Instruction,
    rs1: Word,
    rs2: Word,
    memory_before: Word,
) -> Word {
    if native_step_loads_memory(insn.kind) {
        return memory_before;
    }
    let byte_addr = rs1.wrapping_add(insn.imm as u32);
    let shift = 8 * (byte_addr & 3);
    match insn.kind {
        InsnKind::SB => (memory_before & !(0xff << shift)) | ((rs2 & 0xff) << shift),
        InsnKind::SH => (memory_before & !(0xffff << shift)) | ((rs2 & 0xffff) << shift),
        InsnKind::SW => rs2,
        _ => crate::StepRecord::L1_POISON_WORD,
    }
}

#[cfg(test)]
fn decode_compact_values(
    bytes: &[u8],
    program: &Program,
    cycle_start: Cycle,
) -> Vec<crate::StepRecord> {
    fn word(bytes: &[u8], offset: &mut usize) -> Word {
        let value = Word::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;
        value
    }

    let mut records = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let row_start = offset;
        let ordinal = word(bytes, &mut offset);
        let pc_before = word(bytes, &mut offset);
        let pc_after = word(bytes, &mut offset);
        let encoded_memory_addr = word(bytes, &mut offset);
        let instruction_index = pc_before
            .checked_sub(program.base_address)
            .filter(|pc_offset| pc_offset % PC_STEP_SIZE as u32 == 0)
            .map(|pc_offset| pc_offset as usize / PC_STEP_SIZE)
            .expect("L2C PC is outside the program image");
        let insn = *program
            .instructions
            .get(instruction_index)
            .expect("L2C PC is outside the program image");
        let rs1 = if native_step_reads_rs1(insn.kind) {
            word(bytes, &mut offset)
        } else {
            crate::StepRecord::L1_POISON_WORD
        };
        let rs2 = if native_step_reads_rs2(insn.kind) {
            word(bytes, &mut offset)
        } else {
            crate::StepRecord::L1_POISON_WORD
        };
        let rd_before = if native_step_writes_rd(insn.kind) {
            word(bytes, &mut offset)
        } else {
            crate::StepRecord::L1_POISON_WORD
        };
        let memory_before =
            if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
                word(bytes, &mut offset)
            } else {
                crate::StepRecord::L1_POISON_WORD
            };
        assert_eq!(offset - row_start, compact_values_row_size(insn));
        let memory_addr = (encoded_memory_addr != COMPACT_SKELETON_NO_MEMORY)
            .then_some(WordAddr(encoded_memory_addr));
        let rd_after =
            compact_values_rd_after(insn, pc_before, rs1, rs2, memory_before, memory_addr);
        let memory_value = memory_addr.map(|_| {
            Change::new(
                memory_before,
                compact_values_memory_after(insn, rs1, rs2, memory_before),
            )
        });
        records.push(crate::StepRecord::l2_values(
            cycle_start + Cycle::from(ordinal) * crate::FullTracer::SUBCYCLES_PER_INSN,
            Change::new(pc_before.into(), pc_after.into()),
            insn,
            memory_addr,
            rs1,
            rs2,
            Change::new(rd_before, rd_after),
            memory_value,
        ));
    }
    records
}

#[cfg(test)]
fn decode_compact_registers(
    bytes: &[u8],
    program: &Program,
    cycle_start: Cycle,
    memory_l4: Option<(
        ByteAddr,
        ByteAddr,
        &std::ops::Range<u32>,
        &std::ops::Range<u32>,
    )>,
    future_l5: bool,
) -> Vec<crate::StepRecord> {
    fn bits(bytes: &[u8], row_start: usize, bit: &mut usize, width: usize) -> u32 {
        let mut value = 0u64;
        for byte_index in 0..width.div_ceil(8) + 1 {
            let source = row_start + (*bit / 8) + byte_index;
            if source < bytes.len() {
                value |= u64::from(bytes[source]) << (byte_index * 8);
            }
        }
        value >>= *bit % 8;
        *bit += width;
        (value & ((1u64 << width) - 1)) as u32
    }
    fn access(bytes: &[u8], row_start: usize, bit: &mut usize) -> (Cycle, Word) {
        (
            Cycle::from(bits(bytes, row_start, bit, COMPACT_REGISTERS_CYCLE_BITS)),
            bits(bytes, row_start, bit, 32),
        )
    }
    fn next_pc(insn: Instruction, pc: u32, rs1: Word, rs2: Word) -> u32 {
        let sequential = pc.wrapping_add(PC_STEP_SIZE as u32);
        match insn.kind {
            InsnKind::BEQ => (rs1 == rs2).then(|| pc.wrapping_add(insn.imm as u32)),
            InsnKind::BNE => (rs1 != rs2).then(|| pc.wrapping_add(insn.imm as u32)),
            InsnKind::BLT => {
                ((rs1 as i32) < (rs2 as i32)).then(|| pc.wrapping_add(insn.imm as u32))
            }
            InsnKind::BGE => {
                ((rs1 as i32) >= (rs2 as i32)).then(|| pc.wrapping_add(insn.imm as u32))
            }
            InsnKind::BLTU => (rs1 < rs2).then(|| pc.wrapping_add(insn.imm as u32)),
            InsnKind::BGEU => (rs1 >= rs2).then(|| pc.wrapping_add(insn.imm as u32)),
            InsnKind::JAL => return pc.wrapping_add(insn.imm as u32),
            InsnKind::JALR => return rs1.wrapping_add(insn.imm as u32) & !1,
            _ => return sequential,
        }
        .unwrap_or(sequential)
    }

    let mut records = Vec::new();
    let mut offset = 0;
    let (mut max_heap, mut max_hint) = memory_l4
        .map(|(max_heap, max_hint, _, _)| (max_heap, max_hint))
        .unwrap_or_default();
    while offset < bytes.len() {
        let row_start = offset;
        let mut bit = 0;
        let instruction_index =
            bits(bytes, row_start, &mut bit, COMPACT_REGISTERS_PC_BITS) as usize;
        let pc_before = program
            .base_address
            .wrapping_add((instruction_index * PC_STEP_SIZE) as u32);
        let insn = *program
            .instructions
            .get(instruction_index)
            .unwrap_or_else(|| panic!("L3C PC index {instruction_index} is outside the program image at byte {row_start}"));
        assert_eq!(
            bits(bytes, row_start, &mut bit, COMPACT_REGISTERS_RAW_BITS,),
            insn.raw >> 7,
            "L3C raw instruction payload mismatch"
        );
        let (rs1_previous, rs1) = native_step_reads_rs1(insn.kind)
            .then(|| access(bytes, row_start, &mut bit))
            .unwrap_or((
                crate::StepRecord::L1_POISON_CYCLE,
                crate::StepRecord::L1_POISON_WORD,
            ));
        let (rs2_previous, rs2) = native_step_reads_rs2(insn.kind)
            .then(|| access(bytes, row_start, &mut bit))
            .unwrap_or((
                crate::StepRecord::L1_POISON_CYCLE,
                crate::StepRecord::L1_POISON_WORD,
            ));
        let (rd_previous, rd_before) = native_step_writes_rd(insn.kind)
            .then(|| access(bytes, row_start, &mut bit))
            .unwrap_or((
                crate::StepRecord::L1_POISON_CYCLE,
                crate::StepRecord::L1_POISON_WORD,
            ));
        let memory_before =
            if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
                bits(bytes, row_start, &mut bit, 32)
            } else {
                crate::StepRecord::L1_POISON_WORD
            };
        let memory_previous_cycle = if memory_l4.is_some()
            && (native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind))
        {
            Some(Cycle::from(bits(
                bytes,
                row_start,
                &mut bit,
                COMPACT_REGISTERS_CYCLE_BITS,
            )))
        } else {
            None
        };
        let pc_after = if insn.kind == InsnKind::ECALL {
            bits(bytes, row_start, &mut bit, 32)
        } else {
            next_pc(insn, pc_before, rs1, rs2)
        };
        let bounds_before = (max_heap, max_hint);
        if let Some((_, _, heap, hints)) = memory_l4 {
            if insn.kind == InsnKind::ECALL {
                max_heap = ByteAddr(bits(bytes, row_start, &mut bit, 32));
                max_hint = ByteAddr(bits(bytes, row_start, &mut bit, 32));
            } else if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
                let start = rs1.wrapping_add(insn.imm as u32) & !3;
                let access_end = ByteAddr(start.wrapping_add(WORD_SIZE as u32));
                if heap.contains(&start) {
                    max_heap = max_heap.max(access_end);
                } else if hints.contains(&start) {
                    max_hint = max_hint.max(access_end);
                }
            }
        }
        let mut future_access_mask = 0;
        if future_l5 {
            for (enabled, mask) in [
                (
                    native_step_reads_rs1(insn.kind),
                    crate::StepRecord::FUTURE_ACCESS_RS1,
                ),
                (
                    native_step_reads_rs2(insn.kind),
                    crate::StepRecord::FUTURE_ACCESS_RS2,
                ),
                (
                    native_step_writes_rd(insn.kind),
                    crate::StepRecord::FUTURE_ACCESS_RD,
                ),
                (
                    native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
                    crate::StepRecord::FUTURE_ACCESS_MEM,
                ),
            ] {
                if enabled && bits(bytes, row_start, &mut bit, 1) != 0 {
                    future_access_mask |= mask;
                }
            }
        }
        let row_size = if future_l5 {
            compact_future_access_row_size(insn)
        } else if memory_l4.is_some() {
            compact_memory_row_size(insn)
        } else {
            compact_registers_row_size(insn)
        };
        assert_eq!(bit.div_ceil(8), row_size);
        offset += row_size;
        let memory_addr = (native_step_loads_memory(insn.kind)
            || native_step_stores_memory(insn.kind))
        .then(|| ByteAddr(rs1.wrapping_add(insn.imm as u32)).waddr());
        let rd_after =
            compact_values_rd_after(insn, pc_before, rs1, rs2, memory_before, memory_addr);
        let memory_value = memory_addr.map(|_| {
            Change::new(
                memory_before,
                compact_values_memory_after(insn, rs1, rs2, memory_before),
            )
        });
        let cycle = cycle_start
            + Cycle::try_from(records.len()).unwrap() * crate::FullTracer::SUBCYCLES_PER_INSN;
        let mut record = if memory_l4.is_some() {
            crate::StepRecord::l4_memory(
                cycle,
                Change::new(pc_before.into(), pc_after.into()),
                insn,
                memory_addr,
                rs1,
                rs2,
                Change::new(rd_before, rd_after),
                memory_value,
                [rs1_previous, rs2_previous, rd_previous],
                memory_previous_cycle,
                Change::new(bounds_before.0, max_heap),
                Change::new(bounds_before.1, max_hint),
            )
        } else {
            crate::StepRecord::l3_registers(
                cycle,
                Change::new(pc_before.into(), pc_after.into()),
                insn,
                memory_addr,
                rs1,
                rs2,
                Change::new(rd_before, rd_after),
                memory_value,
                [rs1_previous, rs2_previous, rd_previous],
            )
        };
        if future_l5 {
            record.clear_future_access_mask();
            record.set_future_access_mask(future_access_mask);
        }
        records.push(record);
    }
    records
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
    layered_cycle: Cycle,
    layered_registers_enabled: bool,
    layered_register_latest: [Cycle; VMState::<PureAotTracer>::REG_COUNT],
    layered_max_heap: ByteAddr,
    layered_max_hint: ByteAddr,
    layered_heap: std::ops::Range<u32>,
    layered_hints: std::ops::Range<u32>,
    layered_memory_enabled: bool,
    layered_future_access_enabled: bool,
    layered_compact_future_access_enabled: bool,
    layered_compact_exceptional_enabled: bool,
    layered_next_accesses: Arc<NextCycleAccess>,
    layered_next_access_cursor: usize,
    layered_syscall_future_accesses: Vec<LayeredSyscallFutureAccess>,
    layered_compact_syscall_masks: Vec<CompactFutureSyscallMask>,
    layered_compact_l6_syscalls: Vec<CompactL6SyscallHeader>,
    layered_compact_l6_ops: Vec<CompactL6WriteOp>,
    layered_compact_l6_latest: BTreeMap<WordAddr, Cycle>,
    layered_compact_l6_pending_syscall: Option<(u32, u32, u8, u8)>,
    layered_compact_l6_pending_ecall: Option<(Word, Cycle)>,
    layered_compact_l6_pending_arg0: Option<(Word, Cycle)>,
}

#[derive(Debug, PartialEq, Eq)]
struct LayeredSyscallFutureAccess {
    cycle: Cycle,
    reg_addresses: Vec<WordAddr>,
    mem_addresses: Vec<WordAddr>,
    reg_masks: Vec<u8>,
    mem_masks: Vec<u8>,
}

struct LayeredRegisterState {
    cycle: *mut Cycle,
    latest: *mut Cycle,
    max_heap: *mut ByteAddr,
    max_hint: *mut ByteAddr,
}

impl PureAotTracer {
    fn enable_layered_memory(&mut self) {
        self.layered_registers_enabled = true;
        self.layered_memory_enabled = true;
    }

    fn enable_layered_future_access(&mut self) {
        self.layered_memory_enabled = true;
        self.layered_future_access_enabled = true;
    }

    fn enable_compact_future_access(&mut self) {
        self.enable_layered_future_access();
        self.layered_compact_future_access_enabled = true;
    }

    fn enable_compact_exceptional(&mut self) {
        self.enable_compact_future_access();
        self.layered_compact_exceptional_enabled = true;
    }

    fn record_compact_l6_syscall(&mut self, witness: &SyscallWitness) {
        if !self.layered_compact_exceptional_enabled {
            return;
        }
        let reg_count =
            u8::try_from(witness.reg_ops.len()).expect("L6C syscall reg count overflow");
        let mem_count =
            u8::try_from(witness.mem_ops.len()).expect("L6C syscall mem count overflow");
        let op_offset = u32::try_from(self.layered_compact_l6_ops.len())
            .expect("L6C syscall operation offset overflow");
        let syscall_index = u32::try_from(self.layered_compact_syscall_masks.len() - 1)
            .expect("L6C syscall index overflow");
        self.layered_compact_l6_ops
            .extend(witness.reg_ops.iter().copied().map(CompactL6WriteOp::new));
        self.layered_compact_l6_ops
            .extend(witness.mem_ops.iter().copied().map(CompactL6WriteOp::new));
        assert!(
            self.layered_compact_l6_pending_syscall
                .replace((syscall_index, op_offset, reg_count, mem_count))
                .is_none(),
            "Only one syscall per L6C ECALL"
        );
    }

    fn finish_compact_l6_ecall(&mut self) {
        if !self.layered_compact_exceptional_enabled {
            return;
        }
        let (ecall_code, ecall_previous_cycle) = self
            .layered_compact_l6_pending_ecall
            .take()
            .expect("L6C ECALL must record its code-register read");
        let (syscall_index, op_offset, reg_count, mem_count) =
            if let Some(pending) = self.layered_compact_l6_pending_syscall.take() {
                assert!(
                    self.layered_compact_l6_pending_arg0.is_none(),
                    "witness-producing L6C ECALL must not have a second direct register read"
                );
                pending
            } else {
                let op_offset = u32::try_from(self.layered_compact_l6_ops.len())
                    .expect("L6C syscall operation offset overflow");
                let reg_count = if let Some((value, previous_cycle)) =
                    self.layered_compact_l6_pending_arg0.take()
                {
                    self.layered_compact_l6_ops
                        .push(CompactL6WriteOp::new(crate::WriteOp {
                            addr: Platform::register_vma(Platform::reg_arg0()).into(),
                            value: Change::new(value, value),
                            previous_cycle,
                        }));
                    1
                } else {
                    0
                };
                (crate::StepRecord::NO_SYSCALL, op_offset, reg_count, 0)
            };
        self.layered_compact_l6_syscalls
            .push(CompactL6SyscallHeader::new(
                self.layered_cycle,
                syscall_index,
                op_offset,
                reg_count,
                mem_count,
                ecall_code,
                ecall_previous_cycle,
            ));
    }

    #[cfg(test)]
    fn decode_compact_l6_syscalls(&self) -> Vec<SyscallWitness> {
        self.layered_compact_l6_syscalls
            .iter()
            .copied()
            .filter(|header| header.syscall_index() != crate::StepRecord::NO_SYSCALL)
            .map(|header| {
                let expected_index = header.syscall_index() as usize;
                let start = header.op_offset();
                let reg_end = start + header.reg_count();
                let end = reg_end + header.mem_count();
                let mask = self.layered_compact_syscall_masks[expected_index];
                assert_eq!(mask.reg_count as usize, header.reg_count());
                assert_eq!(mask.mem_count as usize, header.mem_count());
                let future =
                    |index: usize| u8::from(mask.bits[index / 8] & (1 << (index % 8)) != 0);
                SyscallWitness {
                    reg_ops: self.layered_compact_l6_ops[start..reg_end]
                        .iter()
                        .copied()
                        .map(CompactL6WriteOp::decode)
                        .collect(),
                    mem_ops: self.layered_compact_l6_ops[reg_end..end]
                        .iter()
                        .copied()
                        .map(CompactL6WriteOp::decode)
                        .collect(),
                    reg_future_access: (0..header.reg_count()).map(future).collect(),
                    mem_future_access: (0..header.mem_count())
                        .map(|index| future(header.reg_count() + index))
                        .collect(),
                }
            })
            .collect()
    }

    fn compact_future_access_native_state(
        &mut self,
    ) -> (*const NextAccessEvent, usize, *mut usize) {
        (
            self.layered_next_accesses.events().as_ptr(),
            self.layered_next_accesses.events().len(),
            &mut self.layered_next_access_cursor,
        )
    }

    fn consume_compact_row_future_accesses(
        &mut self,
        cycle: Cycle,
        accesses: &[(Cycle, WordAddr, u8)],
    ) -> u8 {
        if !self.layered_compact_future_access_enabled {
            return 0;
        }
        let end_cycle = cycle + Self::SUBCYCLES_PER_INSN;
        let mut mask = 0;
        while let Some(event) = self
            .layered_next_accesses
            .events()
            .get(self.layered_next_access_cursor)
            .copied()
        {
            assert!(
                event.source_cycle >= cycle,
                "L5C skipped future-access event before compact row"
            );
            if event.source_cycle >= end_cycle {
                break;
            }
            let subcycle = event.source_cycle - cycle;
            let (_, _, bit) = accesses
                .iter()
                .find(|(expected_subcycle, address, _)| {
                    *expected_subcycle == subcycle && *address == event.address
                })
                .unwrap_or_else(|| {
                    panic!(
                        "L5C access/tape mismatch at cycle {} address {:?}",
                        event.source_cycle, event.address
                    )
                });
            mask |= *bit;
            self.layered_next_access_cursor += 1;
        }
        mask
    }

    fn consume_compact_syscall_future_accesses(
        &mut self,
        reg_addresses: &[WordAddr],
        mem_addresses: &[WordAddr],
    ) {
        assert!(
            reg_addresses.len() <= 2,
            "L5C syscall register mask overflow"
        );
        assert!(
            reg_addresses.len() + mem_addresses.len()
                <= COMPACT_FUTURE_SYSCALL_MASK_BYTES * u8::BITS as usize,
            "L5C syscall mask exceeds compact family"
        );
        let cycle = self.layered_cycle;
        let end_cycle = cycle + Self::SUBCYCLES_PER_INSN;
        let mut record = CompactFutureSyscallMask {
            reg_count: reg_addresses.len() as u8,
            mem_count: mem_addresses.len() as u8,
            bits: [0; COMPACT_FUTURE_SYSCALL_MASK_BYTES],
        };
        while let Some(event) = self
            .layered_next_accesses
            .events()
            .get(self.layered_next_access_cursor)
            .copied()
        {
            assert!(
                event.source_cycle >= cycle,
                "L5C skipped future-access event before compact syscall"
            );
            if event.source_cycle >= end_cycle {
                break;
            }
            let subcycle = event.source_cycle - cycle;
            let (addresses, base) = match subcycle {
                Self::SUBCYCLE_RD => (reg_addresses, 0),
                Self::SUBCYCLE_MEM => (mem_addresses, reg_addresses.len()),
                _ => panic!(
                    "L5C syscall tape has non-syscall subcycle {} at cycle {}",
                    subcycle, event.source_cycle
                ),
            };
            let index = addresses
                .iter()
                .rposition(|address| *address == event.address)
                .unwrap_or_else(|| {
                    panic!(
                        "L5C syscall access/tape address mismatch: cycle={cycle} cursor={} event_cycle={} subcycle={subcycle} event_address={:?} reg_addresses={reg_addresses:?} mem_addresses={mem_addresses:?}",
                        self.layered_next_access_cursor,
                        event.source_cycle,
                        event.address,
                    )
                });
            let bit = base + index;
            record.bits[bit / 8] |= 1 << (bit % 8);
            self.layered_next_access_cursor += 1;
        }
        self.layered_compact_syscall_masks.push(record);
    }

    fn record_layered_syscall_addresses(
        &mut self,
        reg_addresses: Vec<WordAddr>,
        mem_addresses: Vec<WordAddr>,
    ) {
        if !self.layered_future_access_enabled {
            return;
        }
        if self.layered_compact_future_access_enabled {
            self.consume_compact_syscall_future_accesses(&reg_addresses, &mem_addresses);
            return;
        }
        self.layered_syscall_future_accesses
            .push(LayeredSyscallFutureAccess {
                cycle: self.layered_cycle,
                reg_masks: vec![0; reg_addresses.len()],
                mem_masks: vec![0; mem_addresses.len()],
                reg_addresses,
                mem_addresses,
            });
    }

    fn annotate_layered_future_accesses(&mut self, records: &mut [crate::StepRecord]) {
        if !self.layered_future_access_enabled || records.is_empty() {
            return;
        }
        let start_cycle = records[0].cycle();
        let end_cycle = records[records.len() - 1].cycle() + Self::SUBCYCLES_PER_INSN;
        for record in records.iter_mut() {
            record.clear_future_access_mask();
        }
        while let Some(event) = self
            .layered_next_accesses
            .events()
            .get(self.layered_next_access_cursor)
            .copied()
        {
            assert!(
                event.source_cycle >= start_cycle,
                "L5 skipped future-access event before replay range"
            );
            if event.source_cycle >= end_cycle {
                break;
            }
            let index =
                usize::try_from((event.source_cycle - start_cycle) / Self::SUBCYCLES_PER_INSN)
                    .expect("L5 future-access record offset does not fit usize");
            let record = &mut records[index];
            let subcycle = event.source_cycle - record.cycle();
            let mask = match subcycle {
                Self::SUBCYCLE_RS1 if record.rs1().is_some_and(|op| op.addr == event.address) => {
                    crate::StepRecord::FUTURE_ACCESS_RS1
                }
                Self::SUBCYCLE_RS2 if record.rs2().is_some_and(|op| op.addr == event.address) => {
                    crate::StepRecord::FUTURE_ACCESS_RS2
                }
                Self::SUBCYCLE_RD if record.rd().is_some_and(|op| op.addr == event.address) => {
                    crate::StepRecord::FUTURE_ACCESS_RD
                }
                Self::SUBCYCLE_MEM
                    if record
                        .memory_op()
                        .is_some_and(|op| op.addr == event.address) =>
                {
                    crate::StepRecord::FUTURE_ACCESS_MEM
                }
                Self::SUBCYCLE_RD | Self::SUBCYCLE_MEM if record.insn().kind == InsnKind::ECALL => {
                    let syscall = self
                        .layered_syscall_future_accesses
                        .iter_mut()
                        .find(|syscall| syscall.cycle == record.cycle())
                        .expect("L5 future-access event has no matching syscall");
                    let (addresses, masks) = if subcycle == Self::SUBCYCLE_RD {
                        (&syscall.reg_addresses, &mut syscall.reg_masks)
                    } else {
                        (&syscall.mem_addresses, &mut syscall.mem_masks)
                    };
                    let index = addresses
                        .iter()
                        .rposition(|address| *address == event.address)
                        .expect("L5 syscall access/tape address mismatch");
                    masks[index] = 1;
                    0
                }
                _ => panic!("L5 access/tape mismatch at cycle {}", event.source_cycle),
            };
            record.set_future_access_mask(mask);
            self.layered_next_access_cursor += 1;
        }
        assert!(
            self.layered_next_accesses
                .events()
                .get(self.layered_next_access_cursor)
                .is_none_or(|event| event.source_cycle >= end_cycle),
            "L5 left a future-access event before replay range end"
        );
    }

    fn assert_layered_future_accesses_consumed(&self) {
        if self.layered_future_access_enabled {
            assert_eq!(
                self.layered_next_access_cursor,
                self.layered_next_accesses.events().len(),
                "L5 consumed {} of {} future-access events",
                self.layered_next_access_cursor,
                self.layered_next_accesses.events().len()
            );
        }
    }

    fn update_layered_bounds(&mut self, addr: WordAddr) {
        if !self.layered_memory_enabled {
            return;
        }
        let start = addr.baddr().0;
        let access_end = ByteAddr(start.wrapping_add(WORD_SIZE as u32));
        if self.layered_heap.contains(&start) {
            self.layered_max_heap = self.layered_max_heap.max(access_end);
        } else if self.layered_hints.contains(&start) {
            self.layered_max_hint = self.layered_max_hint.max(access_end);
        }
    }

    fn layered_register_state(&mut self) -> LayeredRegisterState {
        self.layered_registers_enabled = true;
        LayeredRegisterState {
            cycle: &mut self.layered_cycle,
            latest: self.layered_register_latest.as_mut_ptr(),
            max_heap: &mut self.layered_max_heap,
            max_hint: &mut self.layered_max_hint,
        }
    }
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
            layered_cycle: Self::SUBCYCLES_PER_INSN,
            layered_registers_enabled: false,
            layered_register_latest: [0; VMState::<PureAotTracer>::REG_COUNT],
            layered_max_heap: ByteAddr::from(_platform.heap.start),
            layered_max_hint: ByteAddr::from(_platform.hints.start),
            layered_heap: _platform.heap.clone(),
            layered_hints: _platform.hints.clone(),
            layered_memory_enabled: false,
            layered_future_access_enabled: false,
            layered_compact_future_access_enabled: false,
            layered_compact_exceptional_enabled: false,
            layered_next_accesses: Arc::new(NextCycleAccess::default()),
            layered_next_access_cursor: 0,
            layered_syscall_future_accesses: Vec::new(),
            layered_compact_syscall_masks: Vec::new(),
            layered_compact_l6_syscalls: Vec::new(),
            layered_compact_l6_ops: Vec::new(),
            layered_compact_l6_latest: BTreeMap::new(),
            layered_compact_l6_pending_syscall: None,
            layered_compact_l6_pending_ecall: None,
            layered_compact_l6_pending_arg0: None,
        }
    }

    fn with_next_accesses(
        platform: &Platform,
        config: Self::Config,
        next_accesses: Option<Arc<NextCycleAccess>>,
    ) -> Self {
        let mut tracer = Self::new(platform, config);
        tracer.layered_next_accesses = next_accesses.unwrap_or_default();
        tracer
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
        if self.layered_compact_exceptional_enabled {
            self.layered_compact_l6_pending_syscall = None;
            self.layered_compact_l6_pending_ecall = None;
            self.layered_compact_l6_pending_arg0 = None;
        }
    }

    fn track_mmu_maxtouch_before(&mut self) {}
    fn track_mmu_maxtouch_after(&mut self) {}
    fn load_register(&mut self, idx: RegIdx, value: Word) {
        if self.layered_compact_exceptional_enabled && idx == Platform::reg_ecall() {
            let previous_cycle =
                self.track_access(Platform::register_vma(idx).into(), Self::SUBCYCLE_RS1);
            assert!(
                self.layered_compact_l6_pending_ecall
                    .replace((value, previous_cycle))
                    .is_none(),
                "Only one ECALL-code read per L6C step"
            );
        } else if self.layered_compact_exceptional_enabled
            && self.layered_compact_l6_pending_ecall.is_some()
            && idx == Platform::reg_arg0()
        {
            let previous_cycle =
                self.track_access(Platform::register_vma(idx).into(), Self::SUBCYCLE_RS2);
            assert!(
                self.layered_compact_l6_pending_arg0
                    .replace((value, previous_cycle))
                    .is_none(),
                "Only one ECALL arg0 read per L6C step"
            );
        }
    }
    fn store_register(&mut self, _idx: RegIdx, _value: Change<Word>) {}
    fn load_memory(&mut self, addr: WordAddr, _value: Word, _previous_cycle: Cycle) {
        self.update_layered_bounds(addr);
    }
    fn store_memory(&mut self, addr: WordAddr, _value: Change<Word>, _previous_cycle: Cycle) {
        self.update_layered_bounds(addr);
    }
    fn track_syscall(&mut self, effects: SyscallEffects) {
        let witness = effects.finalize(self);
        self.record_layered_syscall_addresses(
            witness.reg_ops.iter().map(|op| op.addr).collect(),
            witness.mem_ops.iter().map(|op| op.addr).collect(),
        );
        self.record_compact_l6_syscall(&witness);
    }
    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        if !self.layered_compact_exceptional_enabled {
            return 0;
        }
        if let Some(index) = (0..VMState::<PureAotTracer>::REG_COUNT)
            .find(|&index| WordAddr::from(Platform::register_vma(index as RegIdx)) == addr)
        {
            let previous = self.layered_register_latest[index];
            self.layered_register_latest[index] = self.layered_cycle + subcycle;
            previous
        } else {
            self.layered_compact_l6_latest
                .insert(addr, self.layered_cycle + subcycle)
                .unwrap_or(0)
        }
    }
    fn final_register_accesses(&self) -> &LatestAccesses {
        panic!("pure AOT execution has no access history")
    }
    fn into_next_accesses(self) -> NextCycleAccess {
        NextCycleAccess::default()
    }
    fn cycle(&self) -> Cycle {
        if self.layered_registers_enabled {
            self.layered_cycle
        } else {
            (self.executed_fallbacks as Cycle + 1) * Self::SUBCYCLES_PER_INSN
        }
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
        self.layered_memory_enabled
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
        let trace_style = match std::env::var_os("CENO_FULLTRACER_EXPERIMENT_LAYER") {
            None => AssemblyTraceStyle::GpuReplayDirect,
            Some(value) if value == "L0" => AssemblyTraceStyle::PreflightPureL0,
            Some(value) if value == "L1" => AssemblyTraceStyle::PreflightSkeletonL1,
            Some(value) if value == "L1C" => AssemblyTraceStyle::PreflightCompactSkeletonL1C,
            Some(value) if value == "L2C" => AssemblyTraceStyle::PreflightCompactValuesL2C,
            Some(value) if value == "L3C" => AssemblyTraceStyle::PreflightCompactRegistersL3C,
            Some(value) if value == "L4C" => AssemblyTraceStyle::PreflightCompactMemoryL4C,
            Some(value) if value == "L5C" => AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
            Some(value) if value == "L6C" => AssemblyTraceStyle::PreflightCompactExceptionalL6C,
            Some(value) if value == "L7" => AssemblyTraceStyle::PreflightCompactClosureL7,
            Some(value) if value == "L2" => AssemblyTraceStyle::PreflightValuesL2,
            Some(value) if value == "L3" => AssemblyTraceStyle::PreflightRegistersL3,
            Some(value) if value == "L4" => AssemblyTraceStyle::PreflightMemoryL4,
            Some(value) if value == "L5" => AssemblyTraceStyle::PreflightFutureAccessL5,
            Some(value) => bail!(
                "CENO_FULLTRACER_EXPERIMENT_LAYER must be exactly L0, L1, L1C, L2, L2C, L3, L3C, L4, L4C, L5, L5C, L6C, or L7 when set, got {:?}",
                value
            ),
        };
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
        if self.trace_style.has_layered_memory() {
            if TypeId::of::<T>() != TypeId::of::<PureAotTracer>() {
                bail!("L4 memory replay requires PureAotTracer state");
            }
            let pure_vm = unsafe { &mut *(vm_ptr as *mut VMState<PureAotTracer>) };
            pure_vm.tracer_mut().enable_layered_memory();
        }
        if self.trace_style.has_layered_future_access() {
            let pure_vm = unsafe { &mut *(vm_ptr as *mut VMState<PureAotTracer>) };
            if self.trace_style.is_compact_exceptional() {
                pure_vm.tracer_mut().enable_compact_exceptional();
            } else if self.trace_style.is_compact_future_access() {
                pure_vm.tracer_mut().enable_compact_future_access();
            } else {
                pure_vm.tracer_mut().enable_layered_future_access();
            }
        }
        let memory_start_ordinal =
            if self.trace_style.is_pure() && !self.trace_style.has_layered_memory() {
                0
            } else {
                vm.tracer().cycle() >> 2
            };
        if memory_start_ordinal > u64::from(u32::MAX) {
            bail!("packed memory access stamp exceeds u32::MAX");
        }
        // Bound the whole native invocation once, rather than checking every
        // memory instruction. A step at the final ordinal is representable.
        let packed_step_limit =
            if self.trace_style.is_pure() && !self.trace_style.has_layered_memory() {
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
        let mut skeleton_records = if self.trace_style.is_generic_layered_record() {
            Vec::<crate::StepRecord>::with_capacity(native_max_steps)
        } else {
            Vec::new()
        };
        let _compact_cycle_start = if self.trace_style.is_compact_layered() {
            let pure_vm = unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) };
            pure_vm.tracer().cycle()
        } else {
            0
        };
        let _compact_bounds_start = if self.trace_style.is_compact_memory()
            || self.trace_style.is_compact_future_access()
        {
            let pure_vm = unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) };
            Some((
                pure_vm.tracer().layered_max_heap,
                pure_vm.tracer().layered_max_hint,
            ))
        } else {
            None
        };
        let mut compact_skeleton_records = if self.trace_style.is_compact_skeleton() {
            Vec::<CompactSkeletonRecord>::with_capacity(native_max_steps)
        } else {
            Vec::new()
        };
        let mut compact_value_bytes = if self.trace_style.is_compact_values() {
            Vec::<u8>::with_capacity(native_max_steps.saturating_mul(COMPACT_VALUES_MAX_BYTES))
        } else if self.trace_style.is_compact_registers() {
            Vec::<u8>::with_capacity(native_max_steps.saturating_mul(COMPACT_REGISTERS_MAX_BYTES))
        } else if self.trace_style.is_compact_memory() {
            Vec::<u8>::with_capacity(native_max_steps.saturating_mul(COMPACT_REGISTERS_MAX_BYTES))
        } else if self.trace_style.is_compact_future_access() {
            Vec::<u8>::with_capacity(
                native_max_steps.saturating_mul(std::mem::size_of::<CompactFutureR>()),
            )
        } else {
            Vec::new()
        };
        let mut compact_bytes_cursor = 0usize;
        let mut skeleton_reserved_len = 0usize;
        let mut skeleton_cursor = 0usize;
        let mut skeleton_cycle = crate::FullTracer::SUBCYCLES_PER_INSN;
        let mut fulltracer_records = std::ptr::null_mut();
        let mut fulltracer_len = std::ptr::null_mut();
        let mut fulltracer_pending_index = std::ptr::null_mut();
        let mut fulltracer_pending_cycle = std::ptr::null_mut();
        let mut fulltracer_latest_cells = std::ptr::null_mut();
        let mut fulltracer_latest_base = 0;
        let mut fulltracer_latest_len = std::ptr::null_mut();
        let mut fulltracer_max_heap = std::ptr::null_mut();
        let mut fulltracer_max_hint = std::ptr::null_mut();
        if self.trace_style.is_layered_record() {
            if self.trace_style.is_compact_layered()
                && TypeId::of::<T>() != TypeId::of::<PureAotTracer>()
            {
                bail!("compact layered replay requires PureAotTracer state");
            }
            trace_mode = match self.trace_style {
                AssemblyTraceStyle::PreflightCompactSkeletonL1C => {
                    AOT_TRACE_MODE_COMPACT_SKELETON_L1C
                }
                AssemblyTraceStyle::PreflightCompactValuesL2C => AOT_TRACE_MODE_COMPACT_VALUES_L2C,
                AssemblyTraceStyle::PreflightCompactRegistersL3C => {
                    AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                }
                AssemblyTraceStyle::PreflightCompactMemoryL4C => AOT_TRACE_MODE_COMPACT_MEMORY_L4C,
                AssemblyTraceStyle::PreflightCompactFutureAccessL5C => {
                    AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                }
                AssemblyTraceStyle::PreflightCompactExceptionalL6C => {
                    AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                }
                AssemblyTraceStyle::PreflightCompactClosureL7 => AOT_TRACE_MODE_COMPACT_CLOSURE_L7,
                AssemblyTraceStyle::PreflightMemoryL4 => AOT_TRACE_MODE_MEMORY_L4,
                AssemblyTraceStyle::PreflightFutureAccessL5 => AOT_TRACE_MODE_FUTURE_ACCESS_L5,
                AssemblyTraceStyle::PreflightRegistersL3 => AOT_TRACE_MODE_REGISTERS_L3,
                AssemblyTraceStyle::PreflightValuesL2 => AOT_TRACE_MODE_VALUES_L2,
                AssemblyTraceStyle::PreflightSkeletonL1 => AOT_TRACE_MODE_SKELETON_L1,
                _ => unreachable!("layered record predicate admitted a non-layered style"),
            };
            fulltracer_records = if self.trace_style.is_compact_skeleton() {
                compact_skeleton_records
                    .as_mut_ptr()
                    .cast::<crate::StepRecord>()
            } else if self.trace_style.is_compact_values()
                || self.trace_style.is_compact_registers()
                || self.trace_style.is_compact_memory()
                || self.trace_style.is_compact_future_access()
            {
                compact_value_bytes.as_mut_ptr().cast::<crate::StepRecord>()
            } else {
                skeleton_records.as_mut_ptr()
            };
            fulltracer_len = &mut skeleton_reserved_len;
            fulltracer_pending_index = &mut skeleton_cursor;
            fulltracer_pending_cycle = &mut skeleton_cycle;
            if self.trace_style.has_layered_registers() {
                if TypeId::of::<T>() != TypeId::of::<PureAotTracer>() {
                    bail!("L3 register replay requires PureAotTracer state");
                }
                let pure_vm = unsafe { &mut *(vm_ptr as *mut VMState<PureAotTracer>) };
                if self.trace_style.has_layered_memory() {
                    pure_vm.tracer_mut().enable_layered_memory();
                }
                if self.trace_style.has_layered_future_access() {
                    if self.trace_style.is_compact_exceptional() {
                        pure_vm.tracer_mut().enable_compact_exceptional();
                    } else if self.trace_style.is_compact_future_access() {
                        pure_vm.tracer_mut().enable_compact_future_access();
                    } else {
                        pure_vm.tracer_mut().enable_layered_future_access();
                    }
                }
                let state = pure_vm.tracer_mut().layered_register_state();
                fulltracer_pending_cycle = state.cycle;
                fulltracer_latest_cells = state.latest;
                if self.trace_style.has_layered_memory() {
                    fulltracer_max_heap = state.max_heap;
                    fulltracer_max_hint = state.max_hint;
                }
            }
        }
        if trace_native_steps
            && !cfg!(debug_assertions)
            && TypeId::of::<T>() == TypeId::of::<crate::FullTracer>()
            && matches!(
                self.trace_style,
                AssemblyTraceStyle::FullTracerDirect | AssemblyTraceStyle::GpuReplayDirect
            )
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
        let mut l7_native_error = 0u32;
        let mut l7_latest_len = 0usize;
        let l7_host_setup_started = Instant::now();
        let mut l7_arenas = if self.trace_style == AssemblyTraceStyle::PreflightCompactClosureL7 {
            InsnKind::iter()
                .map(|kind| {
                    (kind != InsnKind::ECALL
                        && crate::gpu_typed_kind_spec(kind).is_some()
                        && self
                            .program
                            .instructions
                            .iter()
                            .any(|insn| insn.kind == kind))
                    .then(|| {
                        crate::GpuTypedSoaArena::new_compact_with_range(kind, native_max_steps, 0)
                            .expect("L7 supported family has no compact layout")
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut l7_native_kinds = if l7_arenas.is_empty() {
            Vec::new()
        } else {
            l7_arenas
                .iter_mut()
                .map(|arena| {
                    arena
                        .as_mut()
                        .map_or_else(Default::default, |arena| arena.native_state())
                })
                .collect::<Vec<_>>()
        };
        if self.trace_style == AssemblyTraceStyle::PreflightCompactClosureL7 {
            let pure_vm = unsafe { &mut *(vm_ptr as *mut VMState<PureAotTracer>) };
            let state = pure_vm.tracer_mut().layered_register_state();
            let (events, event_count, event_cursor) =
                pure_vm.tracer_mut().compact_future_access_native_state();
            gpu_replay_kinds = l7_native_kinds.as_mut_ptr();
            gpu_replay_kind_count = l7_native_kinds.len();
            gpu_replay_ordinal = &mut skeleton_cursor;
            gpu_replay_pending_cycle = state.cycle;
            gpu_replay_latest_cells = state.latest;
            gpu_replay_latest_base = 0;
            gpu_replay_latest_len = &mut l7_latest_len;
            gpu_replay_max_heap = state.max_heap;
            gpu_replay_max_hint = state.max_hint;
            gpu_replay_events = events;
            gpu_replay_events_len = event_count;
            gpu_replay_event_cursor = event_cursor;
            gpu_replay_error = &mut l7_native_error;
        }
        let mut l7_host_reservation_routing_time =
            if self.trace_style == AssemblyTraceStyle::PreflightCompactClosureL7 {
                l7_host_setup_started.elapsed()
            } else {
                Duration::ZERO
            };
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
        let (
            layered_next_access_events,
            layered_next_access_events_len,
            layered_next_access_cursor,
        ) = if self.trace_style.is_compact_future_access() {
            let pure_vm = unsafe { &mut *(vm_ptr as *mut VMState<PureAotTracer>) };
            pure_vm.tracer_mut().compact_future_access_native_state()
        } else {
            (std::ptr::null(), 0, std::ptr::null_mut())
        };
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
            layered_rs1_previous: 0,
            layered_rs2_previous: 0,
            layered_rd_previous: 0,
            compact_bytes_cursor: &mut compact_bytes_cursor,
            layered_next_access_events,
            layered_next_access_events_len,
            layered_next_access_cursor,
            gpu_replay_packed_block: 0,
            _gpu_replay_packed_block_padding: 0,
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
            AOT_TRACE_MODE_FULLTRACER_DIRECT
                | AOT_TRACE_MODE_GPU_REPLAY_DIRECT
                | AOT_TRACE_MODE_SKELETON_L1
                | AOT_TRACE_MODE_VALUES_L2
                | AOT_TRACE_MODE_REGISTERS_L3
                | AOT_TRACE_MODE_MEMORY_L4
                | AOT_TRACE_MODE_FUTURE_ACCESS_L5
                | AOT_TRACE_MODE_COMPACT_SKELETON_L1C
                | AOT_TRACE_MODE_COMPACT_VALUES_L2C
                | AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                | AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
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
        let exec_fn = if self.trace_style.is_layered_record() {
            ceno_aot_skeleton_l1_callback as AotInsnFn
        } else if self.trace_style.is_pure() && !trace_native_steps {
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
        // This is intentionally an inclusive native-entry measurement. It
        // covers guest execution plus generated L7 admission, routing, and
        // compact packing without adding a timestamp pair to every hot row.
        let native_entry_elapsed = started.elapsed();
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
        } else if trace_mode == AOT_TRACE_MODE_COMPACT_CLOSURE_L7 {
            let routing_sync_started = Instant::now();
            if l7_native_error != 0 {
                bail!("L7 compact family emitter failed with code {l7_native_error:#010x}");
            }
            for (arena, state) in l7_arenas.iter_mut().zip(&l7_native_kinds) {
                match arena {
                    Some(arena) => arena.sync_native_state(state).map_err(anyhow::Error::msg)?,
                    None if state.capacity == 0 && state.cursor == 0 => {}
                    None => bail!("L7 compact emitter used an absent family"),
                }
            }
            l7_host_reservation_routing_time += routing_sync_started.elapsed();
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
        if matches!(
            trace_mode,
            AOT_TRACE_MODE_SKELETON_L1
                | AOT_TRACE_MODE_VALUES_L2
                | AOT_TRACE_MODE_REGISTERS_L3
                | AOT_TRACE_MODE_MEMORY_L4
                | AOT_TRACE_MODE_FUTURE_ACCESS_L5
                | AOT_TRACE_MODE_COMPACT_SKELETON_L1C
                | AOT_TRACE_MODE_COMPACT_VALUES_L2C
                | AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                | AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        ) {
            if skeleton_cursor != executed_steps as usize {
                bail!(
                    "layered record cursor {} does not match executed steps {executed_steps}",
                    skeleton_cursor
                );
            }
            if trace_mode == AOT_TRACE_MODE_COMPACT_SKELETON_L1C {
                // SAFETY: the compact native/fallback recorders initialize one
                // complete 16-byte row before advancing the shared cursor.
                unsafe { compact_skeleton_records.set_len(skeleton_cursor) };
                #[cfg(test)]
                skeleton_records.extend(
                    compact_skeleton_records
                        .iter()
                        .map(|record| record.decode(&self.program, _compact_cycle_start)),
                );
            } else if matches!(
                trace_mode,
                AOT_TRACE_MODE_COMPACT_VALUES_L2C
                    | AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                    | AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                    | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                    | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                    | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
            ) {
                if compact_bytes_cursor > compact_value_bytes.capacity() {
                    bail!(
                        "compact byte cursor {compact_bytes_cursor} exceeds capacity {}",
                        compact_value_bytes.capacity()
                    );
                }
                // SAFETY: native and fallback emitters commit complete rows and
                // advance the byte cursor only after the final forward store.
                unsafe { compact_value_bytes.set_len(compact_bytes_cursor) };
                #[cfg(test)]
                if trace_mode == AOT_TRACE_MODE_COMPACT_VALUES_L2C {
                    skeleton_records.extend(decode_compact_values(
                        &compact_value_bytes,
                        &self.program,
                        _compact_cycle_start,
                    ));
                } else {
                    skeleton_records.extend(decode_compact_registers(
                        &compact_value_bytes,
                        &self.program,
                        _compact_cycle_start,
                        matches!(
                            trace_mode,
                            AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                                | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
                        )
                        .then(|| {
                            let (max_heap, max_hint) = _compact_bounds_start.unwrap();
                            (max_heap, max_hint, &heap, &hints)
                        }),
                        matches!(
                            trace_mode,
                            AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
                        ),
                    ));
                }
            } else {
                // SAFETY: every generic native/fallback recorder initializes
                // exactly one complete StepRecord before advancing the cursor.
                unsafe { skeleton_records.set_len(skeleton_cursor) };
            }
            if trace_mode == AOT_TRACE_MODE_FUTURE_ACCESS_L5 {
                let pure_vm = unsafe { &mut *(vm_ptr as *mut VMState<PureAotTracer>) };
                pure_vm
                    .tracer_mut()
                    .annotate_layered_future_accesses(&mut skeleton_records);
                if pure_vm.halted() {
                    pure_vm.tracer().assert_layered_future_accesses_consumed();
                }
            }
            if matches!(
                trace_mode,
                AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                    | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                    | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
            ) {
                let pure_vm = unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) };
                if pure_vm.halted() {
                    pure_vm.tracer().assert_layered_future_accesses_consumed();
                }
            }
            #[cfg(test)]
            if matches!(
                trace_mode,
                AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
            ) {
                let pure_vm = unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) };
                for record in &mut skeleton_records {
                    let header = pure_vm
                        .tracer()
                        .layered_compact_l6_syscalls
                        .iter()
                        .copied()
                        .find(|header| header.cycle() == record.cycle());
                    let syscall_index = header.map(CompactL6SyscallHeader::syscall_index);
                    let ecall_code =
                        header.map(|header| (header.ecall_code(), header.ecall_previous_cycle()));
                    let ecall_arg0 = header
                        .filter(|header| {
                            header.syscall_index() == crate::StepRecord::NO_SYSCALL
                                && header.reg_count() == 1
                        })
                        .map(|header| {
                            let op = pure_vm.tracer().layered_compact_l6_ops[header.op_offset()]
                                .decode();
                            (op.value.before, op.previous_cycle)
                        });
                    record.complete_l6(syscall_index, ecall_code, ecall_arg0);
                }
            }
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
        let l7_family_rows = l7_arenas
            .iter()
            .map(|arena| arena.as_ref().map_or(0, crate::GpuTypedSoaArena::len))
            .collect::<Vec<_>>();
        let l7_family_bytes = l7_arenas
            .iter()
            .filter_map(Option::as_ref)
            .map(|arena| arena.len() * arena.layout().compact_bytes())
            .sum::<usize>();
        let l7_family_stores = l7_arenas
            .iter()
            .filter_map(Option::as_ref)
            .map(|arena| {
                let stores_per_row = match arena.layout().compact_bytes() {
                    16 | 24 => arena.layout().compact_bytes() / 8,
                    20 | 31 => arena.layout().compact_bytes() / 8 + 1,
                    _ => unreachable!("unknown L7 compact stride"),
                };
                arena.len() * stores_per_row
            })
            .sum::<usize>();
        let compact_bytes_written = compact_bytes_cursor
            + compact_skeleton_records.len() * std::mem::size_of::<CompactSkeletonRecord>()
            + l7_family_bytes;
        if trace_mode == AOT_TRACE_MODE_COMPACT_VALUES_L2C {
            tracing::info!(
                "i061-r-l2c physical shard bytes_written={} records={} fallback_steps={}",
                compact_bytes_written,
                executed_steps,
                context.fallback_steps,
            );
        }
        if trace_mode == AOT_TRACE_MODE_COMPACT_REGISTERS_L3C {
            tracing::info!(
                "i061-r-l3c physical shard bytes_written={} records={} fallback_steps={}",
                compact_bytes_written,
                executed_steps,
                context.fallback_steps,
            );
        }
        if trace_mode == AOT_TRACE_MODE_COMPACT_MEMORY_L4C {
            tracing::info!(
                "i061-r-l4c physical shard bytes_written={} records={} fallback_steps={}",
                compact_bytes_written,
                executed_steps,
                context.fallback_steps,
            );
        }
        if trace_mode == AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C {
            tracing::info!(
                "i061-r-l5c physical shard bytes_written={} records={} fallback_steps={} syscall_mask_bytes={}",
                compact_bytes_written,
                executed_steps,
                context.fallback_steps,
                unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) }
                    .tracer()
                    .layered_compact_syscall_masks
                    .len()
                    * std::mem::size_of::<CompactFutureSyscallMask>(),
            );
        }
        if matches!(
            trace_mode,
            AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        ) {
            let pure_vm = unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) };
            tracing::info!(
                "i061-r-l6c physical shard bytes_written={} records={} fallback_steps={} syscall_header_bytes={} syscall_op_bytes={} syscall_mask_bytes={}",
                compact_bytes_written,
                executed_steps,
                context.fallback_steps,
                pure_vm.tracer().layered_compact_l6_syscalls.len()
                    * std::mem::size_of::<CompactL6SyscallHeader>(),
                pure_vm.tracer().layered_compact_l6_ops.len()
                    * std::mem::size_of::<CompactL6WriteOp>(),
                pure_vm.tracer().layered_compact_syscall_masks.len()
                    * std::mem::size_of::<CompactFutureSyscallMask>(),
            );
        }
        if trace_mode == AOT_TRACE_MODE_COMPACT_CLOSURE_L7 {
            let pure_vm = unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) };
            let header_bytes = pure_vm.tracer().layered_compact_l6_syscalls.len()
                * std::mem::size_of::<CompactL6SyscallHeader>();
            let op_bytes = pure_vm.tracer().layered_compact_l6_ops.len()
                * std::mem::size_of::<CompactL6WriteOp>();
            let mask_bytes = pure_vm.tracer().layered_compact_syscall_masks.len()
                * std::mem::size_of::<CompactFutureSyscallMask>();
            tracing::info!(
                "i061-r-l7 physical shard compact_bytes_written={} family_bytes={} family_stores={} ecall_row_bytes={} syscall_header_bytes={} syscall_op_bytes={} syscall_mask_bytes={} total_physical_bytes={} generic_logical_bytes={} host_reservation_routing_ns={} native_pack_route_inclusive_ns={} family_rows={:?}",
                compact_bytes_written,
                l7_family_bytes,
                l7_family_stores,
                compact_bytes_cursor,
                header_bytes,
                op_bytes,
                mask_bytes,
                compact_bytes_written + header_bytes + op_bytes + mask_bytes,
                executed_steps as usize * std::mem::size_of::<crate::StepRecord>(),
                l7_host_reservation_routing_time.as_nanos(),
                native_entry_elapsed
                    .saturating_sub(Duration::from_nanos(context.fallback_time_ns))
                    .as_nanos(),
                l7_family_rows,
            );
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
            #[cfg(test)]
            compact_bytes_written,
            #[cfg(test)]
            l1_skeleton_records: skeleton_records,
            #[cfg(test)]
            l6_syscall_witnesses: if matches!(
                trace_mode,
                AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
            ) {
                unsafe { &*(vm_ptr as *const VMState<PureAotTracer>) }
                    .tracer()
                    .decode_compact_l6_syscalls()
            } else {
                Vec::new()
            },
            #[cfg(test)]
            l7_family_payloads: l7_arenas
                .iter()
                .filter_map(|arena| arena.as_ref())
                .map(|arena| {
                    (
                        arena.kind(),
                        arena.range_start(),
                        arena.pc_base(),
                        arena.payload_bytes().to_vec(),
                    )
                })
                .collect(),
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
    #[cfg(test)]
    compact_bytes_written: usize,
    #[cfg(test)]
    l1_skeleton_records: Vec<crate::StepRecord>,
    #[cfg(test)]
    l6_syscall_witnesses: Vec<SyscallWitness>,
    #[cfg(test)]
    #[cfg_attr(debug_assertions, allow(dead_code))]
    l7_family_payloads: Vec<(InsnKind, u32, u32, Vec<u8>)>,
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
