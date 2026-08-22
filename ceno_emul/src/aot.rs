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
    /// Internal I049 feasibility image: production preflight block planning
    /// plus explicit trace values for same-execution compact capture.
    PreflightProductionCapture,
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
                | Self::PreflightProductionCapture
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
                | Self::PreflightProductionCapture
        )
    }

    fn uses_preflight_block_plan(self) -> bool {
        matches!(
            self,
            Self::PreflightAdmittedRegisterBlock
                | Self::PreflightAdmittedMemoryBlock
                | Self::PreflightProduction
                | Self::PreflightProductionCapture
        )
    }

    fn carries_next_pc_in_register(self) -> bool {
        self.is_pure()
    }

    fn preflight_feature_enabled(self, feature: PreflightFeature) -> bool {
        !(matches!(
            self,
            Self::PreflightProduction
                | Self::PreflightProductionCapture
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
            // Keep the experimental capture image independently cache-busted:
            // release block-atomic memory rows now publish trace_mem_addr even
            // when their next-access event was emitted early.
            Self::PreflightProductionCapture => "preflight-production-capture-sync2",
        }
    }

    fn is_preflight_production(self) -> bool {
        matches!(
            self,
            Self::PreflightProduction | Self::PreflightProductionCapture
        )
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
const AOT_CTX_PREFLIGHT_BLOCK_KIND_HISTOGRAMS_OFFSET: usize = 768;
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
const AOT_CTX_GPU_REPLAY_ORDINARY_CALLBACKS_OFFSET: usize = 928;
const AOT_CTX_COMBINED_SAVED_OFFSET: usize = 936;
const AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET: usize = 1008;
const AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET: usize = 1016;
const AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET: usize = 1024;
const AOT_CTX_COMPACT_BYTES_CURSOR_OFFSET: usize = 1032;
const AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_OFFSET: usize = 1040;
const AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_LEN_OFFSET: usize = 1048;
const AOT_CTX_LAYERED_NEXT_ACCESS_CURSOR_OFFSET: usize = 1056;
const AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET: usize = 1064;

const AOT_FALLBACK_DYNAMIC_PC: u32 = 1;
const AOT_FALLBACK_MEMORY_GUARD: u32 = 2;
const AOT_FALLBACK_ECALL: u32 = 3;
const AOT_FALLBACK_EXCEPTIONAL: u32 = 4;
const AOT_ABI_VERSION: u32 = 78;
const AOT_CACHE_MAGIC: &str = "ceno-aot-cache-v5";
const AOT_INITIAL_EVENT_SEED: usize = 20_000_000;
const AOT_MAX_COMPILE_JOBS: usize = 32;
const AOT_BLOCK_COMPILE_OVERHEAD: usize = 16;

const AOT_TRACE_MODE_NONE: u32 = 0;
const AOT_TRACE_MODE_CALLBACK: u32 = 1;
const AOT_TRACE_MODE_PREFLIGHT_DIRECT: u32 = 2;
const AOT_TRACE_MODE_FULLTRACER_DIRECT: u32 = 3;
const AOT_TRACE_MODE_GPU_REPLAY_DIRECT: u32 = 4;
const AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT: u32 = 5;
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
    combined_saved: [u64; 9],
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

    fn cycle(self) -> Cycle {
        Cycle::from_le_bytes(self.0[0..8].try_into().unwrap())
    }

    fn syscall_index(self) -> u32 {
        u32::from_le_bytes(self.0[8..12].try_into().unwrap())
    }

    fn op_offset(self) -> usize {
        u32::from_le_bytes(self.0[12..16].try_into().unwrap()) as usize
    }

    fn reg_count(self) -> usize {
        self.0[16] as usize
    }

    fn mem_count(self) -> usize {
        self.0[17] as usize
    }

    fn ecall_code(self) -> Word {
        Word::from_le_bytes(self.0[18..22].try_into().unwrap())
    }

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
    fn compile_preflight_capture_with_extra_roots(
        program: Arc<Program>,
        extra_roots: Vec<u32>,
    ) -> Result<Self> {
        Self::compile_with_extra_roots_and_trace_style(
            program,
            extra_roots,
            AssemblyTraceStyle::PreflightProductionCapture,
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

    /// Internal I049 feasibility loader. This keeps the production preflight
    /// cache key and image unchanged while enabling same-execution capture.
    pub fn load_or_train_preflight_capture_with_config(
        platform: &Platform,
        program: Arc<Program>,
        init_memory: impl IntoIterator<Item = (WordAddr, Word)>,
        config: PreflightTracerConfig,
    ) -> Result<Self> {
        Self::load_or_train_preflight_style_in(
            platform,
            program,
            init_memory,
            config,
            &default_aot_cache_dir(),
            AssemblyTraceStyle::PreflightProductionCapture,
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
        if trace_native_steps && TypeId::of::<T>() == TypeId::of::<PreflightTracer>() {
            let preflight_vm = unsafe { &mut *(vm_ptr as *mut VMState<PreflightTracer>) };
            if let Some(state) = preflight_vm.tracer_mut().prepare_combined_capture_native() {
                trace_mode = AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT;
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
        let preflight_step_cells_table = if matches!(
            trace_mode,
            AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        ) {
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
            combined_saved: [0; 9],
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
                if matches!(
                    trace_mode,
                    AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
                ) {
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
        } else if matches!(
            trace_mode,
            AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        ) {
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
        if matches!(
            trace_mode,
            AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        ) {
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
        if matches!(
            trace_mode,
            AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        ) {
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
        if matches!(
            trace_mode,
            AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        ) {
            let preflight_vm = unsafe { &mut *(vm_ptr as *mut VMState<PreflightTracer>) };
            unsafe {
                preflight_vm
                    .tracer_mut()
                    .sync_native_next_access_tape(context.preflight_event_cursor)
            };
            preflight_vm.tracer_mut().finish_deferred_mmio_bounds();
            preflight_vm
                .tracer_mut()
                .sync_combined_capture()
                .map_err(|message| anyhow!(message))?;
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
        ) = if matches!(
            trace_mode,
            AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        ) {
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
    let static_roots = program.static_aot_roots.as_deref().unwrap_or_default();
    bytes.extend_from_slice(&(static_roots.len() as u64).to_le_bytes());
    for &pc in static_roots {
        bytes.extend_from_slice(&pc.to_le_bytes());
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

fn planner_cache_key(
    program: &Program,
    trace_style: AssemblyTraceStyle,
    model: &ShardCostModel,
) -> String {
    format!(
        "{}-cost{}",
        aot_cache_key(program, trace_style),
        hex_digest(&model.fingerprint())
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

fn cache_temporary_paths(cache_dir: &Path, process_id: u32, sequence: u64) -> [PathBuf; 3] {
    let basename = format!(".ceno-aot-{process_id:08x}-{sequence:016x}");
    [
        cache_dir.join(format!("{basename}.S")),
        cache_dir.join(format!("{basename}.so")),
        cache_dir.join(format!("{basename}.meta")),
    ]
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

type DecodedCacheMetadata = ([u8; 32], Vec<u32>, usize, [u8; 32], Vec<u32>);

fn decode_cache_metadata(metadata: &str, expected_key: &str) -> Result<DecodedCacheMetadata> {
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
    planner_fingerprint: Option<[u8; 32]>,
) -> Result<Option<AotProgram>> {
    let (so_path, metadata_path) = cache_paths(cache_dir, key);
    let role = trace_style.cache_name();
    aot_diagnostic_marker(
        "CACHE_PRESENCE",
        "BEGIN",
        role,
        key,
        &so_path,
        0,
        "artifacts=2",
    );
    let so_exists = so_path.exists();
    let metadata_exists = metadata_path.exists();
    aot_diagnostic_marker(
        "CACHE_PRESENCE",
        "END",
        role,
        key,
        &so_path,
        0,
        &format!("so_exists={so_exists},metadata_exists={metadata_exists}"),
    );
    if !so_exists || !metadata_exists {
        return Ok(None);
    }
    let metadata_bytes = fs::metadata(&metadata_path)?.len();
    aot_diagnostic_marker(
        "METADATA_READ",
        "BEGIN",
        role,
        key,
        &metadata_path,
        metadata_bytes,
        "files=1",
    );
    let metadata = fs::read_to_string(&metadata_path)
        .with_context(|| format!("read AOT metadata {}", metadata_path.display()))?;
    aot_diagnostic_marker(
        "METADATA_READ",
        "END",
        role,
        key,
        &metadata_path,
        metadata.len() as u64,
        "files=1",
    );
    aot_diagnostic_marker(
        "METADATA_DECODE",
        "BEGIN",
        role,
        key,
        &metadata_path,
        metadata.len() as u64,
        "records=1",
    );
    let (expected_digest, roots, event_capacity, profile_digest, emission_order) =
        decode_cache_metadata(&metadata, key)?;
    aot_diagnostic_marker(
        "METADATA_DECODE",
        "END",
        role,
        key,
        &metadata_path,
        metadata.len() as u64,
        &format!(
            "roots={},emissions={},event_capacity={},artifact_digest={},profile_digest={}",
            roots.len(),
            emission_order.len(),
            event_capacity,
            hex_digest(&expected_digest),
            hex_digest(&profile_digest)
        ),
    );
    let so_bytes = fs::metadata(&so_path)?.len();
    aot_diagnostic_marker(
        "ARTIFACT_READ",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        "files=1",
    );
    let artifact =
        fs::read(&so_path).with_context(|| format!("read AOT artifact {}", so_path.display()))?;
    aot_diagnostic_marker(
        "ARTIFACT_READ",
        "END",
        role,
        key,
        &so_path,
        artifact.len() as u64,
        "files=1",
    );
    aot_diagnostic_marker(
        "ARTIFACT_KECCAK",
        "BEGIN",
        role,
        key,
        &so_path,
        artifact.len() as u64,
        "digests=1",
    );
    let actual_digest = keccak256(&artifact);
    aot_diagnostic_marker(
        "ARTIFACT_KECCAK",
        "END",
        role,
        key,
        &so_path,
        artifact.len() as u64,
        &format!("digests=1,artifact_digest={}", hex_digest(&actual_digest)),
    );
    drop(artifact);
    if actual_digest != expected_digest {
        bail!("AOT artifact checksum mismatch");
    }
    tracing::info!(
        "AOT cached artifact size={} profile_digest={}",
        fs::metadata(&so_path)?.len(),
        hex_digest(&profile_digest),
    );
    let root_count = roots.len();
    aot_diagnostic_marker(
        "BLOCK_RECONSTRUCTION",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("roots={root_count}"),
    );
    let blocks = partition_basic_blocks_with_roots(&program, roots)?;
    aot_diagnostic_marker(
        "BLOCK_RECONSTRUCTION",
        "END",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("roots={root_count},blocks={}", blocks.len()),
    );
    aot_diagnostic_marker(
        "EMISSION_VALIDATION",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("blocks={},emissions={}", blocks.len(), emission_order.len()),
    );
    validate_emission_order(&blocks, &emission_order)?;
    aot_diagnostic_marker(
        "EMISSION_VALIDATION",
        "END",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("blocks={},emissions={}", blocks.len(), emission_order.len()),
    );
    let layout_profile = AotLayoutProfile {
        block_counts: Vec::new(),
        edge_counts: BTreeMap::new(),
        emission_order,
        digest: profile_digest,
    };
    let started = Instant::now();
    let (library, entry) = load_native(&so_path, trace_style.cache_name(), key)?;
    aot_diagnostic_marker(
        "AOT_PROGRAM_COMPLETION",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("blocks={},event_capacity={event_capacity}", blocks.len()),
    );
    let aot = AotProgram {
        cache_identity: key.to_owned(),
        artifact_path: Some(so_path.clone()),
        program,
        blocks,
        layout_profile,
        _library: library,
        entry,
        compile_load_time: started.elapsed(),
        trace_style,
        next_access_capacity: event_capacity,
        planner_fingerprint,
    };
    aot_diagnostic_marker(
        "AOT_PROGRAM_COMPLETION",
        "END",
        role,
        key,
        &so_path,
        so_bytes,
        &format!(
            "blocks={},event_capacity={event_capacity}",
            aot.blocks.len()
        ),
    );
    Ok(Some(aot))
}

#[allow(clippy::too_many_arguments)]
fn compile_cached_aot(
    program: Arc<Program>,
    roots: Vec<u32>,
    layout_profile: Option<AotLayoutProfile>,
    trace_style: AssemblyTraceStyle,
    cache_dir: &Path,
    key: &str,
    event_count: usize,
    planner_model: Option<&ShardCostModel>,
) -> Result<AotProgram> {
    let started = Instant::now();
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("create AOT cache directory {}", cache_dir.display()))?;
    let blocks = partition_basic_blocks_with_roots(&program, roots.clone())?;
    let planner_metadata = planner_model
        .map(|model| build_aot_block_cost_descriptors(&program, &blocks, model))
        .transpose()?;
    let layout_profile = layout_profile.unwrap_or_else(|| pc_order_layout(&blocks));
    validate_emission_order(&blocks, &layout_profile.emission_order)?;
    let sequence = AOT_CACHE_TEMP_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| anyhow!("AOT cache temporary sequence exhausted"))?;
    let [asm_tmp, so_tmp, meta_tmp] =
        cache_temporary_paths(cache_dir, std::process::id(), sequence);
    let (so_path, metadata_path) = cache_paths(cache_dir, key);
    let result = (|| -> Result<()> {
        compile_native_to(
            &program,
            &blocks,
            &layout_profile.emission_order,
            trace_style,
            planner_metadata.as_ref(),
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
    let (library, entry) = load_native(&so_path, trace_style.cache_name(), key)?;
    Ok(AotProgram {
        cache_identity: key.to_owned(),
        artifact_path: Some(so_path),
        program,
        blocks,
        layout_profile,
        _library: library,
        entry,
        compile_load_time: started.elapsed(),
        trace_style,
        next_access_capacity: next_access_capacity(event_count),
        planner_fingerprint: planner_model.map(ShardCostModel::fingerprint),
    })
}

#[cfg(test)]
fn write_assembly_with_planner(
    path: &Path,
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
    planner_metadata: Option<&AotPlannerMetadata>,
) -> Result<()> {
    validate_emission_order(blocks, emission_order)?;
    write_assembly_part(
        path,
        program,
        blocks,
        emission_order,
        trace_style,
        planner_metadata,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_assembly_part(
    path: &Path,
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
    planner_metadata: Option<&AotPlannerMetadata>,
    emit_control: bool,
) -> Result<()> {
    let mut labels = BTreeMap::new();
    for block in blocks {
        labels.insert(
            block.start_pc,
            format!("ceno_aot_bb_{:08x}", block.start_pc),
        );
    }

    let mut file = fs::File::create(path).context("create AOT assembly")?;
    writeln!(file, ".text")?;
    if emit_control {
        writeln!(file, ".globl ceno_aot_entry")?;
        writeln!(file, ".type ceno_aot_entry, @function")?;
        writeln!(file, "ceno_aot_entry:")?;
        writeln!(file, "    pushq %rbx")?;
        writeln!(file, "    pushq %r12")?;
        writeln!(file, "    pushq %r13")?;
        writeln!(file, "    pushq %r14")?;
        writeln!(file, "    pushq %r15")?;
        writeln!(file, "    pushq %rbp")?;
        writeln!(file, "    subq $88, %rsp")?;
        writeln!(file, "    movq %rdi, %r12")?;
        writeln!(file, "    movq %rsi, 72(%rsp)")?;
        writeln!(file, "    movq {AOT_CTX_REGISTERS_OFFSET}(%r12), %r13")?;
        if !trace_style.is_pure() {
            writeln!(file, "    movq %rdx, %r14")?;
        }
        writeln!(file, "    movq %rcx, %rbp")?;
        // Keep the preflight tape cursor in a callee-saved register. The executed
        // step output pointer is cold and fits in the otherwise-unused final stack
        // slot.
        writeln!(file, "    movq %r8, 48(%rsp)")?;
        if trace_style.is_pure() {
            emit_reload_pure_memory_state(&mut file)?;
        } else {
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET}(%r12), %rbx"
            )?;
        }
        writeln!(file, "    movl %r9d, %r15d")?;
        writeln!(file, "    movq $0, 0(%rsp)")?;
        writeln!(file, "    movl %r15d, 8(%rsp)")?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    movq %rax, 56(%rsp)")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_dispatch")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    cmpq %rbp, %rax")?;
        writeln!(file, "    jae ceno_aot_done")?;
        emit_dispatch_tree(&mut file, blocks, &labels, 0, blocks.len())?;
    }
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
        writeln!(file, ".globl {label}")?;
        writeln!(file, ".hidden {label}")?;
        writeln!(file, ".type {label}, @function")?;
        writeln!(file, "{label}:")?;
        // Reaching a native block leader ends any Rust fallback recovery run.
        writeln!(
            file,
            "    movl $0, {AOT_CTX_FALLBACK_RECOVERY_REASON_OFFSET}(%r12)"
        )?;
        if matches!(
            trace_style,
            AssemblyTraceStyle::PreflightPureL0
                | AssemblyTraceStyle::PreflightSkeletonL1
                | AssemblyTraceStyle::PreflightCompactSkeletonL1C
                | AssemblyTraceStyle::PreflightCompactValuesL2C
                | AssemblyTraceStyle::PreflightCompactRegistersL3C
                | AssemblyTraceStyle::PreflightCompactMemoryL4C
                | AssemblyTraceStyle::PreflightCompactFutureAccessL5C
                | AssemblyTraceStyle::PreflightCompactExceptionalL6C
                | AssemblyTraceStyle::PreflightCompactClosureL7
                | AssemblyTraceStyle::PreflightValuesL2
                | AssemblyTraceStyle::PreflightRegistersL3
                | AssemblyTraceStyle::PreflightMemoryL4
                | AssemblyTraceStyle::PreflightFutureAccessL5
        ) {
            // Static successor jumps bypass the dispatcher's limit check.
            // Enforce exact-boundary closure at every possible block leader,
            // including scalar/exceptional blocks that cannot be admitted.
            writeln!(file, "    movq 0(%rsp), %rax")?;
            writeln!(file, "    cmpq %rbp, %rax")?;
            writeln!(file, "    jae ceno_aot_done")?;
        }
        let block_plan = if trace_style.uses_preflight_block_plan() {
            preflight_block_plan_kind(program, block)?
        } else {
            None
        };
        let memory_access_count = preflight_block_memory_access_count(program, block)?;
        let hoist_memory_regions =
            matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess))
                && trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds)
                && memory_access_count <= 32;
        let pure_block_plan = if trace_style.uses_pure_block_admission() {
            preflight_block_plan_kind(program, block)?
        } else {
            None
        };
        let pure_counted_block = trace_style.uses_pure_block_admission()
            && block_supports_adaptive_cost_plan(program, block)?;
        let gpu_replay_packed_block = trace_style == AssemblyTraceStyle::GpuReplayDirect
            && block_supports_adaptive_cost_plan(program, block)?;
        let pure_admitted_block = pure_counted_block
            || (matches!(
                trace_style,
                AssemblyTraceStyle::PreflightPureL0
                    | AssemblyTraceStyle::PreflightSkeletonL1
                    | AssemblyTraceStyle::PreflightCompactSkeletonL1C
                    | AssemblyTraceStyle::PreflightCompactValuesL2C
                    | AssemblyTraceStyle::PreflightCompactRegistersL3C
                    | AssemblyTraceStyle::PreflightCompactMemoryL4C
                    | AssemblyTraceStyle::PreflightCompactFutureAccessL5C
                    | AssemblyTraceStyle::PreflightCompactExceptionalL6C
                    | AssemblyTraceStyle::PreflightCompactClosureL7
                    | AssemblyTraceStyle::PreflightValuesL2
                    | AssemblyTraceStyle::PreflightRegistersL3
                    | AssemblyTraceStyle::PreflightMemoryL4
                    | AssemblyTraceStyle::PreflightFutureAccessL5
            ) && pure_block_plan.is_some());
        if pure_admitted_block {
            emit_pure_block_budget_guard(&mut file, block)?;
        }
        if let Some(kind) = pure_block_plan {
            if kind == PreflightBlockPlanKind::MemoryExactAccess {
                emit_pure_block_memory_fast_path_guard(&mut file, program, block)?;
            }
        }
        if pure_admitted_block {
            if trace_style == AssemblyTraceStyle::PreflightCompactClosureL7 {
                emit_l7_block_family_admission(&mut file, program, block)?;
            }
            if trace_style.is_layered_record() {
                writeln!(
                    file,
                    "    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %rax"
                )?;
                writeln!(file, "    movq (%rax), %rax")?;
                writeln!(file, "    addq ${}, %rax", block_instruction_count(block))?;
                writeln!(file, "    movq {AOT_CTX_FULLTRACER_LEN_OFFSET}(%r12), %rcx")?;
                writeln!(file, "    movq %rax, (%rcx)")?;
            }
            writeln!(
                file,
                "    addq ${}, 0(%rsp)",
                block_instruction_count(block)
            )?;
        }
        if gpu_replay_packed_block {
            emit_gpu_replay_packed_block_admission(&mut file, program, block)?;
        }
        let adaptive_exact_access_plan = block_plan.is_none()
            && trace_style.uses_preflight_block_plan()
            && block_supports_adaptive_cost_plan(program, block)?;
        if block_plan.is_none()
            && !adaptive_exact_access_plan
            && trace_style.uses_preflight_block_plan()
        {
            let reason = if instruction_at(program, block.start_pc)?.kind == InsnKind::ECALL {
                AOT_FALLBACK_ECALL
            } else {
                AOT_FALLBACK_EXCEPTIONAL
            };
            emit_call_current_pc(&mut file, reason, trace_style)?;
            writeln!(file, "    jmp ceno_aot_dispatch")?;
            continue;
        }
        if adaptive_exact_access_plan {
            emit_preflight_direct_block_budget_guard(&mut file, block)?;
            if trace_style.preflight_feature_enabled(PreflightFeature::EventCapacity) {
                emit_preflight_direct_block_event_capacity_guard(
                    &mut file,
                    program,
                    block_idx,
                    block,
                    PreflightAccessMode::BlockAtomic,
                )?;
            }
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_accounting", block.start_pc),
            )?;
            emit_preflight_adaptive_block_plan_entry(
                &mut file,
                block_idx,
                block,
                planner_metadata,
            )?;
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_register_first_checks", block.start_pc),
            )?;
            if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                emit_preflight_direct_block_access_entry(
                    &mut file,
                    program,
                    block_idx,
                    block,
                    trace_style.preflight_feature_enabled(PreflightFeature::RegisterEvents),
                )?;
            }
        }
        if block_plan.is_some() {
            emit_preflight_direct_block_budget_guard(&mut file, block)?;
            if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess)) {
                emit_preflight_direct_block_memory_fast_path_guard(
                    &mut file,
                    program,
                    block,
                    hoist_memory_regions,
                )?;
            }
            if trace_style.preflight_feature_enabled(PreflightFeature::EventCapacity) {
                emit_preflight_direct_block_event_capacity_guard(
                    &mut file,
                    program,
                    block_idx,
                    block,
                    PreflightAccessMode::BlockAtomic,
                )?;
            }
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_accounting", block.start_pc),
            )?;
            emit_preflight_adaptive_block_plan_entry(
                &mut file,
                block_idx,
                block,
                planner_metadata,
            )?;
            if block_plan.is_some() {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_register_first_checks", block.start_pc),
                )?;
                if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                    emit_preflight_direct_block_access_entry(
                        &mut file,
                        program,
                        block_idx,
                        block,
                        trace_style.preflight_feature_enabled(PreflightFeature::RegisterEvents),
                    )?;
                }
            }
            // The entry guards make this block atomic with respect to Rust
            // fallback. Reserve its executed-step count once, as Pure AOT
            // does, and publish tracked cycle/step state at block exit.
            writeln!(
                file,
                "    addq ${}, 0(%rsp)",
                block_instruction_count(block)
            )?;
        }
        let registers_resident =
            !cfg!(debug_assertions) && (block_plan.is_some() || pure_admitted_block);
        let memory_cells_resident =
            registers_resident && memory_access_count != 0 && !trace_style.is_pure();
        if registers_resident {
            writeln!(file, "    movq %r13, %r10")?;
        }
        if memory_cells_resident {
            writeln!(file, "    movq {AOT_CTX_MEMORY_CELLS_OFFSET}(%r12), %r11")?;
            writeln!(
                file,
                "    movl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %eax"
            )?;
            writeln!(file, "    negq %rax")?;
            writeln!(file, "    leaq (%r11,%rax,8), %r11")?;
            writeln!(
                file,
                "    movq {AOT_CTX_MEMORY_START_ORDINAL_OFFSET}(%r12), %r15"
            )?;
            writeln!(file, "    addq 0(%rsp), %r15")?;
            writeln!(file, "    subq ${}, %r15", block_instruction_count(block))?;
        }
        let mut pc = block.start_pc;
        let mut memory_access_index = 0usize;
        let mut last_profile_region = None;
        while pc < block.end_pc {
            let insn = instruction_at(program, pc)?;
            if trace_style == AssemblyTraceStyle::GpuReplayDirect {
                let resume_label = format!("ceno_aot_gpu_resume_{pc:08x}");
                writeln!(file, ".globl {resume_label}")?;
                writeln!(file, ".hidden {resume_label}")?;
                writeln!(file, ".type {resume_label}, @function")?;
                writeln!(file, "{resume_label}:")?;
            }
            let current_memory_access_index =
                if native_opcode_family(insn.kind) == Some(NativeOpcodeFamily::Memory) {
                    let index = memory_access_index;
                    memory_access_index += 1;
                    Some(index)
                } else {
                    None
                };
            let step_trace_style =
                if trace_style.is_preflight_production() || trace_style.is_layered_record() {
                    trace_style
                } else if pure_block_plan.is_some() {
                    AssemblyTraceStyle::PureBlock
                } else if pure_counted_block {
                    AssemblyTraceStyle::PureCountedBlock
                } else if matches!(block_plan, Some(PreflightBlockPlanKind::RegisterOnly)) {
                    AssemblyTraceStyle::PreflightAdmittedRegisterBlock
                } else if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess))
                    || adaptive_exact_access_plan
                {
                    AssemblyTraceStyle::PreflightAdmittedMemoryBlock
                } else if trace_style.uses_preflight_block_plan() {
                    AssemblyTraceStyle::PreflightScalar
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
            let reserved_block_step = (pure_admitted_block
                || block_plan.is_some()
                || gpu_replay_packed_block)
                .then_some(ReservedBlockStep {
                    block_start_pc: block.start_pc,
                    block_end_pc: block.end_pc,
                    remaining_after: ((block.end_pc - pc - PC_STEP_SIZE as u32)
                        / PC_STEP_SIZE as u32) as u64,
                    cycle_offset: (pc - block.start_pc) as u64,
                    memory_guard_hoisted: matches!(
                        block_plan,
                        Some(PreflightBlockPlanKind::MemoryExactAccess)
                    ),
                    memory_region_index: hoist_memory_regions
                        .then_some(current_memory_access_index)
                        .flatten(),
                    registers_resident,
                    memory_cells_resident,
                    memory_ordinal_resident: memory_cells_resident,
                });
            emit_instruction_body(
                &mut file,
                program,
                pc,
                insn,
                step_trace_style,
                reserved_block_step,
            )?;
            pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        }
        if let Some(prev_pc) = pc.checked_sub(PC_STEP_SIZE as u32) {
            let insn = instruction_at(program, prev_pc)?;
            if block_plan.is_some() {
                emit_preflight_direct_block_trace_exit(&mut file, block)?;
                emit_preflight_direct_execution_metadata(&mut file, prev_pc, insn)?;
                if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                    emit_assembly_profile_symbol(
                        &mut file,
                        &format!("ceno_aot_bb_{:08x}_register_latest_commit", block.start_pc),
                    )?;
                    emit_preflight_direct_block_register_access_exit(&mut file, program, block)?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_plan_commit", block.start_pc),
                )?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_ENTRY,
                    )?;
                }
                emit_preflight_direct_block_plan_exit(&mut file, program, block_idx, block)?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_EXIT,
                    )?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_guards_exit", block.start_pc),
                )?;
                emit_preflight_direct_busy_loop_guard(&mut file, prev_pc)?;
            } else if adaptive_exact_access_plan {
                if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                    emit_assembly_profile_symbol(
                        &mut file,
                        &format!("ceno_aot_bb_{:08x}_register_latest_commit", block.start_pc),
                    )?;
                    emit_preflight_direct_block_register_access_exit(&mut file, program, block)?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_plan_commit", block.start_pc),
                )?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_ENTRY,
                    )?;
                }
                emit_preflight_direct_block_plan_exit(&mut file, program, block_idx, block)?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_EXIT,
                    )?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_guards_exit", block.start_pc),
                )?;
                emit_preflight_direct_busy_loop_guard(&mut file, prev_pc)?;
            }
            if trace_style.has_layered_registers() && pure_admitted_block {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_layered_register_commit", block.start_pc),
                )?;
                emit_layered_register_block_commit(&mut file, program, block)?;
            }
            if gpu_replay_packed_block {
                emit_gpu_replay_register_block_commit(&mut file, program, block)?;
            }
            emit_successor_jump(&mut file, program, &labels, next_block_pc, prev_pc, insn)?;
        }
    }
    if emit_control {
        emit_assembly_profile_symbol(&mut file, "ceno_aot_dynamic_fallback")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_dynamic")?;
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            let fallback_label = ".L_gpu_replay_dynamic_fallback";
            writeln!(file, "    movl %r15d, %eax")?;
            writeln!(file, "    subl ${:#010x}, %eax", program.base_address)?;
            writeln!(file, "    testl $3, %eax")?;
            writeln!(file, "    jne {fallback_label}")?;
            writeln!(
                file,
                "    cmpl ${}, %eax",
                program.instructions.len() * PC_STEP_SIZE
            )?;
            writeln!(file, "    jae {fallback_label}")?;
            writeln!(file, "    shrl $2, %eax")?;
            writeln!(file, "    leaq ceno_aot_gpu_resume_table(%rip), %rdx")?;
            writeln!(file, "    movq (%rdx,%rax,8), %rax")?;
            writeln!(file, "    testq %rax, %rax")?;
            writeln!(file, "    je {fallback_label}")?;
            writeln!(file, "    jmp *%rax")?;
            writeln!(file, "{fallback_label}:")?;
            emit_call_current_pc(&mut file, AOT_FALLBACK_DYNAMIC_PC, trace_style)?;
            writeln!(file, "    jmp ceno_aot_dispatch")?;
        } else {
            emit_call_current_pc(&mut file, AOT_FALLBACK_DYNAMIC_PC, trace_style)?;
            writeln!(file, "    jmp ceno_aot_dispatch")?;
        }
        emit_global_hidden_symbol(&mut file, "ceno_aot_memory_guard")?;
        emit_call_current_pc(&mut file, AOT_FALLBACK_MEMORY_GUARD, trace_style)?;
        writeln!(file, "    jmp ceno_aot_dispatch")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_exceptional")?;
        emit_call_current_pc(&mut file, AOT_FALLBACK_EXCEPTIONAL, trace_style)?;
        writeln!(file, "    jmp ceno_aot_dispatch")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_done")?;
        if !trace_style.is_pure() {
            emit_sync_preflight_direct(&mut file)?;
            emit_flush_preflight_event_cursor(&mut file)?;
        }
        writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
        writeln!(file, "    movl %r15d, (%rdx)")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    movq 48(%rsp), %rdx")?;
        writeln!(file, "    movq %rax, (%rdx)")?;
        writeln!(file, "    movl ${AOT_STATUS_HALTED}, %eax")?;
        writeln!(file, "    jmp ceno_aot_return")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_error")?;
        if !trace_style.is_pure() {
            emit_flush_preflight_event_cursor(&mut file)?;
        }
        writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
        writeln!(file, "    movl %r15d, (%rdx)")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    movq 48(%rsp), %rdx")?;
        writeln!(file, "    movq %rax, (%rdx)")?;
        writeln!(file, "    movl ${AOT_STATUS_ERROR}, %eax")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_return")?;
        writeln!(file, "    addq $88, %rsp")?;
        writeln!(file, "    popq %rbp")?;
        writeln!(file, "    popq %r15")?;
        writeln!(file, "    popq %r14")?;
        writeln!(file, "    popq %r13")?;
        writeln!(file, "    popq %r12")?;
        writeln!(file, "    popq %rbx")?;
        writeln!(file, "    ret")?;
        if matches!(
            trace_style,
            AssemblyTraceStyle::FullTracerDirect | AssemblyTraceStyle::GpuReplayDirect
        ) {
            emit_fulltracer_shared_recorder(&mut file)?;
        }
        if trace_style.is_generic_layered_record() {
            emit_skeleton_l1_shared_recorder(&mut file)?;
        }
        if trace_style.is_compact_skeleton() {
            emit_compact_skeleton_l1c_shared_recorder(&mut file)?;
        }
        if trace_style.is_compact_values() {
            emit_compact_values_l2c_shared_recorder(&mut file)?;
        }
        if trace_style.is_compact_registers()
            || trace_style.is_compact_memory()
            || trace_style.is_compact_future_access()
        {
            emit_compact_registers_l3c_shared_recorder(
                &mut file,
                trace_style.is_compact_memory() || trace_style.is_compact_future_access(),
                trace_style.is_compact_future_access(),
            )?;
        }
        if trace_style == AssemblyTraceStyle::GpuReplayDirect
            || trace_style == AssemblyTraceStyle::PreflightCompactClosureL7
            || trace_style.is_preflight_direct()
        {
            emit_gpu_replay_shared_recorder(&mut file)?;
        }
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            let compiled = blocks
                .iter()
                .flat_map(|block| (block.start_pc..block.end_pc).step_by(PC_STEP_SIZE))
                .collect::<BTreeSet<_>>();
            writeln!(file, ".section .data.rel.ro.local,\"aw\",@progbits")?;
            writeln!(file, ".p2align 3")?;
            writeln!(file, ".hidden ceno_aot_gpu_resume_table")?;
            writeln!(file, "ceno_aot_gpu_resume_table:")?;
            for index in 0..program.instructions.len() {
                let pc = program
                    .base_address
                    .wrapping_add((index * PC_STEP_SIZE) as u32);
                if compiled.contains(&pc) {
                    writeln!(file, "    .quad ceno_aot_gpu_resume_{pc:08x}")?;
                } else {
                    writeln!(file, "    .quad 0")?;
                }
            }
            writeln!(file, ".text")?;
        }
    }
    writeln!(file, ".section .note.GNU-stack,\"\",@progbits")?;
    Ok(())
}

fn emit_assembly_profile_symbol(mut file: impl Write, name: &str) -> Result<()> {
    writeln!(file, ".type {name}, @function")?;
    writeln!(file, "{name}:")?;
    Ok(())
}

fn emit_global_hidden_symbol(mut file: impl Write, name: &str) -> Result<()> {
    writeln!(file, ".globl {name}")?;
    writeln!(file, ".hidden {name}")?;
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
        writeln!(file, "    jmp ceno_aot_dynamic")?;
        return Ok(());
    }

    if end - start <= 8 {
        for block in &blocks[start..end] {
            let label = labels.get(&block.start_pc).expect("block label must exist");
            writeln!(file, "    cmpl ${:#010x}, %r15d", block.start_pc)?;
            writeln!(file, "    je {label}")?;
        }
        writeln!(file, "    jmp ceno_aot_dynamic")?;
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

fn emit_call_one(
    mut file: impl Write,
    pc: u32,
    reason: u32,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if !trace_style.is_pure() {
        emit_sync_preflight_direct(&mut file)?;
        emit_flush_preflight_event_cursor(&mut file)?;
    }
    writeln!(
        file,
        "    movl ${reason}, {AOT_CTX_FALLBACK_REASON_OFFSET}(%r12)"
    )?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl ${pc:#010x}, %esi")?;
    writeln!(file, "    call *72(%rsp)")?;
    if trace_style.is_pure() {
        emit_reload_pure_memory_state(&mut file)?;
    } else {
        emit_reload_preflight_event_cursor(&mut file)?;
    }
    emit_after_step(&mut file)?;
    Ok(())
}

fn emit_call_current_pc(
    mut file: impl Write,
    reason: u32,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if !trace_style.is_pure() {
        emit_sync_preflight_direct(&mut file)?;
        emit_flush_preflight_event_cursor(&mut file)?;
    }
    writeln!(
        file,
        "    movl ${reason}, {AOT_CTX_FALLBACK_REASON_OFFSET}(%r12)"
    )?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl %r15d, %esi")?;
    writeln!(file, "    call *72(%rsp)")?;
    if trace_style.is_pure() {
        emit_reload_pure_memory_state(&mut file)?;
    } else {
        emit_reload_preflight_event_cursor(&mut file)?;
    }
    emit_after_step(&mut file)?;
    Ok(())
}

fn emit_after_step(mut file: impl Write) -> Result<()> {
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "    incq 0(%rsp)")?;
    writeln!(file, "    movl 8(%rsp), %r15d")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je ceno_aot_done")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    jae ceno_aot_done")?;
    Ok(())
}

fn emit_reload_pure_memory_state(mut file: impl Write) -> Result<()> {
    writeln!(file, "    movq {AOT_CTX_MEMORY_CELLS_OFFSET}(%r12), %rbx")?;
    writeln!(
        file,
        "    movl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %r14d"
    )?;
    writeln!(
        file,
        "    movl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %edx"
    )?;
    writeln!(file, "    subl %r14d, %edx")?;
    writeln!(file, "    shll $2, %r14d")?;
    writeln!(file, "    shll $2, %edx")?;
    writeln!(file, "    movl %edx, 64(%rsp)")?;
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

.globl ceno_aot_fulltracer_emit_step
.hidden ceno_aot_fulltracer_emit_step
.type ceno_aot_fulltracer_emit_step, @function
ceno_aot_fulltracer_emit_step:
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
    movl %edx, 104(%r10)
    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), %rcx
    leaq 3(,%rcx,4), %rsi
    testl %ecx, %ecx
    cmovzq %rcx, %rsi
    movq %rsi, 120(%r10)

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
    writeln!(file, r#""#)?;
    Ok(())
}

fn emit_skeleton_l1_shared_recorder(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
.globl ceno_aot_skeleton_l1_emit_step
.hidden ceno_aot_skeleton_l1_emit_step
.type ceno_aot_skeleton_l1_emit_step, @function
ceno_aot_skeleton_l1_emit_step:
    pushq %r10
    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    movq (%r8), %rcx
    imulq $136, %rcx, %r9
    addq %r9, %r10
    movabsq $0xa5a5a5a5a5a5a5a5, %rax
    movq %rax, 0(%r10)
    movq %rax, 8(%r10)
    movq %rax, 16(%r10)
    movq %rax, 24(%r10)
    movq %rax, 32(%r10)
    movq %rax, 40(%r10)
    movq %rax, 48(%r10)
    movq %rax, 56(%r10)
    movq %rax, 64(%r10)
    movq %rax, 72(%r10)
    movq %rax, 80(%r10)
    movq %rax, 88(%r10)
    movq %rax, 96(%r10)
    movq %rax, 104(%r10)
    movq %rax, 112(%r10)
    movq %rax, 120(%r10)
    movq %rax, 128(%r10)

    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    movq (%r8), %rax
    movq %rax, 0(%r10)
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %eax
    movl %eax, 8(%r10)
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %eax
    movl %eax, 12(%r10)
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %eax
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %eax
    shrl $2, %eax
    imulq $12, %rax, %rax
    addq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %rax
    movq 0(%rax), %rdx
    movq %rdx, 32(%r10)
    movl 8(%rax), %edx
    movl %edx, 40(%r10)
    movl $0, 44(%r10)
    movl $0, 48(%r10)
    movl $0, 64(%r10)
    movl $0, 80(%r10)
    movl $0, 104(%r10)

    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_skeleton_l1_rs1_done
    movb $1, 44(%r10)
    movl {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12), %eax
    shll $6, %eax
    movl %eax, 48(%r10)
.L_skeleton_l1_rs1_done:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_skeleton_l1_rs2_done
    movb $1, 45(%r10)
    movl {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12), %eax
    shll $6, %eax
    movl %eax, 64(%r10)
.L_skeleton_l1_rs2_done:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_skeleton_l1_rd_done
    movb $1, 46(%r10)
    movl {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12), %eax
    shll $6, %eax
    movl %eax, 80(%r10)
.L_skeleton_l1_rd_done:
    testl $24, %edi
    je .L_skeleton_l1_mem_done
    movb $1, 47(%r10)
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax
    movl %eax, 104(%r10)
.L_skeleton_l1_mem_done:
    cmpl ${AOT_TRACE_MODE_MEMORY_L4}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    je .L_skeleton_l1_bounds_enabled
    cmpl ${AOT_TRACE_MODE_FUTURE_ACCESS_L5}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    jne .L_skeleton_l1_bounds_done
.L_skeleton_l1_bounds_enabled:
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %rax
    movl (%rax), %eax
    movl %eax, 16(%r10)
    movl %eax, 20(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %rax
    movl (%rax), %eax
    movl %eax, 24(%r10)
    movl %eax, 28(%r10)
.L_skeleton_l1_bounds_done:
    cmpl ${AOT_TRACE_MODE_VALUES_L2}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    je .L_skeleton_l1_values_enabled
    cmpl ${AOT_TRACE_MODE_REGISTERS_L3}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    je .L_skeleton_l1_values_enabled
    cmpl ${AOT_TRACE_MODE_MEMORY_L4}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    je .L_skeleton_l1_values_enabled
    cmpl ${AOT_TRACE_MODE_FUTURE_ACCESS_L5}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    jne .L_skeleton_l1_values_done
.L_skeleton_l1_values_enabled:
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_skeleton_l1_rs1_value_done
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %eax
    movl %eax, 52(%r10)
.L_skeleton_l1_rs1_value_done:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_skeleton_l1_rs2_value_done
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %eax
    movl %eax, 68(%r10)
.L_skeleton_l1_rs2_value_done:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_skeleton_l1_rd_value_done
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %eax
    movl %eax, 84(%r10)
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %eax
    movl %eax, 88(%r10)
.L_skeleton_l1_rd_value_done:
    testl $24, %edi
    je .L_skeleton_l1_values_done
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %eax
    movl %eax, 108(%r10)
    movl {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12), %eax
    movl %eax, 112(%r10)
.L_skeleton_l1_values_done:
    cmpl ${AOT_TRACE_MODE_REGISTERS_L3}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    je .L_skeleton_l1_registers_enabled
    cmpl ${AOT_TRACE_MODE_MEMORY_L4}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    je .L_skeleton_l1_registers_enabled
    cmpl ${AOT_TRACE_MODE_FUTURE_ACCESS_L5}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    jne .L_skeleton_l1_registers_done
.L_skeleton_l1_registers_enabled:
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_skeleton_l1_rs1_previous_done
    movq {AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET}(%r12), %rax
    movq %rax, 56(%r10)
.L_skeleton_l1_rs1_previous_done:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_skeleton_l1_rs2_previous_done
    movq {AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET}(%r12), %rax
    movq %rax, 72(%r10)
.L_skeleton_l1_rs2_previous_done:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_skeleton_l1_registers_done
    movq {AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET}(%r12), %rax
    movq %rax, 96(%r10)
.L_skeleton_l1_registers_done:
    cmpl ${AOT_TRACE_MODE_MEMORY_L4}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    je .L_skeleton_l1_memory_enabled
    cmpl ${AOT_TRACE_MODE_FUTURE_ACCESS_L5}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    jne .L_skeleton_l1_memory_done
.L_skeleton_l1_memory_enabled:
    testl $24, %edi
    je .L_skeleton_l1_memory_done
    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), %rax
    leaq 3(,%rax,4), %rcx
    testl %eax, %eax
    cmovzq %rax, %rcx
    movq %rcx, 120(%r10)

    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    leal (,%rdx,4), %esi
    leal 4(%rsi), %ecx
    cmpl {AOT_CTX_HEAP_START_OFFSET}(%r12), %esi
    jb .L_skeleton_l1_heap_done
    cmpl {AOT_CTX_HEAP_END_OFFSET}(%r12), %esi
    jae .L_skeleton_l1_heap_done
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %rax
    cmpl (%rax), %ecx
    jbe .L_skeleton_l1_heap_done
    movl %ecx, (%rax)
.L_skeleton_l1_heap_done:
    cmpl {AOT_CTX_HINTS_START_OFFSET}(%r12), %esi
    jb .L_skeleton_l1_hint_done
    cmpl {AOT_CTX_HINTS_END_OFFSET}(%r12), %esi
    jae .L_skeleton_l1_hint_done
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %rax
    cmpl (%rax), %ecx
    jbe .L_skeleton_l1_hint_done
    movl %ecx, (%rax)
.L_skeleton_l1_hint_done:
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %rax
    movl (%rax), %eax
    movl %eax, 20(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %rax
    movl (%rax), %eax
    movl %eax, 28(%r10)
.L_skeleton_l1_memory_done:
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    incq (%r8)
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    popq %r10
    ret
"#
    )?;
    Ok(())
}

fn emit_compact_skeleton_l1c_shared_recorder(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
.globl ceno_aot_compact_skeleton_l1c_emit_step
.hidden ceno_aot_compact_skeleton_l1c_emit_step
.type ceno_aot_compact_skeleton_l1c_emit_step, @function
ceno_aot_compact_skeleton_l1c_emit_step:
    pushq %r10
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    movq (%r8), %rcx
    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10
    movq %rcx, %r9
    shlq $4, %r9
    addq %r9, %r10

    movl ${COMPACT_SKELETON_NO_MEMORY}, %eax
    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi
    testl $24, %edi
    je .L_compact_skeleton_l1c_no_memory
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax
.L_compact_skeleton_l1c_no_memory:
    movl %ecx, 0(%r10)
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    movl %edx, 4(%r10)
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    movl %edx, 8(%r10)
    movl %eax, 12(%r10)

    incq %rcx
    movq %rcx, (%r8)
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    popq %r10
    ret
"#
    )?;
    Ok(())
}

fn emit_compact_values_l2c_shared_recorder(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
.globl ceno_aot_compact_values_l2c_emit_step
.hidden ceno_aot_compact_values_l2c_emit_step
.type ceno_aot_compact_values_l2c_emit_step, @function
ceno_aot_compact_values_l2c_emit_step:
    pushq %r10
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    movq (%r8), %rcx
    movq {AOT_CTX_COMPACT_BYTES_CURSOR_OFFSET}(%r12), %r8
    movq (%r8), %r9
    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10
    addq %r9, %r10

    movl ${COMPACT_SKELETON_NO_MEMORY}, %eax
    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi
    testl ${}, %edi
    je .L_compact_values_l2c_no_memory
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax
.L_compact_values_l2c_no_memory:
    movl %ecx, 0(%r10)
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    movl %edx, 4(%r10)
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    movl %edx, 8(%r10)
    movl %eax, 12(%r10)

    cmpl ${}, %edi
    je .L_compact_values_l2c_r
    cmpl ${}, %edi
    je .L_compact_values_l2c_i
    cmpl ${}, %edi
    je .L_compact_values_l2c_branch
    cmpl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_compact_values_l2c_j
    cmpl ${}, %edi
    je .L_compact_values_l2c_load
    cmpl ${}, %edi
    je .L_compact_values_l2c_store
    movl $16, %r11d
    jmp .L_compact_values_l2c_commit

.L_compact_values_l2c_r:
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    movl %edx, 16(%r10)
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    movl %edx, 20(%r10)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 24(%r10)
    movl $28, %r11d
    jmp .L_compact_values_l2c_commit
.L_compact_values_l2c_i:
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    movl %edx, 16(%r10)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 20(%r10)
    movl $24, %r11d
    jmp .L_compact_values_l2c_commit
.L_compact_values_l2c_branch:
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    movl %edx, 16(%r10)
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    movl %edx, 20(%r10)
    movl $24, %r11d
    jmp .L_compact_values_l2c_commit
.L_compact_values_l2c_j:
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 16(%r10)
    movl $20, %r11d
    jmp .L_compact_values_l2c_commit
.L_compact_values_l2c_load:
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    movl %edx, 16(%r10)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 20(%r10)
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 24(%r10)
    movl $28, %r11d
    jmp .L_compact_values_l2c_commit
.L_compact_values_l2c_store:
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    movl %edx, 16(%r10)
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    movl %edx, 20(%r10)
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 24(%r10)
    movl $28, %r11d

.L_compact_values_l2c_commit:
    addq %r11, %r9
    movq {AOT_CTX_COMPACT_BYTES_CURSOR_OFFSET}(%r12), %r8
    movq %r9, (%r8)
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    incq %rcx
    movq %rcx, (%r8)
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    popq %r10
    ret
"#,
        NATIVE_TRACE_LOAD_MEM | NATIVE_TRACE_STORE_MEM,
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_READ_RS2 | NATIVE_TRACE_WRITE_RD,
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_WRITE_RD,
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_READ_RS2,
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_WRITE_RD | NATIVE_TRACE_LOAD_MEM,
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_READ_RS2 | NATIVE_TRACE_STORE_MEM,
    )?;
    Ok(())
}

fn emit_l3c_pack(
    mut file: impl Write,
    load: &str,
    bit: usize,
    width: usize,
    check_cycle: bool,
) -> Result<()> {
    writeln!(file, "    {load}")?;
    if check_cycle {
        writeln!(
            file,
            "    cmpq ${}, %rax",
            1u64 << COMPACT_REGISTERS_CYCLE_BITS
        )?;
        writeln!(file, "    jae .L_compact_registers_l3c_overflow")?;
    }
    let chunk_offset = bit / 64 * 8;
    let shift = bit % 64;
    if shift == 0 {
        writeln!(file, "    orq %rax, {chunk_offset}(%rsp)")?;
    } else {
        writeln!(file, "    movq %rax, %rdx")?;
        writeln!(file, "    shlq ${shift}, %rdx")?;
        writeln!(file, "    orq %rdx, {chunk_offset}(%rsp)")?;
        if shift + width > 64 {
            writeln!(file, "    shrq ${}, %rax", 64 - shift)?;
            writeln!(file, "    orq %rax, {}(%rsp)", chunk_offset + 8)?;
        }
    }
    Ok(())
}

fn emit_l3c_commit(mut file: impl Write, size: usize) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_COMPACT_BYTES_CURSOR_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    movq (%r8), %r9")?;
    writeln!(
        file,
        "    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    addq %r9, %r10")?;
    let mut offset = 0;
    for _ in 0..size / 8 {
        writeln!(file, "    movq {offset}(%rsp), %rax")?;
        writeln!(file, "    movq %rax, {offset}(%r10)")?;
        offset += 8;
    }
    let remainder = size - offset;
    if remainder >= 4 {
        writeln!(file, "    movl {offset}(%rsp), %eax")?;
        writeln!(file, "    movl %eax, {offset}(%r10)")?;
        offset += 4;
    }
    if remainder & 2 != 0 {
        writeln!(file, "    movw {offset}(%rsp), %ax")?;
        writeln!(file, "    movw %ax, {offset}(%r10)")?;
        offset += 2;
    }
    if remainder & 1 != 0 {
        writeln!(file, "    movb {offset}(%rsp), %al")?;
        writeln!(file, "    movb %al, {offset}(%r10)")?;
    }
    writeln!(file, "    addq ${size}, %r9")?;
    writeln!(file, "    movq %r9, (%r8)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    incq (%r8)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    addq $4, (%r8)")?;
    writeln!(file, "    addq $32, %rsp")?;
    writeln!(file, "    popq %r10")?;
    writeln!(file, "    ret")?;
    Ok(())
}

fn emit_l3c_access(
    mut file: impl Write,
    bit: &mut usize,
    previous_offset: usize,
    value_offset: usize,
) -> Result<()> {
    emit_l3c_pack(
        &mut file,
        &format!("movq {previous_offset}(%r12), %rax"),
        *bit,
        COMPACT_REGISTERS_CYCLE_BITS,
        true,
    )?;
    *bit += COMPACT_REGISTERS_CYCLE_BITS;
    emit_l3c_pack(
        &mut file,
        &format!("movl {value_offset}(%r12), %eax"),
        *bit,
        32,
        false,
    )?;
    *bit += 32;
    Ok(())
}

fn emit_l4c_update_bounds(mut file: impl Write, label: &str) -> Result<()> {
    writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
    writeln!(file, "    shll $2, %eax")?;
    writeln!(file, "    leal 4(%rax), %edx")?;
    writeln!(file, "    cmpl {AOT_CTX_HEAP_START_OFFSET}(%r12), %eax")?;
    writeln!(file, "    jb .L_compact_memory_l4c_{label}_heap_done")?;
    writeln!(file, "    cmpl {AOT_CTX_HEAP_END_OFFSET}(%r12), %eax")?;
    writeln!(file, "    jae .L_compact_memory_l4c_{label}_heap_done")?;
    writeln!(
        file,
        "    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    cmpl (%r8), %edx")?;
    writeln!(file, "    jbe .L_compact_memory_l4c_{label}_heap_done")?;
    writeln!(file, "    movl %edx, (%r8)")?;
    writeln!(file, ".L_compact_memory_l4c_{label}_heap_done:")?;
    writeln!(file, "    cmpl {AOT_CTX_HINTS_START_OFFSET}(%r12), %eax")?;
    writeln!(file, "    jb .L_compact_memory_l4c_{label}_hint_done")?;
    writeln!(file, "    cmpl {AOT_CTX_HINTS_END_OFFSET}(%r12), %eax")?;
    writeln!(file, "    jae .L_compact_memory_l4c_{label}_hint_done")?;
    writeln!(
        file,
        "    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    cmpl (%r8), %edx")?;
    writeln!(file, "    jbe .L_compact_memory_l4c_{label}_hint_done")?;
    writeln!(file, "    movl %edx, (%r8)")?;
    writeln!(file, ".L_compact_memory_l4c_{label}_hint_done:")?;
    Ok(())
}

fn emit_l5c_consume_row_future_accesses(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
    xorl %esi, %esi
    movq {AOT_CTX_LAYERED_NEXT_ACCESS_CURSOR_OFFSET}(%r12), %r8
    movq (%r8), %rcx
.L_compact_future_l5c_event_loop:
    cmpq {AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_LEN_OFFSET}(%r12), %rcx
    jae .L_compact_future_l5c_event_done
    movq {AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_OFFSET}(%r12), %r9
    leaq (%rcx,%rcx,2), %rax
    leaq (%r9,%rax,8), %r9
    movq 0(%r9), %rax
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r10
    movq (%r10), %rdx
    cmpq %rdx, %rax
    jb .L_compact_registers_l3c_overflow
    leaq 4(%rdx), %r10
    cmpq %r10, %rax
    jae .L_compact_future_l5c_event_done
    subq %rdx, %rax
    movl 16(%r9), %edx
    cmpq $0, %rax
    je .L_compact_future_l5c_rs1
    cmpq $1, %rax
    je .L_compact_future_l5c_rs2
    cmpq $2, %rax
    je .L_compact_future_l5c_rd
    cmpq $3, %rax
    je .L_compact_future_l5c_mem
    jmp .L_compact_registers_l3c_overflow
.L_compact_future_l5c_rs1:
    testl ${NATIVE_TRACE_READ_RS1}, {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12)
    jz .L_compact_registers_l3c_overflow
    movl {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12), %eax
    shll $6, %eax
    cmpl %eax, %edx
    jne .L_compact_registers_l3c_overflow
    orl ${}, %esi
    jmp .L_compact_future_l5c_event_next
.L_compact_future_l5c_rs2:
    testl ${NATIVE_TRACE_READ_RS2}, {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12)
    jz .L_compact_registers_l3c_overflow
    movl {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12), %eax
    shll $6, %eax
    cmpl %eax, %edx
    jne .L_compact_registers_l3c_overflow
    orl ${}, %esi
    jmp .L_compact_future_l5c_event_next
.L_compact_future_l5c_rd:
    testl ${NATIVE_TRACE_WRITE_RD}, {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12)
    jz .L_compact_registers_l3c_overflow
    movl {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12), %eax
    shll $6, %eax
    cmpl %eax, %edx
    jne .L_compact_registers_l3c_overflow
    orl ${}, %esi
    jmp .L_compact_future_l5c_event_next
.L_compact_future_l5c_mem:
    testl ${}, {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12)
    jz .L_compact_registers_l3c_overflow
    cmpl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    jne .L_compact_registers_l3c_overflow
    orl ${}, %esi
.L_compact_future_l5c_event_next:
    incq %rcx
    movq %rcx, (%r8)
    jmp .L_compact_future_l5c_event_loop
.L_compact_future_l5c_event_done:
"#,
        crate::StepRecord::FUTURE_ACCESS_RS1,
        crate::StepRecord::FUTURE_ACCESS_RS2,
        crate::StepRecord::FUTURE_ACCESS_RD,
        NATIVE_TRACE_LOAD_MEM | NATIVE_TRACE_STORE_MEM,
        crate::StepRecord::FUTURE_ACCESS_MEM,
    )?;
    Ok(())
}

fn emit_compact_registers_l3c_shared_recorder(
    mut file: impl Write,
    memory_l4: bool,
    future_l5: bool,
) -> Result<()> {
    writeln!(
        file,
        r#"
.globl ceno_aot_compact_registers_l3c_emit_step
.hidden ceno_aot_compact_registers_l3c_emit_step
.type ceno_aot_compact_registers_l3c_emit_step, @function
ceno_aot_compact_registers_l3c_emit_step:
    pushq %r10
    subq $32, %rsp
    movq $0, 0(%rsp)
    movq $0, 8(%rsp)
    movq $0, 16(%rsp)
    movq $0, 24(%rsp)
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %eax
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %eax
    testl $3, %eax
    jne .L_compact_registers_l3c_overflow
    shrl $2, %eax
    cmpl ${}, %eax
    jae .L_compact_registers_l3c_overflow
"#,
        1u32 << COMPACT_REGISTERS_PC_BITS,
    )?;
    if future_l5 {
        emit_l5c_consume_row_future_accesses(&mut file)?;
    }
    let pc_load = future_l5
        .then(|| {
            format!(
                "movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %eax\n    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %eax\n    shrl $2, %eax"
            )
        })
        .unwrap_or_else(|| "movl %eax, %eax".to_owned());
    emit_l3c_pack(&mut file, &pc_load, 0, COMPACT_REGISTERS_PC_BITS, false)?;
    writeln!(
        file,
        "    imulq ${}, %rax, %rax",
        std::mem::size_of::<Instruction>()
    )?;
    writeln!(file, "    movq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %r8")?;
    writeln!(
        file,
        "    movl {}(%r8,%rax), %eax",
        std::mem::offset_of!(Instruction, raw)
    )?;
    writeln!(file, "    shrl $7, %eax")?;
    emit_l3c_pack(
        &mut file,
        "movl %eax, %eax",
        20,
        COMPACT_REGISTERS_RAW_BITS,
        false,
    )?;
    writeln!(file, "    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi")?;
    writeln!(
        file,
        "    cmpl ${}, %edi",
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_READ_RS2 | NATIVE_TRACE_WRITE_RD
    )?;
    writeln!(file, "    je .L_compact_registers_l3c_r")?;
    writeln!(
        file,
        "    cmpl ${}, %edi",
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_WRITE_RD
    )?;
    writeln!(file, "    je .L_compact_registers_l3c_i")?;
    writeln!(
        file,
        "    cmpl ${}, %edi",
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_READ_RS2
    )?;
    writeln!(file, "    je .L_compact_registers_l3c_branch")?;
    writeln!(file, "    cmpl ${NATIVE_TRACE_WRITE_RD}, %edi")?;
    writeln!(file, "    je .L_compact_registers_l3c_j")?;
    writeln!(
        file,
        "    cmpl ${}, %edi",
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_WRITE_RD | NATIVE_TRACE_LOAD_MEM
    )?;
    writeln!(file, "    je .L_compact_registers_l3c_load")?;
    writeln!(
        file,
        "    cmpl ${}, %edi",
        NATIVE_TRACE_READ_RS1 | NATIVE_TRACE_READ_RS2 | NATIVE_TRACE_STORE_MEM
    )?;
    writeln!(file, "    je .L_compact_registers_l3c_store")?;
    writeln!(
        file,
        "    cmpl ${}, {AOT_CTX_TRACE_KIND_OFFSET}(%r12)",
        InsnKind::ECALL as u32
    )?;
    writeln!(file, "    je .L_compact_registers_l3c_exceptional")?;
    writeln!(file, "    jmp .L_compact_registers_l3c_header")?;

    for (label, accesses, memory, l3_size) in [
        (
            "r",
            &[
                (
                    AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS1_VALUE_OFFSET,
                ),
                (
                    AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS2_VALUE_OFFSET,
                ),
                (
                    AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RD_BEFORE_OFFSET,
                ),
            ][..],
            false,
            28,
        ),
        (
            "i",
            &[
                (
                    AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS1_VALUE_OFFSET,
                ),
                (
                    AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RD_BEFORE_OFFSET,
                ),
            ][..],
            false,
            21,
        ),
        (
            "branch",
            &[
                (
                    AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS1_VALUE_OFFSET,
                ),
                (
                    AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS2_VALUE_OFFSET,
                ),
            ][..],
            false,
            21,
        ),
        (
            "j",
            &[(
                AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RD_BEFORE_OFFSET,
            )][..],
            false,
            13,
        ),
        (
            "load",
            &[
                (
                    AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS1_VALUE_OFFSET,
                ),
                (
                    AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RD_BEFORE_OFFSET,
                ),
            ][..],
            true,
            25,
        ),
        (
            "store",
            &[
                (
                    AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS1_VALUE_OFFSET,
                ),
                (
                    AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
                    AOT_CTX_TRACE_RS2_VALUE_OFFSET,
                ),
            ][..],
            true,
            25,
        ),
    ] {
        writeln!(file, ".L_compact_registers_l3c_{label}:")?;
        let mut bit = COMPACT_REGISTERS_PC_BITS + COMPACT_REGISTERS_RAW_BITS;
        for &(previous, value) in accesses {
            emit_l3c_access(&mut file, &mut bit, previous, value)?;
        }
        if memory {
            emit_l3c_pack(
                &mut file,
                &format!("movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %eax"),
                bit,
                32,
                false,
            )?;
            bit += 32;
            if memory_l4 {
                emit_l3c_pack(
                    &mut file,
                    &format!(
                        "movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), %rax\n    leaq 3(,%rax,4), %rdx\n    testl %eax, %eax\n    cmovnzq %rdx, %rax"
                    ),
                    bit,
                    COMPACT_REGISTERS_CYCLE_BITS,
                    true,
                )?;
                bit += COMPACT_REGISTERS_CYCLE_BITS;
                emit_l4c_update_bounds(&mut file, label)?;
            }
        }
        if future_l5 {
            let mask_bits: &[u8] = match label {
                "r" => &[
                    crate::StepRecord::FUTURE_ACCESS_RS1,
                    crate::StepRecord::FUTURE_ACCESS_RS2,
                    crate::StepRecord::FUTURE_ACCESS_RD,
                ],
                "i" => &[
                    crate::StepRecord::FUTURE_ACCESS_RS1,
                    crate::StepRecord::FUTURE_ACCESS_RD,
                ],
                "branch" => &[
                    crate::StepRecord::FUTURE_ACCESS_RS1,
                    crate::StepRecord::FUTURE_ACCESS_RS2,
                ],
                "j" => &[crate::StepRecord::FUTURE_ACCESS_RD],
                "load" => &[
                    crate::StepRecord::FUTURE_ACCESS_RS1,
                    crate::StepRecord::FUTURE_ACCESS_RD,
                    crate::StepRecord::FUTURE_ACCESS_MEM,
                ],
                "store" => &[
                    crate::StepRecord::FUTURE_ACCESS_RS1,
                    crate::StepRecord::FUTURE_ACCESS_RS2,
                    crate::StepRecord::FUTURE_ACCESS_MEM,
                ],
                _ => unreachable!(),
            };
            for mask in mask_bits {
                emit_l3c_pack(
                    &mut file,
                    &format!(
                        "movl %esi, %eax\n    shrl ${}, %eax\n    andl $1, %eax",
                        mask.trailing_zeros()
                    ),
                    bit,
                    1,
                    false,
                )?;
                bit += 1;
            }
        }
        let size = if future_l5 {
            match label {
                "r" | "load" | "store" => 29,
                "i" | "branch" => 21,
                "j" => 14,
                _ => unreachable!(),
            }
        } else if memory_l4 && memory {
            28
        } else {
            l3_size
        };
        debug_assert_eq!(bit.div_ceil(8), size);
        emit_l3c_commit(&mut file, size)?;
    }
    writeln!(file, ".L_compact_registers_l3c_exceptional:")?;
    emit_l3c_pack(
        &mut file,
        &format!("movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %eax"),
        COMPACT_REGISTERS_PC_BITS + COMPACT_REGISTERS_RAW_BITS,
        32,
        false,
    )?;
    if memory_l4 {
        emit_l3c_pack(
            &mut file,
            &format!("movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8\n    movl (%r8), %eax"),
            COMPACT_REGISTERS_PC_BITS + COMPACT_REGISTERS_RAW_BITS + 32,
            32,
            false,
        )?;
        emit_l3c_pack(
            &mut file,
            &format!("movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8\n    movl (%r8), %eax"),
            COMPACT_REGISTERS_PC_BITS + COMPACT_REGISTERS_RAW_BITS + 64,
            32,
            false,
        )?;
    }
    emit_l3c_commit(&mut file, if memory_l4 { 18 } else { 10 })?;
    writeln!(file, ".L_compact_registers_l3c_header:")?;
    emit_l3c_commit(&mut file, 6)?;
    writeln!(file, ".L_compact_registers_l3c_overflow:")?;
    writeln!(file, "    addq $32, %rsp")?;
    writeln!(file, "    popq %r10")?;
    // Discard this recorder call's return address before entering the native
    // entrypoint epilogue, whose stack frame begins at the caller's rsp.
    writeln!(file, "    addq $8, %rsp")?;
    writeln!(file, "    jmp ceno_aot_error")?;
    Ok(())
}

fn emit_gpu_replay_shared_recorder(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
.macro GPU_REPLAY_WRITE field, source
    movq (\field*8)(%r10), %r8
    movl \source, (%r8,%rcx,4)
.endm

.macro GPU_REPLAY_ACCESS index_offset, subcycle, scratch_offset
    cmpl ${AOT_TRACE_MODE_COMPACT_CLOSURE_L7}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)
    jne .L_gpu_replay_addressed_access_\@
.if \scratch_offset == 0
    movq {AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET}(%r12), %r11
.elseif \scratch_offset == 4
    movq {AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET}(%r12), %r11
.else
    movq {AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET}(%r12), %r11
.endif
    movl %r11d, \scratch_offset(%rsp)
    testq %r11, %r11
    jne .L_gpu_replay_access_done_\@
    movq {AOT_CTX_GPU_REPLAY_LATEST_LEN_OFFSET}(%r12), %r8
    incq (%r8)
    jmp .L_gpu_replay_access_done_\@
.L_gpu_replay_addressed_access_\@:
    movl \index_offset(%r12), %edx
    movq {AOT_CTX_GPU_REPLAY_LATEST_CELLS_OFFSET}(%r12), %r8
    shll $6, %edx
    movl %edx, %r9d
    subl {AOT_CTX_GPU_REPLAY_LATEST_BASE_OFFSET}(%r12), %r9d
    movq (%r8,%r9,8), %r11
    movq %rax, %rsi
    addq $\subcycle, %rsi
    movq %rsi, (%r8,%r9,8)
    movl %r11d, \scratch_offset(%rsp)
    testq %r11, %r11
    jne .L_gpu_replay_access_done_\@
    movq {AOT_CTX_GPU_REPLAY_LATEST_LEN_OFFSET}(%r12), %r8
    incq (%r8)
.L_gpu_replay_access_done_\@:
.endm

.globl ceno_aot_gpu_replay_emit_step
.hidden ceno_aot_gpu_replay_emit_step
.type ceno_aot_gpu_replay_emit_step, @function
ceno_aot_gpu_replay_emit_step:
    subq $48, %rsp
    movl $0, 0(%rsp)
    movl $0, 4(%rsp)
    movl $0, 8(%rsp)
    movl $0, 12(%rsp)
    movl $0, 16(%rsp)

    movl {AOT_CTX_TRACE_KIND_OFFSET}(%r12), %eax
    cmpq {AOT_CTX_GPU_REPLAY_KIND_COUNT_OFFSET}(%r12), %rax
    jae .L_gpu_replay_bad_kind
    imulq $128, %rax, %rax
    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10
    addq %rax, %r10
    cmpl ${gpu_sentinel}, 116(%r10)
    je .L_gpu_replay_sentinel_ok
    cmpl ${gpu_compact_sentinel}, 116(%r10)
    jne .L_gpu_replay_bad_sentinel
.L_gpu_replay_sentinel_ok:
    movl 108(%r10), %ecx
    cmpl 104(%r10), %ecx
    jae .L_gpu_replay_capacity
    cmpl $7, 112(%r10)
    ja .L_gpu_replay_bad_layout

    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8
    movq (%r8), %rax
    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_gpu_replay_rs1_done
    GPU_REPLAY_ACCESS {AOT_CTX_TRACE_RS1_IDX_OFFSET}, 0, 0
.L_gpu_replay_rs1_done:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_gpu_replay_rs2_done
    GPU_REPLAY_ACCESS {AOT_CTX_TRACE_RS2_IDX_OFFSET}, 1, 4
.L_gpu_replay_rs2_done:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_gpu_replay_rd_done
    GPU_REPLAY_ACCESS {AOT_CTX_TRACE_RD_IDX_OFFSET}, 2, 8
.L_gpu_replay_rd_done:
    testl $24, %edi
    je .L_gpu_replay_mem_done
    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), %r11
    leaq 3(,%r11,4), %rsi
    testl %r11d, %r11d
    cmovzq %r11, %rsi
    movl %esi, 12(%rsp)
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    leal (,%rdx,4), %esi
    leal 4(%rsi), %r9d
    cmpl {AOT_CTX_HEAP_START_OFFSET}(%r12), %esi
    jb .L_gpu_replay_heap_done
    cmpl {AOT_CTX_HEAP_END_OFFSET}(%r12), %esi
    jae .L_gpu_replay_heap_done
    movq {AOT_CTX_GPU_REPLAY_MAX_HEAP_OFFSET}(%r12), %r8
    cmpl (%r8), %r9d
    jbe .L_gpu_replay_heap_done
    movl %r9d, (%r8)
.L_gpu_replay_heap_done:
    cmpl {AOT_CTX_HINTS_START_OFFSET}(%r12), %esi
    jb .L_gpu_replay_mem_done
    cmpl {AOT_CTX_HINTS_END_OFFSET}(%r12), %esi
    jae .L_gpu_replay_mem_done
    movq {AOT_CTX_GPU_REPLAY_MAX_HINT_OFFSET}(%r12), %r8
    cmpl (%r8), %r9d
    jbe .L_gpu_replay_mem_done
    movl %r9d, (%r8)
.L_gpu_replay_mem_done:

    movq {AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET}(%r12), %r8
    movq (%r8), %rsi
.L_gpu_replay_event_loop:
    cmpq {AOT_CTX_GPU_REPLAY_EVENTS_LEN_OFFSET}(%r12), %rsi
    jae .L_gpu_replay_events_done
    leaq (%rsi,%rsi,2), %r9
    shlq $3, %r9
    addq {AOT_CTX_GPU_REPLAY_EVENTS_OFFSET}(%r12), %r9
    movq 0(%r9), %r11
    cmpq %rax, %r11
    jb .L_gpu_replay_bad_event
    leaq 4(%rax), %rdx
    cmpq %rdx, %r11
    jae .L_gpu_replay_events_done
    subq %rax, %r11
    movl 16(%r9), %edx
    cmpl $0, %r11d
    je .L_gpu_replay_event_rs1
    cmpl $1, %r11d
    je .L_gpu_replay_event_rs2
    cmpl $2, %r11d
    je .L_gpu_replay_event_rd
    cmpl $3, %r11d
    jne .L_gpu_replay_bad_event
    testl $24, %edi
    je .L_gpu_replay_bad_event
    cmpl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    jne .L_gpu_replay_bad_event
    jmp .L_gpu_replay_event_match
.L_gpu_replay_event_rs1:
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_gpu_replay_bad_event
    movl {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12), %r9d
    shll $6, %r9d
    cmpl %r9d, %edx
    jne .L_gpu_replay_bad_event
    jmp .L_gpu_replay_event_match
.L_gpu_replay_event_rs2:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_gpu_replay_bad_event
    movl {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12), %r9d
    shll $6, %r9d
    cmpl %r9d, %edx
    jne .L_gpu_replay_bad_event
    jmp .L_gpu_replay_event_match
.L_gpu_replay_event_rd:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_gpu_replay_bad_event
    movl {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12), %r9d
    shll $6, %r9d
    cmpl %r9d, %edx
    jne .L_gpu_replay_bad_event
.L_gpu_replay_event_match:
    btsl %r11d, 16(%rsp)
    incq %rsi
    jmp .L_gpu_replay_event_loop
.L_gpu_replay_events_done:
    movq {AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET}(%r12), %r8
    movq %rsi, (%r8)

    cmpl ${gpu_compact_sentinel}, 116(%r10)
    je .L_gpu_replay_compact

    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    movl (%r8), %edx
    GPU_REPLAY_WRITE 0, %edx
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 1, %edx
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %edx
    shrl $2, %edx
    imulq $12, %rdx, %rdx
    addq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %rdx
    movl 8(%rdx), %edx
    GPU_REPLAY_WRITE 2, %edx

    movl 112(%r10), %edx
    cmpl $0, %edx
    je .L_gpu_replay_layout_r
    cmpl $1, %edx
    je .L_gpu_replay_layout_i
    cmpl $2, %edx
    je .L_gpu_replay_layout_branch
    cmpl $3, %edx
    je .L_gpu_replay_layout_jal
    cmpl $4, %edx
    je .L_gpu_replay_layout_jalr
    cmpl $5, %edx
    je .L_gpu_replay_layout_load
    cmpl $6, %edx
    je .L_gpu_replay_layout_store
    jmp .L_gpu_replay_layout_u
.L_gpu_replay_layout_r:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 4(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 9, %edx
    movl $10, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_i:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl $8, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_branch:
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl 4(%rsp), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl $8, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_jal:
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl $7, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_jalr:
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl $9, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_load:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl 12(%rsp), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 9, %edx
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 10, %edx
    movl {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 11, %edx
    movl $12, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_store:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 4(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl 12(%rsp), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 9, %edx
    movl {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 10, %edx
    movl $11, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_u:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl $7, %edx
.L_gpu_replay_write_mask:
    movl 16(%rsp), %edi
    shll $8, %edi
    movq (%r10,%rdx,8), %r8
    movl %edi, (%r8,%rcx,4)
    incl %ecx
    movl %ecx, 108(%r10)
    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    incq (%r8)
    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    movl ${AOT_STATUS_CONTINUE}, %eax
    addq $48, %rsp
    ret

.L_gpu_replay_compact:
    movl 112(%r10), %edx
    cmpl $0, %edx
    je .L_gpu_compact_stride_31
    cmpl $3, %edx
    je .L_gpu_compact_stride_16
    cmpl $7, %edx
    je .L_gpu_compact_stride_20
    cmpl $5, %edx
    je .L_gpu_compact_stride_31
    cmpl $6, %edx
    je .L_gpu_compact_stride_31
    imulq $24, %rcx, %r9
    jmp .L_gpu_compact_pointer
.L_gpu_compact_stride_31:
    imulq $31, %rcx, %r9
    jmp .L_gpu_compact_pointer
.L_gpu_compact_stride_16:
    imulq $16, %rcx, %r9
    jmp .L_gpu_compact_pointer
.L_gpu_compact_stride_20:
    imulq $20, %rcx, %r9
.L_gpu_compact_pointer:
    addq 0(%r10), %r9
    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    movl (%r8), %edx
    subl 120(%r10), %edx
    cmpl $262144, %edx
    jae .L_gpu_replay_bad_compact_range
    movl %edx, 20(%rsp)

    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    testl %ecx, %ecx
    jne .L_gpu_compact_have_pc_base
    movl %edx, %r8d
    andl $0xffc00000, %r8d
    movl %r8d, 124(%r10)
.L_gpu_compact_have_pc_base:
    subl 124(%r10), %edx
    testl $3, %edx
    jne .L_gpu_replay_bad_compact_pc
    cmpl $0x400000, %edx
    jae .L_gpu_replay_bad_compact_pc
    shrl $2, %edx
    movl %edx, 24(%rsp)

    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %edx
    shrl $2, %edx
    imulq $12, %rdx, %rdx
    addq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %rdx
    movl 8(%rdx), %edx
    shrl $7, %edx
    movl %edx, 28(%rsp)

    movl 112(%r10), %edx
    cmpl $3, %edx
    je .L_gpu_compact_jal_tail
    cmpl $7, %edx
    je .L_gpu_compact_u_first

    movl 0(%rsp), %edx
    cmpl $0x8000000, %edx
    jae .L_gpu_replay_bad_compact_cycle
    movl %edx, 32(%rsp)
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    movl %edx, 36(%rsp)

    movl 112(%r10), %edx
    cmpl $1, %edx
    je .L_gpu_compact_second_rd
    cmpl $4, %edx
    je .L_gpu_compact_second_rd
    cmpl $5, %edx
    je .L_gpu_compact_second_rd
    movl 4(%rsp), %edx
    cmpl $0x8000000, %edx
    jae .L_gpu_replay_bad_compact_cycle
    movl %edx, 40(%rsp)
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    movl %edx, 44(%rsp)
    movl 112(%r10), %edx
    cmpl $2, %edx
    je .L_gpu_compact_pack_2
    jmp .L_gpu_compact_third_memory_or_rd

.L_gpu_compact_second_rd:
    movl 8(%rsp), %edx
    cmpl $0x8000000, %edx
    jae .L_gpu_replay_bad_compact_cycle
    movl %edx, 40(%rsp)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 44(%rsp)
    movl 112(%r10), %edx
    cmpl $5, %edx
    jne .L_gpu_compact_pack_2

.L_gpu_compact_third_memory_or_rd:
    movl 112(%r10), %edx
    cmpl $0, %edx
    je .L_gpu_compact_third_rd
    movl 12(%rsp), %edx
    jmp .L_gpu_compact_third_cycle
.L_gpu_compact_third_rd:
    movl 8(%rsp), %edx
.L_gpu_compact_third_cycle:
    cmpl $0x8000000, %edx
    jae .L_gpu_replay_bad_compact_cycle
    movl %edx, 0(%rsp)
    movl 112(%r10), %edx
    cmpl $0, %edx
    jne .L_gpu_compact_third_memory_value
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    jmp .L_gpu_compact_third_value
.L_gpu_compact_third_memory_value:
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
.L_gpu_compact_third_value:
    movl %edx, 4(%rsp)
    jmp .L_gpu_compact_pack_3

.L_gpu_compact_jal_tail:
    movl 8(%rsp), %edx
    cmpl $0x8000000, %edx
    jae .L_gpu_replay_bad_compact_cycle
    movl %edx, 32(%rsp)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 36(%rsp)
    jmp .L_gpu_compact_pack_1

.L_gpu_compact_u_tail:
    movl 8(%rsp), %edx
    cmpl $0x8000000, %edx
    jae .L_gpu_replay_bad_compact_cycle
    movl %edx, 40(%rsp)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 44(%rsp)
    jmp .L_gpu_compact_pack_u

.L_gpu_compact_u_first:
    movl 0(%rsp), %edx
    cmpl $0x8000000, %edx
    jae .L_gpu_replay_bad_compact_cycle
    movl %edx, 32(%rsp)
    jmp .L_gpu_compact_u_tail

.L_gpu_compact_pack_3:
    movl 0(%rsp), %edx
    movl 4(%rsp), %esi
    call .L_gpu_compact_pack_common
    movl 40(%rsp), %r8d
    shrl $6, %r8d
    movl 44(%rsp), %r11d
    shlq $21, %r11
    orq %r11, %r8
    movl %edx, %r11d
    andl $0x7ff, %r11d
    shlq $53, %r11
    orq %r11, %r8
    movq %r8, 16(%r9)
    shrl $11, %edx
    shlq $16, %rsi
    orq %rsi, %rdx
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    shlq $48, %rdi
    orq %rdi, %rdx
    movq %rdx, 24(%r9)
    jmp .L_gpu_compact_commit

.L_gpu_compact_pack_2:
    call .L_gpu_compact_pack_common
    movl 40(%rsp), %r8d
    shrl $6, %r8d
    movl 44(%rsp), %r11d
    shlq $21, %r11
    orq %r11, %r8
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    shlq $53, %rdi
    orq %rdi, %r8
    movq %r8, 16(%r9)
    jmp .L_gpu_compact_commit

.L_gpu_compact_pack_1:
    movl $0, 40(%rsp)
    call .L_gpu_compact_pack_common
    movq 8(%r9), %r8
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    shlq $58, %rdi
    orq %rdi, %r8
    movq %r8, 8(%r9)
    jmp .L_gpu_compact_commit

.L_gpu_compact_pack_u:
    movl 20(%rsp), %r8d
    movl 24(%rsp), %r11d
    shlq $18, %r11
    orq %r11, %r8
    movl 28(%rsp), %r11d
    shlq $38, %r11
    orq %r11, %r8
    movl 32(%rsp), %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 0(%r9)
    movl 32(%rsp), %r8d
    shrl $1, %r8d
    movl 40(%rsp), %r11d
    shlq $26, %r11
    orq %r11, %r8
    movl 44(%rsp), %r11d
    andl $0x7ff, %r11d
    shlq $53, %r11
    orq %r11, %r8
    movq %r8, 8(%r9)
    movl 44(%rsp), %r8d
    shrl $11, %r8d
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    shll $21, %edi
    orl %edi, %r8d
    movl %r8d, 16(%r9)
    jmp .L_gpu_compact_commit

// Assemble the common 63-bit prefix and first access into two fixed stores.
// Input access cycle/value live at 32/36(%rsp).
.L_gpu_compact_pack_common:
    movl 28(%rsp), %r8d
    movl 32(%rsp), %r11d
    shlq $18, %r11
    orq %r11, %r8
    movl 36(%rsp), %r11d
    shlq $38, %r11
    orq %r11, %r8
    movl 40(%rsp), %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 0(%r9)
    movl 40(%rsp), %r8d
    shrl $1, %r8d
    movl 44(%rsp), %r11d
    shlq $26, %r11
    orq %r11, %r8
    movl 48(%rsp), %r11d
    andl $0x3f, %r11d
    shlq $58, %r11
    orq %r11, %r8
    movq %r8, 8(%r9)
    ret

.L_gpu_compact_commit:
    movl 108(%r10), %ecx
    incl %ecx
    movl %ecx, 108(%r10)
    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    incq (%r8)
    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    movl ${AOT_STATUS_CONTINUE}, %eax
    addq $48, %rsp
    ret

.L_gpu_replay_bad_kind:
    movl $1, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_sentinel:
    movl $2, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_capacity:
    movl $3, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_layout:
    movl $4, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_event:
    movl $5, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_range:
    movl $6, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_pc:
    movl $7, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_cycle:
    movl $8, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_mask:
    movl $9, %edx
.L_gpu_replay_error:
    movl {AOT_CTX_TRACE_KIND_OFFSET}(%r12), %r11d
    shll $8, %r11d
    orl %r11d, %edx
    movq {AOT_CTX_GPU_REPLAY_ERROR_OFFSET}(%r12), %r8
    movl %edx, (%r8)
    movl ${AOT_STATUS_ERROR}, %eax
    addq $48, %rsp
    ret
"#,
        gpu_sentinel = crate::gpu_typed_ingress::GPU_TYPED_NATIVE_SENTINEL,
        gpu_compact_sentinel = crate::gpu_typed_ingress::GPU_COMPACT_NATIVE_SENTINEL,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_after_native_step(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    preflight_memory_bounds_updated: bool,
    preflight_memory_event_updated: bool,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if trace_style.is_layered_record() {
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movl %r15d, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        if trace_style.has_layered_registers() {
            let reserved = reserved_block_step.ok_or_else(|| {
                anyhow!("native L3 register row at {pc:#010x} is not block-admitted")
            })?;
            emit_layered_register_predecessors(&mut file, program, pc, reserved)?;
        }
        if trace_style == AssemblyTraceStyle::PreflightCompactClosureL7
            && insn.kind != InsnKind::ECALL
        {
            let reserved = reserved_block_step.ok_or_else(|| {
                anyhow!("native L7 family row at {pc:#010x} is not block-admitted")
            })?;
            let (family_count, static_rank) = l7_block_family_rank(
                program,
                reserved.block_start_pc,
                reserved.block_end_pc,
                pc,
                insn.kind,
            )?;
            let state_offset = insn.kind as usize
                * std::mem::size_of::<crate::gpu_typed_ingress::GpuTypedNativeKindState>();
            writeln!(
                file,
                "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
            )?;
            writeln!(file, "    addq ${state_offset}, %r10")?;
            writeln!(file, "    subl ${}, 108(%r10)", family_count - static_rank)?;
            writeln!(file, "    call ceno_aot_gpu_replay_emit_step")?;
            let restore = family_count - static_rank - 1;
            if restore != 0 {
                writeln!(
                    file,
                    "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
                )?;
                writeln!(file, "    addq ${state_offset}, %r10")?;
                writeln!(file, "    addl ${restore}, 108(%r10)")?;
            }
            if reserved.registers_resident {
                writeln!(file, "    movq %r13, %r10")?;
            }
        } else if trace_style.is_compact_skeleton() {
            writeln!(file, "    call ceno_aot_compact_skeleton_l1c_emit_step")?;
        } else if trace_style.is_compact_values() {
            writeln!(file, "    call ceno_aot_compact_values_l2c_emit_step")?;
        } else if trace_style.is_compact_registers()
            || trace_style.is_compact_memory()
            || trace_style.is_compact_future_access()
        {
            writeln!(file, "    call ceno_aot_compact_registers_l3c_emit_step")?;
        } else {
            writeln!(file, "    call ceno_aot_skeleton_l1_emit_step")?;
        }
        if reserved_block_step.is_none() {
            writeln!(file, "    incq 0(%rsp)")?;
            writeln!(file, "    movq 0(%rsp), %rax")?;
            writeln!(file, "    cmpq %rbp, %rax")?;
            writeln!(file, "    jae ceno_aot_done")?;
        }
        return Ok(());
    }
    if matches!(
        trace_style,
        AssemblyTraceStyle::PureBlock | AssemblyTraceStyle::PureCountedBlock
    ) {
        return Ok(());
    }
    if trace_style.is_pure() {
        writeln!(file, "    incq 0(%rsp)")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    cmpq %rbp, %rax")?;
        writeln!(file, "    jae ceno_aot_done")?;
        return Ok(());
    }

    if trace_style.is_preflight_direct() {
        let batched_block =
            reserved_block_step.is_some() && trace_style.uses_preflight_block_plan();
        if !batched_block {
            writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
            writeln!(file, "    movl %r15d, 8(%rsp)")?;
        }
        emit_preflight_direct_step_static(
            &mut file,
            pc,
            insn,
            preflight_memory_bounds_updated,
            preflight_memory_event_updated,
            if trace_style.uses_preflight_block_plan() {
                PreflightAccessMode::BlockAtomic
            } else {
                PreflightAccessMode::Exact
            },
            matches!(trace_style, AssemblyTraceStyle::PreflightScalar),
            reserved_block_step.map(|step| step.cycle_offset),
            trace_style,
        )?;
        let capture_done = format!(".L_preflight_capture_done_{pc:x}");
        writeln!(
            file,
            "    cmpl ${AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
        )?;
        writeln!(file, "    jne {capture_done}")?;
        // Preflight block emitters carry admission state in r10/r11. Preserve
        // it in dedicated context slots so metadata's fixed guest-stack offsets
        // remain valid.
        let saved = [
            "%rax", "%rcx", "%rdx", "%rsi", "%rdi", "%r8", "%r9", "%r10", "%r11",
        ];
        for (index, register) in saved.into_iter().enumerate() {
            writeln!(
                file,
                "    movq {register}, {}(%r12)",
                AOT_CTX_COMBINED_SAVED_OFFSET + index * 8
            )?;
        }
        emit_preflight_capture_trace_metadata(&mut file, insn)?;
        writeln!(file, "    call ceno_aot_gpu_replay_emit_step")?;
        for (index, register) in saved.into_iter().enumerate() {
            writeln!(
                file,
                "    movq {}(%r12), {register}",
                AOT_CTX_COMBINED_SAVED_OFFSET + index * 8
            )?;
        }
        writeln!(file, "{capture_done}:")?;
        if !batched_block {
            emit_after_step(&mut file)?;
        }
        return Ok(());
    }

    if matches!(
        trace_style,
        AssemblyTraceStyle::FullTracerDirect | AssemblyTraceStyle::GpuReplayDirect
    ) {
        let callback_label = format!(".L_fulltracer_callback_{pc:x}");
        let fulltracer_label = format!(".L_fulltracer_direct_{pc:x}");
        let gpu_replay_label = format!(".L_gpu_replay_direct_{pc:x}");
        let done_label = format!(".L_fulltracer_direct_done_{pc:x}");
        writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
        writeln!(file, "    movl %r15d, 8(%rsp)")?;
        writeln!(
            file,
            "    cmpl ${AOT_TRACE_MODE_FULLTRACER_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
        )?;
        writeln!(file, "    je {fulltracer_label}")?;
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            writeln!(
                file,
                "    cmpl ${AOT_TRACE_MODE_GPU_REPLAY_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
            )?;
            writeln!(file, "    je {gpu_replay_label}")?;
        }
        writeln!(file, "    jmp {callback_label}")?;
        writeln!(file, "{fulltracer_label}:")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        writeln!(file, "    call ceno_aot_fulltracer_emit_step")?;
        writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
        writeln!(file, "    jmp {done_label}")?;
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            writeln!(file, "{gpu_replay_label}:")?;
            emit_native_trace_metadata(&mut file, pc, program, insn)?;
            let packed_label = format!(".L_gpu_replay_packed_static_{pc:x}");
            let replay_done = format!(".L_gpu_replay_emit_done_{pc:x}");
            writeln!(
                file,
                "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
            )?;
            writeln!(file, "    jne {packed_label}")?;
            writeln!(file, "    call ceno_aot_gpu_replay_emit_step")?;
            writeln!(file, "    jmp {replay_done}")?;
            writeln!(file, "{packed_label}:")?;
            let reserved = reserved_block_step.ok_or_else(|| {
                anyhow!("packed production row at {pc:#010x} is not block-admitted")
            })?;
            emit_gpu_replay_register_predecessors(&mut file, program, pc, reserved)?;
            emit_gpu_replay_packed_static_row(&mut file, program, pc, insn, reserved)?;
            writeln!(file, "{replay_done}:")?;
            writeln!(file, "    jmp {done_label}")?;
        }
        writeln!(file, "{callback_label}:")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        writeln!(file, "    movq %r12, %rdi")?;
        writeln!(file, "    call *%r14")?;
        writeln!(file, "{done_label}:")?;
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            let packed_done = format!(".L_gpu_replay_after_done_{pc:x}");
            writeln!(
                file,
                "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
            )?;
            writeln!(file, "    jne {packed_done}")?;
            emit_after_step(&mut file)?;
            writeln!(file, "{packed_done}:")?;
        } else {
            emit_after_step(&mut file)?;
        }
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
        false,
        PreflightAccessMode::Exact,
        true,
        None,
        AssemblyTraceStyle::PreflightScalar,
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
    writeln!(file, "    je 2f")?;
    writeln!(
        file,
        "    cmpl ${AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jne 1f")?;
    writeln!(file, "2:")?;
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
    writeln!(file, "    je ceno_aot_error")?;
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

/// L7 reserves every packed-AoS family used by a native block atomically.
/// Phase one is read-only: every state, layout, pointer, and final cursor is
/// checked. Phase two publishes all final cursors. Per-instruction emission
/// subsequently addresses `final_cursor - family_count + static_rank`.
fn emit_l7_block_family_admission(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    let mut counts = [0u32; InsnKind::COUNT];
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let kind = instruction_at(program, pc)?.kind;
        if crate::gpu_typed_kind_spec(kind).is_none() {
            bail!("L7 native block contains unsupported kind {kind:?}");
        }
        counts[kind as usize] = counts[kind as usize]
            .checked_add(1)
            .ok_or_else(|| anyhow!("L7 block family count overflow"))?;
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }

    let error = format!(".L_l7_admission_error_{:08x}", block.start_pc);
    let done = format!(".L_l7_admission_done_{:08x}", block.start_pc);
    for (kind_index, count) in counts
        .into_iter()
        .enumerate()
        .filter(|(_, count)| *count != 0)
    {
        let kind = InsnKind::iter()
            .nth(kind_index)
            .expect("InsnKind indices must be dense");
        let layout = crate::gpu_typed_kind_spec(kind)
            .expect("counted L7 family must have a compact layout")
            .layout as u32;
        writeln!(
            file,
            "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10\n    testq %r10, %r10\n    je {error}"
        )?;
        writeln!(
            file,
            "    cmpq ${}, {AOT_CTX_GPU_REPLAY_KIND_COUNT_OFFSET}(%r12)",
            kind_index + 1
        )?;
        writeln!(file, "    jb {error}")?;
        writeln!(
            file,
            "    addq ${}, %r10",
            kind_index * std::mem::size_of::<crate::gpu_typed_ingress::GpuTypedNativeKindState>()
        )?;
        writeln!(
            file,
            "    cmpl ${}, 116(%r10)",
            crate::gpu_typed_ingress::GPU_COMPACT_NATIVE_SENTINEL
        )?;
        writeln!(file, "    jne {error}")?;
        writeln!(file, "    cmpl ${layout}, 112(%r10)")?;
        writeln!(file, "    jne {error}")?;
        writeln!(file, "    cmpq $0, 0(%r10)")?;
        writeln!(file, "    je {error}")?;
        writeln!(file, "    movl 108(%r10), %eax")?;
        writeln!(file, "    addl ${count}, %eax")?;
        writeln!(file, "    jc {error}")?;
        writeln!(file, "    cmpl 104(%r10), %eax")?;
        writeln!(file, "    ja {error}")?;
    }
    for (kind_index, count) in counts
        .into_iter()
        .enumerate()
        .filter(|(_, count)| *count != 0)
    {
        writeln!(
            file,
            "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
        )?;
        writeln!(
            file,
            "    addq ${}, %r10",
            kind_index * std::mem::size_of::<crate::gpu_typed_ingress::GpuTypedNativeKindState>()
        )?;
        writeln!(file, "    addl ${count}, 108(%r10)")?;
    }
    writeln!(file, "    jmp {done}")?;
    writeln!(file, "{error}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_ERROR_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    testq %rax, %rax")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "    movl $10, (%rax)")?;
    writeln!(file, "    jmp ceno_aot_error")?;
    writeln!(file, "{done}:")?;
    Ok(())
}

/// Enter the production packed lane only when the current replay owner exposes
/// packed family storage. The explicit field-SoA oracle keeps the original
/// per-step path. Packed admission is fail-closed and publishes family cursors
/// only after every capacity/layout/pointer check succeeds.
fn emit_gpu_replay_packed_block_admission(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    let first_kind = instruction_at(program, block.start_pc)?.kind;
    let state_offset = first_kind as usize
        * std::mem::size_of::<crate::gpu_typed_ingress::GpuTypedNativeKindState>();
    let generic = format!(".L_gpu_replay_generic_block_{:08x}", block.start_pc);
    let packed = format!(".L_gpu_replay_packed_block_{:08x}", block.start_pc);
    writeln!(
        file,
        "    movl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    cmpl ${AOT_TRACE_MODE_GPU_REPLAY_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jne {generic}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    testq %r10, %r10")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(
        file,
        "    cmpq ${}, {AOT_CTX_GPU_REPLAY_KIND_COUNT_OFFSET}(%r12)",
        first_kind as usize + 1
    )?;
    writeln!(file, "    jb ceno_aot_error")?;
    writeln!(file, "    addq ${state_offset}, %r10")?;
    writeln!(
        file,
        "    cmpl ${}, 116(%r10)",
        crate::gpu_typed_ingress::GPU_TYPED_NATIVE_SENTINEL
    )?;
    writeln!(file, "    je {generic}")?;
    writeln!(
        file,
        "    cmpl ${}, 116(%r10)",
        crate::gpu_typed_ingress::GPU_COMPACT_NATIVE_SENTINEL
    )?;
    writeln!(file, "    jne ceno_aot_error")?;
    emit_pure_block_budget_guard(&mut file, block)?;
    emit_l7_block_family_admission(&mut file, program, block)?;
    writeln!(
        file,
        "    addq ${}, 0(%rsp)",
        block_instruction_count(block)
    )?;
    writeln!(
        file,
        "    movl $1, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jmp {packed}")?;
    writeln!(file, "{generic}:")?;
    writeln!(file, "{packed}:")?;
    Ok(())
}

fn l7_block_family_rank(
    program: &Program,
    block_start_pc: u32,
    block_end_pc: u32,
    current_pc: u32,
    kind: InsnKind,
) -> Result<(u32, u32)> {
    let mut count = 0u32;
    let mut rank = None;
    let mut pc = block_start_pc;
    while pc < block_end_pc {
        let instruction = instruction_at(program, pc)?;
        if instruction.kind == kind {
            if pc == current_pc {
                rank = Some(count);
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| anyhow!("L7 static family rank overflow"))?;
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok((
        count,
        rank.ok_or_else(|| anyhow!("L7 current instruction has no static family rank"))?,
    ))
}

#[derive(Clone)]
struct GpuPackedStaticField {
    load_eax: String,
    width: usize,
}

fn emit_gpu_replay_static_pack_stores(
    mut file: impl Write,
    fields: &[GpuPackedStaticField],
    byte_len: usize,
) -> Result<()> {
    let total_bits = fields.iter().map(|field| field.width).sum::<usize>();
    if total_bits.div_ceil(8) != byte_len {
        bail!("packed static field width does not match row size");
    }
    let mut field_start = 0usize;
    let ranges = fields
        .iter()
        .map(|field| {
            let range = field_start..field_start + field.width;
            field_start += field.width;
            (field, range)
        })
        .collect::<Vec<_>>();
    let mut chunk_start = 0usize;
    while chunk_start < total_bits {
        let chunk_bits = (total_bits - chunk_start).min(64);
        writeln!(file, "    xorl %r8d, %r8d")?;
        for (field, range) in &ranges {
            let overlap_start = range.start.max(chunk_start);
            let overlap_end = range.end.min(chunk_start + chunk_bits);
            if overlap_start >= overlap_end {
                continue;
            }
            writeln!(file, "    {}", field.load_eax)?;
            let source_shift = overlap_start - range.start;
            let contribution_bits = overlap_end - overlap_start;
            if source_shift != 0 {
                writeln!(file, "    shrl ${source_shift}, %eax")?;
            }
            if contribution_bits < 32 {
                writeln!(
                    file,
                    "    andl ${:#x}, %eax",
                    (1u64 << contribution_bits) - 1
                )?;
            }
            writeln!(file, "    movl %eax, %r11d")?;
            let destination_shift = overlap_start - chunk_start;
            if destination_shift != 0 {
                writeln!(file, "    shlq ${destination_shift}, %r11")?;
            }
            writeln!(file, "    orq %r11, %r8")?;
        }
        let byte_offset = chunk_start / 8;
        match chunk_bits.div_ceil(8) {
            8 => writeln!(file, "    movq %r8, {byte_offset}(%r9)")?,
            4 => writeln!(file, "    movl %r8d, {byte_offset}(%r9)")?,
            tail => {
                // The only partial final chunk is the exact seven-byte tail of
                // a 31-byte row. Keep it inside the row: no padded qword may
                // initialize or overlap the following record.
                if tail != 7 {
                    bail!("unsupported packed static tail of {tail} bytes");
                }
                writeln!(file, "    movl %r8d, {byte_offset}(%r9)")?;
                writeln!(file, "    shrq $32, %r8")?;
                writeln!(file, "    movw %r8w, {}(%r9)", byte_offset + 4)?;
                writeln!(file, "    shrq $16, %r8")?;
                writeln!(file, "    movb %r8b, {}(%r9)", byte_offset + 6)?;
            }
        }
        chunk_start += chunk_bits;
    }
    Ok(())
}

fn emit_gpu_replay_packed_static_row(
    mut file: impl Write,
    program: &Program,
    pc: u32,
    insn: Instruction,
    reserved: ReservedBlockStep,
) -> Result<()> {
    use crate::gpu_typed_ingress::GpuTypedLayout;

    let spec = crate::gpu_typed_kind_spec(insn.kind)
        .ok_or_else(|| anyhow!("packed static row has unsupported kind {:?}", insn.kind))?;
    let (family_count, static_rank) = l7_block_family_rank(
        program,
        reserved.block_start_pc,
        reserved.block_end_pc,
        pc,
        insn.kind,
    )?;
    let stride = spec.layout.compact_bytes();
    let state_offset = insn.kind as usize
        * std::mem::size_of::<crate::gpu_typed_ingress::GpuTypedNativeKindState>();
    let error = format!(".L_gpu_replay_static_error_{pc:08x}");
    let pc_base_ready = format!(".L_gpu_replay_static_pc_base_{pc:08x}");
    let events_done = format!(".L_gpu_replay_static_events_done_{pc:08x}");
    let event_loop = format!(".L_gpu_replay_static_event_loop_{pc:08x}");
    let event_match = format!(".L_gpu_replay_static_event_match_{pc:08x}");

    // Family cursor was transactionally advanced at block entry. Address this
    // static PC's unpublished row without reading or modifying the cursor.
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    addq ${state_offset}, %r10")?;
    writeln!(file, "    movl 108(%r10), %eax")?;
    writeln!(file, "    subl ${}, %eax", family_count - static_rank)?;
    writeln!(file, "    imulq ${stride}, %rax, %rax")?;
    writeln!(file, "    addq 0(%r10), %rax")?;
    writeln!(file, "    movq %rax, 40(%rsp)")?;

    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    movl (%r8), %eax")?;
    writeln!(file, "    subl 120(%r10), %eax")?;
    writeln!(file, "    cmpl $262144, %eax")?;
    writeln!(file, "    movl $6, %edx")?;
    writeln!(file, "    jae {error}")?;
    writeln!(file, "    movl %eax, 36(%rsp)")?;

    writeln!(file, "    cmpl $0, 124(%r10)")?;
    writeln!(file, "    jne {pc_base_ready}")?;
    writeln!(file, "    movl ${:#010x}, %eax", pc & !((1 << 22) - 1))?;
    writeln!(file, "    movl %eax, 124(%r10)")?;
    writeln!(file, "{pc_base_ready}:")?;
    writeln!(file, "    movl ${pc:#010x}, %eax")?;
    writeln!(file, "    subl 124(%r10), %eax")?;
    writeln!(file, "    testl $3, %eax")?;
    writeln!(file, "    movl $7, %edx")?;
    writeln!(file, "    jne {error}")?;
    writeln!(file, "    cmpl $0x400000, %eax")?;
    writeln!(file, "    jae {error}")?;
    writeln!(file, "    shrl $2, %eax")?;
    writeln!(file, "    movl %eax, 32(%rsp)")?;

    for offset in [
        AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
        AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
        AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
    ] {
        writeln!(file, "    movq {offset}(%r12), %rax")?;
        writeln!(file, "    cmpq $0x8000000, %rax")?;
        writeln!(file, "    movl $8, %edx")?;
        writeln!(file, "    jae {error}")?;
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        writeln!(
            file,
            "    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    leaq 3(,%rax,4), %rcx")?;
        writeln!(file, "    testq %rax, %rax")?;
        writeln!(file, "    cmovzq %rax, %rcx")?;
        writeln!(file, "    cmpq $0x8000000, %rcx")?;
        writeln!(file, "    movl $8, %edx")?;
        writeln!(file, "    jae {error}")?;
        writeln!(file, "    movl %ecx, 28(%rsp)")?;
    }

    // Consume precisely the current row's future-access events before any
    // destination store. Static register addresses and the dynamic memory
    // address are validated in transcript order.
    writeln!(file, "    movl $0, 24(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    movq (%r8), %rax")?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    movq (%r8), %rsi")?;
    writeln!(file, "{event_loop}:")?;
    writeln!(
        file,
        "    cmpq {AOT_CTX_GPU_REPLAY_EVENTS_LEN_OFFSET}(%r12), %rsi"
    )?;
    writeln!(file, "    jae {events_done}")?;
    writeln!(file, "    leaq (%rsi,%rsi,2), %r9")?;
    writeln!(file, "    shlq $3, %r9")?;
    writeln!(
        file,
        "    addq {AOT_CTX_GPU_REPLAY_EVENTS_OFFSET}(%r12), %r9"
    )?;
    writeln!(file, "    movq 0(%r9), %r11")?;
    writeln!(file, "    cmpq %rax, %r11")?;
    writeln!(file, "    movl $5, %edx")?;
    writeln!(file, "    jb {error}")?;
    writeln!(file, "    leaq 4(%rax), %rcx")?;
    writeln!(file, "    cmpq %rcx, %r11")?;
    writeln!(file, "    jae {events_done}")?;
    writeln!(file, "    subq %rax, %r11")?;
    writeln!(file, "    movl 16(%r9), %ecx")?;
    let accesses = [
        (
            native_step_reads_rs1(insn.kind),
            0u32,
            (insn.rs1 as u32) << 6,
        ),
        (
            native_step_reads_rs2(insn.kind),
            1u32,
            (insn.rs2 as u32) << 6,
        ),
        (
            native_step_writes_rd(insn.kind),
            2u32,
            insn.rd_internal() << 6,
        ),
    ];
    for (enabled, subcycle, address) in accesses {
        if enabled {
            let next = format!(".L_gpu_replay_static_event_next_{pc:08x}_{subcycle}");
            writeln!(file, "    cmpl ${subcycle}, %r11d")?;
            writeln!(file, "    jne {next}")?;
            writeln!(file, "    cmpl ${address}, %ecx")?;
            writeln!(file, "    jne {error}")?;
            writeln!(file, "    jmp {event_match}")?;
            writeln!(file, "{next}:")?;
        }
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        writeln!(file, "    cmpl $3, %r11d")?;
        writeln!(file, "    jne {error}")?;
        writeln!(file, "    cmpl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %ecx")?;
        writeln!(file, "    jne {error}")?;
    } else {
        writeln!(file, "    jmp {error}")?;
    }
    writeln!(file, "{event_match}:")?;
    writeln!(file, "    btsl %r11d, 24(%rsp)")?;
    writeln!(file, "    incl %esi")?;
    writeln!(file, "    jmp {event_loop}")?;
    writeln!(file, "{events_done}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    movq %rsi, (%r8)")?;
    writeln!(file, "    cmpl $16, 24(%rsp)")?;
    writeln!(file, "    movl $9, %edx")?;
    writeln!(file, "    jae {error}")?;

    let source = |text: String, width| GpuPackedStaticField {
        load_eax: text,
        width,
    };
    let mut fields = vec![
        source("movl 36(%rsp), %eax".into(), 18),
        source("movl 32(%rsp), %eax".into(), 20),
        source(format!("movl ${:#x}, %eax", insn.raw >> 7), 25),
    ];
    let access = |previous_offset: usize, value_offset: usize| {
        [
            source(format!("movl {previous_offset}(%r12), %eax"), 27),
            source(format!("movl {value_offset}(%r12), %eax"), 32),
        ]
    };
    match spec.layout {
        GpuTypedLayout::R => {
            fields.extend(access(
                AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS1_VALUE_OFFSET,
            ));
            fields.extend(access(
                AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS2_VALUE_OFFSET,
            ));
            fields.extend(access(
                AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RD_BEFORE_OFFSET,
            ));
        }
        GpuTypedLayout::I | GpuTypedLayout::Jalr => {
            fields.extend(access(
                AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS1_VALUE_OFFSET,
            ));
            fields.extend(access(
                AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RD_BEFORE_OFFSET,
            ));
        }
        GpuTypedLayout::Branch => {
            fields.extend(access(
                AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS1_VALUE_OFFSET,
            ));
            fields.extend(access(
                AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS2_VALUE_OFFSET,
            ));
        }
        GpuTypedLayout::Jal => fields.extend(access(
            AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
            AOT_CTX_TRACE_RD_BEFORE_OFFSET,
        )),
        GpuTypedLayout::Load => {
            fields.extend(access(
                AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS1_VALUE_OFFSET,
            ));
            fields.extend(access(
                AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RD_BEFORE_OFFSET,
            ));
            fields.push(source("movl 28(%rsp), %eax".into(), 27));
            fields.push(source(
                format!("movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %eax"),
                32,
            ));
        }
        GpuTypedLayout::Store => {
            fields.extend(access(
                AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS1_VALUE_OFFSET,
            ));
            fields.extend(access(
                AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RS2_VALUE_OFFSET,
            ));
            fields.push(source("movl 28(%rsp), %eax".into(), 27));
            fields.push(source(
                format!("movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %eax"),
                32,
            ));
        }
        GpuTypedLayout::U => {
            fields.push(source(
                format!("movl {AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET}(%r12), %eax"),
                27,
            ));
            fields.extend(access(
                AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
                AOT_CTX_TRACE_RD_BEFORE_OFFSET,
            ));
        }
    }
    fields.push(source("movl 24(%rsp), %eax".into(), 4));
    writeln!(file, "    movq 40(%rsp), %r9")?;
    emit_gpu_replay_static_pack_stores(&mut file, &fields, stride)?;

    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    incq (%r8)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    addq $4, (%r8)")?;
    let done = format!(".L_gpu_replay_static_done_{pc:08x}");
    writeln!(file, "    jmp {done}")?;
    writeln!(file, "{error}:")?;
    writeln!(file, "    orl ${:#x}, %edx", (insn.kind as u32) << 8)?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_ERROR_OFFSET}(%r12), %r8"
    )?;
    writeln!(file, "    testq %r8, %r8")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "    movl %edx, (%r8)")?;
    writeln!(file, "    jmp ceno_aot_error")?;
    writeln!(file, "{done}:")?;
    Ok(())
}

#[derive(Clone, Copy)]
struct ReservedBlockStep {
    block_start_pc: u32,
    block_end_pc: u32,
    remaining_after: u64,
    cycle_offset: u64,
    memory_guard_hoisted: bool,
    memory_region_index: Option<usize>,
    registers_resident: bool,
    memory_cells_resident: bool,
    memory_ordinal_resident: bool,
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

#[derive(Clone, Copy)]
struct PreflightMemoryGuardAccess {
    pc: u32,
    insn: Instruction,
    region_index: usize,
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

fn layered_register_predecessors(
    program: &Program,
    block_start_pc: u32,
    current_pc: u32,
) -> Result<Vec<(u32, PreflightSubcycle, Option<Cycle>)>> {
    let mut latest = BTreeMap::<u32, Cycle>::new();
    let mut current = Vec::new();
    let mut pc = block_start_pc;
    while pc <= current_pc {
        let insn = instruction_at(program, pc)?;
        for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
            let previous =
                latest.insert(reg_idx, u64::from(pc - block_start_pc) + subcycle.value());
            if pc == current_pc {
                current.push((reg_idx, subcycle, previous));
            }
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(current)
}

fn emit_layered_register_predecessors(
    mut file: impl Write,
    program: &Program,
    pc: u32,
    reserved: ReservedBlockStep,
) -> Result<()> {
    for (reg_idx, subcycle, block_previous) in
        layered_register_predecessors(program, reserved.block_start_pc, pc)?
    {
        let destination = match subcycle {
            PreflightSubcycle::Rs1 => AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
            PreflightSubcycle::Rs2 => AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
            PreflightSubcycle::Rd => AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
        };
        if let Some(previous) = block_previous {
            writeln!(
                file,
                "    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %rax"
            )?;
            writeln!(file, "    movq (%rax), %rax")?;
            if previous >= reserved.cycle_offset {
                writeln!(file, "    addq ${}, %rax", previous - reserved.cycle_offset)?;
            } else {
                writeln!(file, "    subq ${}, %rax", reserved.cycle_offset - previous)?;
            }
        } else {
            writeln!(
                file,
                "    movq {AOT_CTX_FULLTRACER_LATEST_CELLS_OFFSET}(%r12), %rax"
            )?;
            writeln!(file, "    movq {}(%rax), %rax", reg_idx as usize * 8)?;
        }
        writeln!(file, "    movq %rax, {destination}(%r12)")?;
    }
    Ok(())
}

fn emit_gpu_replay_register_predecessors(
    mut file: impl Write,
    program: &Program,
    pc: u32,
    reserved: ReservedBlockStep,
) -> Result<()> {
    for (reg_idx, subcycle, block_previous) in
        layered_register_predecessors(program, reserved.block_start_pc, pc)?
    {
        let destination = match subcycle {
            PreflightSubcycle::Rs1 => AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET,
            PreflightSubcycle::Rs2 => AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET,
            PreflightSubcycle::Rd => AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET,
        };
        if let Some(previous) = block_previous {
            writeln!(
                file,
                "    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %rax"
            )?;
            writeln!(file, "    movq (%rax), %rax")?;
            if previous >= reserved.cycle_offset {
                writeln!(file, "    addq ${}, %rax", previous - reserved.cycle_offset)?;
            } else {
                writeln!(file, "    subq ${}, %rax", reserved.cycle_offset - previous)?;
            }
        } else {
            let address = reg_idx << 6;
            writeln!(
                file,
                "    movq {AOT_CTX_GPU_REPLAY_LATEST_CELLS_OFFSET}(%r12), %r8"
            )?;
            writeln!(file, "    movl ${address}, %eax")?;
            writeln!(
                file,
                "    subl {AOT_CTX_GPU_REPLAY_LATEST_BASE_OFFSET}(%r12), %eax"
            )?;
            writeln!(file, "    movq (%r8,%rax,8), %rax")?;
            let nonzero = format!(".L_gpu_replay_previous_nonzero_{pc:08x}_{destination}");
            writeln!(file, "    testq %rax, %rax")?;
            writeln!(file, "    jne {nonzero}")?;
            writeln!(
                file,
                "    movq {AOT_CTX_GPU_REPLAY_LATEST_LEN_OFFSET}(%r12), %r8"
            )?;
            writeln!(file, "    incq (%r8)")?;
            writeln!(file, "{nonzero}:")?;
        }
        writeln!(file, "    movq %rax, {destination}(%r12)")?;
    }
    Ok(())
}

fn emit_layered_register_block_commit(
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
        "    movq {AOT_CTX_FULLTRACER_LATEST_CELLS_OFFSET}(%r12), %rdx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r8")?;
    for access in accesses {
        let reg_idx = access.addr >> 6;
        let from_end = block_cycles - access.cycle_offset;
        writeln!(file, "    leaq -{from_end}(%r8), %rax")?;
        writeln!(file, "    movq %rax, {}(%rdx)", reg_idx as usize * 8)?;
    }
    Ok(())
}

fn emit_gpu_replay_register_block_commit(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    let done = format!(".L_gpu_replay_register_commit_done_{:08x}", block.start_pc);
    writeln!(
        file,
        "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
    )?;
    writeln!(file, "    je {done}")?;
    let accesses = preflight_block_last_accesses(program, block)?;
    if !accesses.is_empty() {
        let block_cycles = block_instruction_count(block) * PC_STEP_SIZE as u64;
        writeln!(
            file,
            "    movq {AOT_CTX_GPU_REPLAY_LATEST_CELLS_OFFSET}(%r12), %rdx"
        )?;
        writeln!(
            file,
            "    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    movq (%rax), %r8")?;
        for access in accesses {
            let address = access.addr;
            let from_end = block_cycles - access.cycle_offset;
            writeln!(file, "    movl ${address}, %eax")?;
            writeln!(
                file,
                "    subl {AOT_CTX_GPU_REPLAY_LATEST_BASE_OFFSET}(%r12), %eax"
            )?;
            writeln!(file, "    leaq -{from_end}(%r8), %rcx")?;
            writeln!(file, "    movq %rcx, (%rdx,%rax,8)")?;
        }
    }
    writeln!(file, "{done}:")?;
    Ok(())
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

fn build_aot_block_kind_histograms(
    program: &Program,
    blocks: &[BasicBlock],
) -> Result<Vec<AotBlockKindHistogram>> {
    blocks
        .iter()
        .map(|block| {
            let instruction_offset =
                usize::try_from((block.start_pc - program.base_address) / PC_STEP_SIZE as u32)?;
            let instruction_count = usize::try_from(block_instruction_count(block))?;
            let instructions = program
                .instructions
                .get(instruction_offset..instruction_offset + instruction_count)
                .ok_or_else(|| anyhow!("AOT block instruction range is out of bounds"))?;
            let mut counts = [0u32; InsnKind::COUNT];
            for instruction in instructions {
                counts[instruction.kind as usize] = counts[instruction.kind as usize]
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("AOT block kind histogram overflow"))?;
            }
            Ok(AotBlockKindHistogram {
                counts,
                instruction_offset: u32::try_from(instruction_offset)?,
                instruction_count: u32::try_from(instruction_count)?,
            })
        })
        .collect()
}

fn build_aot_block_cost_descriptors(
    program: &Program,
    blocks: &[BasicBlock],
    model: &ShardCostModel,
) -> Result<AotPlannerMetadata> {
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
    Ok(AotPlannerMetadata {
        descriptors,
        contributions,
    })
}

fn emit_preflight_direct_block_budget_guard(
    mut file: impl Write,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    addq ${block_steps}, %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    ja ceno_aot_exceptional")?;
    Ok(())
}

fn emit_pure_block_budget_guard(mut file: impl Write, block: &BasicBlock) -> Result<()> {
    let block_steps = block_instruction_count(block);
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    addq ${block_steps}, %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    // If the limit ends inside this block, execute one exact fallback step and
    // dispatch again. This preserves the existing instruction-limit contract.
    writeln!(file, "    ja ceno_aot_exceptional")?;
    Ok(())
}

fn emit_rollback_reserved_block_steps(
    mut file: impl Write,
    reserved_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if let Some(step) = reserved_step {
        writeln!(file, "    subq ${}, 0(%rsp)", step.remaining_after + 1)?;
    }
    Ok(())
}

fn emit_restore_reserved_block_steps(
    mut file: impl Write,
    reserved_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if let Some(step) = reserved_step.filter(|step| step.remaining_after != 0) {
        writeln!(file, "    addq ${}, 0(%rsp)", step.remaining_after)?;
    }
    Ok(())
}

fn emit_rollback_gpu_replay_packed_steps(
    mut file: impl Write,
    trace_style: AssemblyTraceStyle,
    reserved_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        if let Some(step) = reserved_step {
            let done = format!(
                ".L_gpu_replay_rollback_done_{:08x}_{}",
                step.block_start_pc, step.remaining_after
            );
            writeln!(
                file,
                "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
            )?;
            writeln!(file, "    je {done}")?;
            writeln!(file, "    subq ${}, 0(%rsp)", step.remaining_after + 1)?;
            writeln!(file, "{done}:")?;
        }
    }
    Ok(())
}

fn emit_restore_gpu_replay_packed_steps(
    mut file: impl Write,
    trace_style: AssemblyTraceStyle,
    reserved_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        if let Some(step) = reserved_step.filter(|step| step.remaining_after != 0) {
            let done = format!(
                ".L_gpu_replay_restore_done_{:08x}_{}",
                step.block_start_pc, step.remaining_after
            );
            writeln!(
                file,
                "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
            )?;
            writeln!(file, "    je {done}")?;
            writeln!(file, "    addq ${}, 0(%rsp)", step.remaining_after)?;
            writeln!(file, "{done}:")?;
        }
    }
    Ok(())
}

fn emit_gpu_replay_packed_family_rollback(
    mut file: impl Write,
    program: &Program,
    pc: u32,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    reserved_step: Option<ReservedBlockStep>,
) -> Result<Option<(usize, u32)>> {
    if trace_style != AssemblyTraceStyle::GpuReplayDirect {
        return Ok(None);
    }
    let reserved = reserved_step.expect("packed family rollback requires admitted block metadata");
    let (family_count, static_rank) = l7_block_family_rank(
        program,
        reserved.block_start_pc,
        reserved.block_end_pc,
        pc,
        insn.kind,
    )?;
    let state_offset = insn.kind as usize
        * std::mem::size_of::<crate::gpu_typed_ingress::GpuTypedNativeKindState>();
    let skip = format!(".L_gpu_replay_family_rollback_skip_{pc:08x}");
    writeln!(
        file,
        "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
    )?;
    writeln!(file, "    je {skip}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    addq ${state_offset}, %r10")?;
    writeln!(file, "    subl ${}, 108(%r10)", family_count - static_rank)?;
    writeln!(file, "{skip}:")?;
    Ok(Some((state_offset, family_count - static_rank - 1)))
}

fn emit_gpu_replay_packed_family_restore(
    mut file: impl Write,
    pc: u32,
    restore: Option<(usize, u32)>,
) -> Result<()> {
    if let Some((state_offset, remaining)) = restore.filter(|(_, remaining)| *remaining != 0) {
        let skip = format!(".L_gpu_replay_family_restore_skip_{pc:08x}");
        writeln!(
            file,
            "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
        )?;
        writeln!(file, "    je {skip}")?;
        writeln!(
            file,
            "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
        )?;
        writeln!(file, "    addq ${state_offset}, %r10")?;
        writeln!(file, "    addl ${remaining}, 108(%r10)")?;
        writeln!(file, "{skip}:")?;
    }
    Ok(())
}

fn emit_pure_block_memory_fast_path_guard(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        if native_opcode_family(insn.kind) == Some(NativeOpcodeFamily::Memory) {
            writeln!(file, "    movl {}(%r13), %eax", insn.rs1 as usize * 4)?;
            writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
            match insn.kind {
                InsnKind::LH | InsnKind::LHU | InsnKind::SH => {
                    writeln!(file, "    testl $1, %edx")?;
                    writeln!(file, "    jne ceno_aot_memory_guard")?;
                }
                InsnKind::LW | InsnKind::SW => {
                    writeln!(file, "    testl $3, %edx")?;
                    writeln!(file, "    jne ceno_aot_memory_guard")?;
                }
                _ => {}
            }
            writeln!(file, "    subl %r14d, %edx")?;
            writeln!(file, "    cmpl 64(%rsp), %edx")?;
            writeln!(file, "    jae ceno_aot_memory_guard")?;
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
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

fn preflight_block_memory_access_count(program: &Program, block: &BasicBlock) -> Result<usize> {
    let mut count = 0usize;
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        count += usize::from(
            native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
        );
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(count)
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
    writeln!(file, "    je ceno_aot_error")?;
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
    record_regions: bool,
) -> Result<()> {
    writeln!(file, "    movq %r13, %r10")?;
    if record_regions {
        writeln!(file, "    xorq %r11, %r11")?;
    }
    let mut accesses = Vec::new();
    let mut pc = block.start_pc;
    let mut memory_access_index = 0usize;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        if matches!(
            native_opcode_family(insn.kind),
            Some(NativeOpcodeFamily::Memory)
        ) {
            accesses.push(PreflightMemoryGuardAccess {
                pc,
                insn,
                region_index: memory_access_index,
            });
            memory_access_index += 1;
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }

    let mut word_groups = BTreeMap::<(u8, u32), Vec<PreflightMemoryGuardAccess>>::new();
    for access in &accesses {
        if matches!(access.insn.kind, InsnKind::LW | InsnKind::SW) {
            word_groups
                .entry((access.insn.rs1, access.insn.imm as u32 & 3))
                .or_default()
                .push(*access);
        }
    }
    let grouped_indices = word_groups
        .values()
        .filter(|group| group.len() >= 2)
        .flat_map(|group| group.iter().map(|access| access.region_index))
        .collect::<BTreeSet<_>>();
    for (group_index, group) in word_groups
        .values()
        .filter(|group| group.len() >= 2)
        .enumerate()
    {
        emit_preflight_direct_memory_fast_path_group_guard(
            &mut file,
            block.start_pc,
            group_index,
            group,
            record_regions,
        )?;
    }
    for access in accesses {
        if grouped_indices.contains(&access.region_index) {
            continue;
        }
        emit_preflight_direct_memory_fast_path_guard(
            &mut file,
            access.pc,
            access.insn,
            record_regions.then_some(access.region_index),
        )?;
    }
    if record_regions {
        writeln!(file, "    movq %r11, 64(%rsp)")?;
    }
    Ok(())
}

fn emit_preflight_direct_memory_fast_path_group_guard(
    mut file: impl Write,
    block_pc: u32,
    group_index: usize,
    accesses: &[PreflightMemoryGuardAccess],
    record_regions: bool,
) -> Result<()> {
    debug_assert!(accesses.len() >= 2);
    debug_assert!(
        accesses
            .iter()
            .all(|access| matches!(access.insn.kind, InsnKind::LW | InsnKind::SW))
    );
    let rs1 = accesses[0].insn.rs1;
    debug_assert!(accesses.iter().all(|access| access.insn.rs1 == rs1));
    let min_imm = accesses.iter().map(|access| access.insn.imm).min().unwrap();
    let max_imm = accesses.iter().map(|access| access.insn.imm).max().unwrap();
    let heap_ok_label = format!(".L_block_memory_group_heap_ok_{block_pc:x}_{group_index}");
    let stack_ok_label = format!(".L_block_memory_group_stack_ok_{block_pc:x}_{group_index}");
    let hints_ok_label = format!(".L_block_memory_group_hints_ok_{block_pc:x}_{group_index}");
    let done_label = format!(".L_block_memory_group_done_{block_pc:x}_{group_index}");

    writeln!(file, "    movl {}(%r10), %eax", rs1 as usize * 4)?;
    writeln!(file, "    leal {min_imm}(%rax), %edx")?;
    writeln!(file, "    testl $3, %edx")?;
    writeln!(file, "    jne ceno_aot_memory_guard")?;
    writeln!(file, "    leal {max_imm}(%rax), %ecx")?;
    // If the affine interval wraps the 32-bit guest address space, use the
    // scalar guard for the whole block.
    writeln!(file, "    cmpl %edx, %ecx")?;
    writeln!(file, "    jb ceno_aot_memory_guard")?;
    for (start_offset, end_offset, label) in [
        (
            AOT_CTX_HEAP_START_OFFSET,
            AOT_CTX_HEAP_END_OFFSET,
            &heap_ok_label,
        ),
        (
            AOT_CTX_STACK_START_OFFSET,
            AOT_CTX_STACK_END_OFFSET,
            &stack_ok_label,
        ),
        (
            AOT_CTX_HINTS_START_OFFSET,
            AOT_CTX_HINTS_END_OFFSET,
            &hints_ok_label,
        ),
    ] {
        writeln!(file, "    cmpl {start_offset}(%r12), %edx")?;
        writeln!(file, "    jb 1f")?;
        writeln!(file, "    cmpl {end_offset}(%r12), %ecx")?;
        writeln!(file, "    jb {label}")?;
        writeln!(file, "1:")?;
    }
    writeln!(file, "    shrl $2, %edx")?;
    writeln!(file, "    shrl $2, %ecx")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %edx"
    )?;
    writeln!(file, "    jb ceno_aot_memory_guard")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %ecx"
    )?;
    writeln!(file, "    jb {done_label}")?;
    writeln!(file, "    jmp ceno_aot_memory_guard")?;

    for (label, region) in [
        (&heap_ok_label, 1u64),
        (&stack_ok_label, 2u64),
        (&hints_ok_label, 3u64),
    ] {
        writeln!(file, "{label}:")?;
        if record_regions {
            let mask = accesses.iter().fold(0u64, |mask, access| {
                mask | (region << (access.region_index * 2))
            });
            writeln!(file, "    movabsq ${mask:#018x}, %rdi")?;
            writeln!(file, "    orq %rdi, %r11")?;
        }
        writeln!(file, "    jmp {done_label}")?;
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_memory_fast_path_guard(
    mut file: impl Write,
    pc: u32,
    insn: Instruction,
    region_index: Option<usize>,
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
            writeln!(file, "    jne ceno_aot_memory_guard")?;
        }
        InsnKind::LW | InsnKind::SW => {
            writeln!(file, "    testl $3, %edx")?;
            writeln!(file, "    jne ceno_aot_memory_guard")?;
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
    writeln!(file, "    jb ceno_aot_memory_guard")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    jb {done_label}")?;
    writeln!(file, "    jmp ceno_aot_memory_guard")?;
    for (label, region) in [
        (&heap_ok_label, 1u8),
        (&stack_ok_label, 2u8),
        (&hints_ok_label, 3u8),
    ] {
        writeln!(file, "{label}:")?;
        if let Some(index) = region_index {
            let bit = index * 2;
            if region & 1 != 0 {
                writeln!(file, "    btsq ${bit}, %r11")?;
            }
            if region & 2 != 0 {
                writeln!(file, "    btsq ${}, %r11", bit + 1)?;
            }
        }
        writeln!(file, "    jmp {done_label}")?;
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_block_access_entry(
    mut file: impl Write,
    program: &Program,
    block_idx: usize,
    block: &BasicBlock,
    emit_events: bool,
) -> Result<()> {
    let accesses = preflight_block_first_accesses(program, block)?;
    if accesses.is_empty() {
        return Ok(());
    }
    let register_mask = accesses.iter().fold(0u64, |mask, access| {
        mask | preflight_register_bit(access.addr >> 6)
    });
    if !emit_events {
        let all_seen_label = format!(".L_preflight_block_latest_all_seen_{block_idx}");
        writeln!(file, "    movq 56(%rsp), %rax")?;
        writeln!(file, "    movl ${}, %ecx", register_mask as u32)?;
        writeln!(file, "    andl %ecx, %eax")?;
        writeln!(file, "    cmpl %ecx, %eax")?;
        writeln!(file, "    je {all_seen_label}")?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
        )?;
        writeln!(file, "    xorq %rdi, %rdi")?;
        for (access_idx, access) in accesses.iter().enumerate() {
            let done_label = format!(".L_preflight_block_latest_seen_{block_idx}_{access_idx}");
            let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
            writeln!(file, "    cmpq $0, {offset}(%rdx)")?;
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
                writeln!(file, "    je ceno_aot_error")?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
                )?;
                writeln!(file, "    xorq %rdi, %rdi")?;
            } else {
                writeln!(file, "    incq %rdi")?;
            }
            writeln!(file, "{done_label}:")?;
        }
        if !cfg!(debug_assertions) {
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET}(%r12), %rsi"
            )?;
            writeln!(file, "    addq %rdi, (%rsi)")?;
        }
        writeln!(file, "    movl ${}, %eax", register_mask as u32)?;
        writeln!(file, "    orq %rax, 56(%rsp)")?;
        writeln!(file, "{all_seen_label}:")?;
        return Ok(());
    }
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
        let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{block_idx}_register_first_check_{access_idx}"),
        )?;
        writeln!(file, "    movq {offset}(%rdx), %r11")?;
        // Zero is the uninitialized sentinel, and every shard starts after cycle zero,
        // so the unsigned shard-start comparison also covers first touches.
        writeln!(file, "    cmpq %r10, %r11")?;
        writeln!(file, "    jae {done_label}")?;
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{block_idx}_register_tape_append_{access_idx}"),
        )?;
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
            writeln!(file, "    je ceno_aot_error")?;
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

fn emit_preflight_specialized_cost_contribution(
    mut file: impl Write,
    block_idx: usize,
    contribution_idx: usize,
    contribution: &AotChipContribution,
    has_lzcnt: bool,
    has_bucket_cache: bool,
) -> Result<()> {
    let done_label = format!(".L_preflight_cost_contribution_done_{block_idx}_{contribution_idx}");
    writeln!(file, "    movl ${}, %eax", contribution.chip_index)?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdi"
    )?;
    writeln!(file, "    leaq (%rdi,%rax,8), %rsi")?;
    writeln!(file, "    movq (%rsi), %r9")?;
    writeln!(file, "    movq %r9, %r11")?;
    writeln!(file, "    addq ${}, %r11", contribution.instance_delta)?;
    writeln!(file, "    movq %r11, (%rsi)")?;
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
        if has_bucket_cache {
            writeln!(file, "    leaq -1(%r9), %r8")?;
            writeln!(file, "    movq $1, %rdi")?;
            writeln!(file, "    shlxq %r8, %rdi, %r8")?;
            writeln!(file, "    incq %r8")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %rdi"
            )?;
            writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rdi"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
            )?;
            writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
        }
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
    writeln!(file, "    cmpq %r9, %rdx")?;
    writeln!(file, "    je {done_label}")?;
    writeln!(file, "    movq $1, 80(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET}(%r12), %rdi"
    )?;
    writeln!(
        file,
        "    addq ${}, %rdi",
        contribution.cost_row_byte_offset
    )?;
    writeln!(file, "    movq %rdx, %r8")?;
    writeln!(file, "    shlq $4, %r8")?;
    writeln!(file, "    movq %r9, %rax")?;
    writeln!(file, "    shlq $4, %rax")?;
    writeln!(file, "    movdqu (%rdi,%r8), %xmm1")?;
    writeln!(file, "    movdqu (%rdi,%rax), %xmm2")?;
    writeln!(file, "    psubq %xmm1, %xmm2")?;
    writeln!(file, "    paddq %xmm2, %xmm0")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_TOWER_COST_TABLE_OFFSET}(%r12), %rdi"
    )?;
    writeln!(
        file,
        "    addq ${}, %rdi",
        contribution.cost_row_byte_offset / 2
    )?;
    writeln!(file, "    movq (%rdi,%r9,8), %rax")?;
    writeln!(file, "    movq 32(%rsp), %r8")?;
    writeln!(file, "    cmpq %r8, %rax")?;
    writeln!(file, "    cmovaq %rax, %r8")?;
    writeln!(file, "    movq %r8, 32(%rsp)")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_adaptive_block_plan_entry(
    mut file: impl Write,
    block_idx: usize,
    block: &BasicBlock,
    planner_metadata: Option<&AotPlannerMetadata>,
) -> Result<()> {
    let specialized_descriptor = planner_metadata
        .map(|metadata| {
            let descriptor = &metadata.descriptors[block_idx];
            (descriptor, metadata.contributions_for(descriptor))
        })
        .filter(|(_, contributions)| contributions.len() <= 2);
    let loop_label = format!(".L_preflight_cost_loop_{block_idx}");
    let loop_done_label = format!(".L_preflight_cost_loop_done_{block_idx}");
    let contribution_done_label = format!(".L_preflight_cost_contribution_done_{block_idx}");
    let unchanged_label = format!(".L_preflight_cost_unchanged_{block_idx}");
    let accept_label = format!(".L_preflight_cost_accept_{block_idx}");
    let first_shard_label = format!(".L_preflight_cost_first_shard_{block_idx}");
    let target_done_label = format!(".L_preflight_cost_target_done_{block_idx}");
    let split_label = format!(".L_preflight_cost_split_{block_idx}");
    let done_label = format!(".L_preflight_cost_done_{block_idx}");
    let bucket_scan_label = format!(".L_preflight_bucket_scan_{block_idx}");
    let bucket_scan_done_label = format!(".L_preflight_bucket_scan_done_{block_idx}");
    let bucket_fast_label = format!(".L_preflight_bucket_fast_{block_idx}");
    let bucket_slow_label = format!(".L_preflight_bucket_slow_{block_idx}");
    let bucket_rollback_label = format!(".L_preflight_bucket_rollback_{block_idx}");
    let block_cycles = block_instruction_count(block) * PC_STEP_SIZE as u64;
    let descriptor_offset = block_idx * std::mem::size_of::<AotBlockCostDescriptor>();
    let has_lzcnt = std::is_x86_feature_detected!("lzcnt");
    let has_bucket_cache = has_lzcnt && std::is_x86_feature_detected!("bmi2");

    if has_bucket_cache {
        if let Some((_, contributions)) = specialized_descriptor {
            // The common one/two-chip case embeds immutable descriptor fields
            // directly in the artifact and has no descriptor-table scan.
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rsi"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdx"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %r11"
            )?;
            for (index, contribution) in contributions.iter().enumerate() {
                let fail_label = format!(".L_preflight_bucket_special_fail_{block_idx}_{index}");
                writeln!(file, "    movl ${}, %eax", contribution.chip_index)?;
                writeln!(file, "    cmpq %r8, (%rsi,%rax,8)")?;
                writeln!(file, "    jne {fail_label}")?;
                writeln!(file, "    movq (%rdx,%rax,8), %r9")?;
                writeln!(file, "    addq ${}, %r9", contribution.instance_delta)?;
                writeln!(file, "    cmpq (%r11,%rax,8), %r9")?;
                writeln!(file, "    jae {fail_label}")?;
                writeln!(file, "    movq %r9, (%rdx,%rax,8)")?;
            }
            writeln!(file, "    jmp {unchanged_label}")?;
            for (index, _) in contributions.iter().enumerate() {
                let fail_label = format!(".L_preflight_bucket_special_fail_{block_idx}_{index}");
                writeln!(file, "{fail_label}:")?;
                for contribution in &contributions[..index] {
                    writeln!(file, "    movl ${}, %eax", contribution.chip_index)?;
                    writeln!(
                        file,
                        "    subq ${}, (%rdx,%rax,8)",
                        contribution.instance_delta
                    )?;
                }
                writeln!(file, "    jmp {bucket_slow_label}")?;
            }
            writeln!(file, "{bucket_slow_label}:")?;
        } else {
            // Most blocks do not cross a power-of-two cost bucket. Prove that
            // first, then update only instance counts. Rust callbacks advance a
            // generation so chips they may have changed retry the exact path.
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
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rsi"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdx"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %r11"
            )?;
            writeln!(file, "    testl %ecx, %ecx")?;
            writeln!(file, "    je {bucket_scan_done_label}")?;
            writeln!(file, "{bucket_scan_label}:")?;
            writeln!(file, "    movl (%r10), %eax")?;
            writeln!(file, "    cmpq %r8, (%rsi,%rax,8)")?;
            writeln!(file, "    jne {bucket_slow_label}")?;
            writeln!(file, "    movq (%rdx,%rax,8), %r9")?;
            writeln!(file, "    addq 8(%r10), %r9")?;
            writeln!(file, "    cmpq (%r11,%rax,8), %r9")?;
            writeln!(file, "    jae {bucket_slow_label}")?;
            writeln!(file, "    movq %r9, (%rdx,%rax,8)")?;
            writeln!(file, "    addq $16, %r10")?;
            writeln!(file, "    decl %ecx")?;
            writeln!(file, "    jne {bucket_scan_label}")?;
            writeln!(file, "{bucket_scan_done_label}:")?;
            writeln!(file, "{bucket_fast_label}:")?;
            writeln!(file, "    jmp {unchanged_label}")?;
            writeln!(file, "{bucket_slow_label}:")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET}(%r12), %rsi"
            )?;
            writeln!(file, "    movl {descriptor_offset}(%rsi), %eax")?;
            writeln!(file, "    shlq $4, %rax")?;
            writeln!(
                file,
                "    addq {AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET}(%r12), %rax"
            )?;
            writeln!(file, "    movq %rax, %rsi")?;
            writeln!(file, "    cmpq %r10, %rsi")?;
            writeln!(file, "    je {bucket_rollback_label}_done")?;
            writeln!(file, "{bucket_rollback_label}:")?;
            writeln!(file, "    movl (%rsi), %eax")?;
            writeln!(file, "    movq 8(%rsi), %r9")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdi"
            )?;
            writeln!(file, "    subq %r9, (%rdi,%rax,8)")?;
            writeln!(file, "    addq $16, %rsi")?;
            writeln!(file, "    cmpq %r10, %rsi")?;
            writeln!(file, "    jne {bucket_rollback_label}")?;
            writeln!(file, "{bucket_rollback_label}_done:")?;
        }
    }

    // Speculatively update all affected chip counts while accumulating trace
    // and main deltas and the largest absolute tower peak. The only loop
    // branch depends on descriptor size; bucket selection and max use cmov.
    writeln!(file, "    pxor %xmm0, %xmm0")?;
    writeln!(file, "    movq $0, 80(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %rax")?;
    writeln!(file, "    movq %rax, 32(%rsp)")?;
    if let Some((_, contributions)) = specialized_descriptor {
        for (index, contribution) in contributions.iter().enumerate() {
            emit_preflight_specialized_cost_contribution(
                &mut file,
                block_idx,
                index,
                contribution,
                has_lzcnt,
                has_bucket_cache,
            )?;
        }
    } else {
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
            if has_bucket_cache {
                writeln!(file, "    leaq -1(%r9), %r8")?;
                writeln!(file, "    movq $1, %rdi")?;
                writeln!(file, "    shlxq %r8, %rdi, %r8")?;
                writeln!(file, "    incq %r8")?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %rdi"
                )?;
                writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rdi"
                )?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
                )?;
                writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
            }
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
        writeln!(file, "    cmpq %r9, %rdx")?;
        writeln!(file, "    je {contribution_done_label}")?;
        writeln!(file, "    movq $1, 80(%rsp)")?;
        // Point at this chip's precomputed cost-table row. Keeping the row
        // offset in the descriptor avoids two serialized multiplies per chip.
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET}(%r12), %rdi"
        )?;
        writeln!(file, "    movq 40(%rsp), %r8")?;
        writeln!(file, "    addq %r8, %rdi")?;
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
        writeln!(file, "{contribution_done_label}:")?;
        writeln!(file, "    addq $16, %r10")?;
        writeln!(file, "    decl %ecx")?;
        writeln!(file, "    jne {loop_label}")?;
    }
    writeln!(file, "{loop_done_label}:")?;
    writeln!(file, "    cmpq $0, 80(%rsp)")?;
    writeln!(file, "    je {unchanged_label}")?;
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
    writeln!(file, "{unchanged_label}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    cmpq $0, (%r10)")?;
    writeln!(file, "    je {done_label}")?;
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
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{split_label}:")?;
    if let Some((descriptor, contributions)) = specialized_descriptor {
        writeln!(
            file,
            "    movq ${}, {AOT_CTX_PREFLIGHT_PENDING_SPECIALIZED_OFFSET}(%r12)",
            contributions.len() + 1
        )?;
        for (index, contribution) in contributions.iter().enumerate() {
            writeln!(
                file,
                "    movl ${}, {}(%r12)",
                contribution.chip_index,
                AOT_CTX_PREFLIGHT_PENDING_CHIPS_OFFSET + index * std::mem::size_of::<u32>()
            )?;
            writeln!(file, "    movabsq ${}, %rax", contribution.instance_delta)?;
            writeln!(
                file,
                "    movq %rax, {}(%r12)",
                AOT_CTX_PREFLIGHT_PENDING_DELTAS_OFFSET + index * std::mem::size_of::<u64>()
            )?;
        }
        for (offset, value) in [
            (
                AOT_CTX_PREFLIGHT_PENDING_TRACE_OFFSET,
                descriptor.standalone_trace_cells,
            ),
            (
                AOT_CTX_PREFLIGHT_PENDING_MAIN_OFFSET,
                descriptor.standalone_main_peak,
            ),
            (
                AOT_CTX_PREFLIGHT_PENDING_TOWER_OFFSET,
                descriptor.standalone_tower_peak,
            ),
        ] {
            writeln!(file, "    movabsq ${value}, %rax")?;
            writeln!(file, "    movq %rax, {offset}(%r12)")?;
        }
    }
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
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_plan_commit_diagnostic(mut file: impl Write, helper_kind: u32) -> Result<()> {
    // Keep the native entry's SysV stack alignment and preserve the semantic
    // helper kind. No caller-saved register or condition flag is live here.
    writeln!(file, "    subq $16, %rsp")?;
    writeln!(
        file,
        "    movl {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    movl %eax, 0(%rsp)")?;
    writeln!(
        file,
        "    movl ${helper_kind}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    movl 0(%rsp), %ecx")?;
    writeln!(
        file,
        "    movl %ecx, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    addq $16, %rsp")?;
    Ok(())
}

fn emit_preflight_direct_block_plan_exit(
    mut file: impl Write,
    program: &Program,
    block_idx: usize,
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
    let cut_label = format!(".L_preflight_replay_cut_{block_idx}");
    let done_label = format!(".L_preflight_replay_counted_{block_idx}");
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_REPLAY_RANGE_LEN_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r10")?;
    writeln!(file, "    leaq {block_steps}(%r10), %r11")?;
    writeln!(
        file,
        "    cmpq {AOT_CTX_PREFLIGHT_REPLAY_RANGE_CAPACITY_OFFSET}(%r12), %r11"
    )?;
    writeln!(file, "    jae {cut_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_REPLAY_FAMILY_COUNTS_OFFSET}(%r12), %r9"
    )?;
    let mut histogram = [0usize; InsnKind::COUNT];
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        histogram[instruction_at(program, pc)?.kind as usize] += 1;
        pc += PC_STEP_SIZE as u32;
    }
    for (kind, count) in histogram
        .into_iter()
        .enumerate()
        .filter(|(_, count)| *count != 0)
    {
        if crate::gpu_typed_kind_spec(InsnKind::iter().nth(kind).unwrap()).is_some() {
            writeln!(
                file,
                "    addq ${count}, {}(%r9)",
                kind * size_of::<usize>()
            )?;
        } else if InsnKind::iter().nth(kind).unwrap() == InsnKind::ECALL {
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_REPLAY_FALLBACK_COUNT_OFFSET}(%r12), %r8"
            )?;
            writeln!(file, "    addq ${count}, (%r8)")?;
        } else {
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_REPLAY_UNSUPPORTED_COUNT_OFFSET}(%r12), %r8"
            )?;
            writeln!(file, "    addq ${count}, (%r8)")?;
        }
    }
    writeln!(file, "    movq %r11, (%rax)")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{cut_label}:")?;
    writeln!(
        file,
        "    movq ${block_idx}, {AOT_CTX_PREFLIGHT_PENDING_BLOCK_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_REPLAY_BLOCK_CUT}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_block_trace_exit(mut file: impl Write, block: &BasicBlock) -> Result<()> {
    let block_steps = block_instruction_count(block);
    let block_cycles = block_steps * PC_STEP_SIZE as u64;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq ${block_cycles}, (%rax)")?;
    writeln!(
        file,
        "    addq ${block_steps}, {AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
    writeln!(file, "    movl %r15d, 8(%rsp)")?;
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

#[allow(clippy::too_many_arguments)]
fn emit_preflight_direct_step_static(
    mut file: impl Write,
    pc: u32,
    insn: Instruction,
    preflight_memory_bounds_updated: bool,
    preflight_memory_event_updated: bool,
    access_mode: PreflightAccessMode,
    check_busy_loop: bool,
    block_cycle_offset: Option<u64>,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    let has_memory_access =
        native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind);
    if trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds)
        && has_memory_access
        && !preflight_memory_bounds_updated
    {
        writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
        emit_preflight_direct_memory_bounds(&mut file, "%eax")?;
    }

    match access_mode {
        PreflightAccessMode::Exact => {
            let register_latest =
                trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest);
            let register_events =
                trace_style.preflight_feature_enabled(PreflightFeature::RegisterEvents);
            let memory_events =
                trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents);
            if register_latest || memory_events {
                emit_preflight_direct_access_cache_load(&mut file)?;
            }

            if native_step_loads_memory(insn.kind) {
                if register_latest && native_step_reads_rs1(insn.kind) {
                    emit_preflight_direct_register_access_cached(
                        &mut file,
                        insn.rs1 as u32,
                        PreflightSubcycle::Rs1,
                        register_events,
                    )?;
                }
                if memory_events {
                    writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                    emit_preflight_direct_memory_access_cached(
                        &mut file,
                        pc,
                        "%eax",
                        block_cycle_offset.unwrap_or(0),
                        None,
                        "%r11",
                        "%r10",
                        false,
                        false,
                    )?;
                }
                if register_latest && native_step_writes_rd(insn.kind) {
                    emit_preflight_direct_register_access_cached(
                        &mut file,
                        insn.rd_internal(),
                        PreflightSubcycle::Rd,
                        register_events,
                    )?;
                }
            } else {
                if register_latest {
                    for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
                        emit_preflight_direct_register_access_cached(
                            &mut file,
                            reg_idx,
                            subcycle,
                            register_events,
                        )?;
                    }
                }
                if has_memory_access && memory_events {
                    writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                    emit_preflight_direct_memory_access_cached(
                        &mut file,
                        pc,
                        "%eax",
                        block_cycle_offset.unwrap_or(0),
                        None,
                        "%r11",
                        "%r10",
                        false,
                        false,
                    )?;
                }
            }
        }
        PreflightAccessMode::BlockAtomic => {
            if has_memory_access
                && trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents)
                && !preflight_memory_event_updated
            {
                emit_preflight_direct_memory_shard_cache_load(&mut file)?;
                writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                emit_preflight_direct_memory_access_cached(
                    &mut file,
                    pc,
                    "%eax",
                    block_cycle_offset.unwrap_or(0),
                    None,
                    "%r11",
                    "%r10",
                    false,
                    false,
                )?;
            }
        }
    }

    if block_cycle_offset.is_none() {
        emit_preflight_direct_execution_metadata(&mut file, pc, insn)?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    addq $4, (%rax)")?;
        writeln!(
            file,
            "    incq {AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET}(%r12)"
        )?;
    }
    if check_busy_loop {
        emit_preflight_direct_busy_loop_guard(&mut file, pc)?;
    }
    if block_cycle_offset.is_none() {
        writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
    }
    Ok(())
}

fn emit_preflight_direct_execution_metadata(
    mut file: impl Write,
    pc: u32,
    insn: Instruction,
) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PC_BEFORE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movl ${pc:#010x}, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PC_AFTER_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %ecx")?;
    writeln!(file, "    movl %ecx, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LAST_KIND_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movb ${}, (%rax)", insn.kind as u8)?;
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
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je ceno_aot_done")?;
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
}

impl PreflightSubcycle {
    fn value(self) -> u64 {
        match self {
            PreflightSubcycle::Rs1 => 0,
            PreflightSubcycle::Rs2 => 1,
            PreflightSubcycle::Rd => 2,
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

fn emit_preflight_direct_memory_shard_cache_load(mut file: impl Write) -> Result<()> {
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
    first_touch_helper: u32,
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
            "    movl ${first_touch_helper}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movq %r12, %rdi")?;
        emit_flush_preflight_event_cursor(&mut file)?;
        writeln!(file, "    call *%r14")?;
        emit_reload_preflight_event_cursor(&mut file)?;
        writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
        writeln!(file, "    je ceno_aot_error")?;
        emit_preflight_direct_access_cache_load(&mut file)?;
    } else if first_touch_helper != AOT_PREFLIGHT_HELPER_MEMORY_FIRST_TOUCH {
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET}(%r12), %rsi"
        )?;
        writeln!(file, "    incq (%rsi)")?;
    }
    writeln!(file, "4:")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_preflight_direct_memory_access_cached(
    mut file: impl Write,
    pc: u32,
    addr_reg: &str,
    cycle_offset: u64,
    prev_stamp_reg: Option<&str>,
    prev_work_reg: &str,
    shard_start_reg: &str,
    prev_is_ordinal: bool,
    addr_is_dense_index: bool,
) -> Result<()> {
    let event_label = format!(".L_preflight_memory_event_{pc:x}");
    let done_label = format!(".L_preflight_memory_event_done_{pc:x}");
    if let Some(prev_stamp_reg) = prev_stamp_reg {
        if prev_stamp_reg != prev_work_reg {
            writeln!(file, "    movq {prev_stamp_reg}, {prev_work_reg}")?;
        }
    } else {
        writeln!(
            file,
            "    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), {prev_work_reg}"
        )?;
    }
    if !prev_is_ordinal {
        writeln!(file, "    shlq $2, {prev_work_reg}")?;
    }
    writeln!(file, "    cmpq {shard_start_reg}, {prev_work_reg}")?;
    writeln!(file, "    jb {event_label}")?;
    writeln!(file, ".pushsection .text.unlikely,\"ax\",@progbits")?;
    writeln!(file, "{event_label}:")?;
    let event_prev_work_reg = if prev_work_reg == "%rcx" {
        writeln!(file, "    movq %rcx, %rdi")?;
        "%rdi"
    } else {
        prev_work_reg
    };
    writeln!(file, "    movl {addr_reg}, %ecx")?;
    if addr_is_dense_index {
        writeln!(
            file,
            "    addl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %ecx"
        )?;
    }
    writeln!(file, "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %r9")?;
    writeln!(file, "    movq (%r9), %r9")?;
    writeln!(file, "    addq ${}, %r9", cycle_offset + 3)?;
    if prev_is_ordinal {
        writeln!(file, "    shlq $2, {event_prev_work_reg}")?;
    }
    writeln!(
        file,
        "    testq {event_prev_work_reg}, {event_prev_work_reg}"
    )?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    orq $3, {event_prev_work_reg}")?;
    writeln!(file, "1:")?;
    writeln!(
        file,
        "    movl %ecx, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)"
    )?;
    emit_preflight_direct_event_append(
        &mut file,
        event_prev_work_reg,
        "%r9",
        "%ecx",
        AOT_PREFLIGHT_HELPER_MEMORY_FIRST_TOUCH,
    )?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, ".popsection")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn emit_preflight_direct_register_access_cached(
    mut file: impl Write,
    reg_idx: u32,
    subcycle: PreflightSubcycle,
    emit_event: bool,
) -> Result<()> {
    let addr = reg_idx << 6;
    let offset = addr as u64 * std::mem::size_of::<Cycle>() as u64;
    writeln!(file, "    movq %r8, %rax")?;
    writeln!(file, "    addq ${}, %rax", subcycle.value())?;
    writeln!(file, "    movq {offset}(%rdx), %r11")?;
    writeln!(file, "    movq %rax, {offset}(%rdx)")?;
    if !emit_event {
        return Ok(());
    }
    // Zero is the uninitialized sentinel, and every shard starts after cycle zero,
    // so the unsigned shard-start comparison also covers first touches.
    writeln!(file, "    cmpq %r10, %r11")?;
    writeln!(file, "    jae 2f")?;
    writeln!(
        file,
        "    movl ${addr}, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)"
    )?;
    emit_preflight_direct_event_append(
        &mut file,
        "%r11",
        "%rax",
        &format!("${addr}"),
        AOT_PREFLIGHT_HELPER_FIRST_TOUCH,
    )?;
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
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    match native_opcode_family(insn.kind) {
        Some(NativeOpcodeFamily::Compute) => emit_native_compute(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            reserved_block_step,
        ),
        Some(NativeOpcodeFamily::ControlFlow) => emit_native_control_flow(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            reserved_block_step,
        ),
        Some(NativeOpcodeFamily::Memory) => emit_native_memory(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            reserved_block_step,
        ),
        None => emit_call_one(
            &mut file,
            pc,
            if insn.kind == InsnKind::ECALL {
                AOT_FALLBACK_ECALL
            } else {
                AOT_FALLBACK_EXCEPTIONAL
            },
            trace_style,
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

fn emit_preflight_capture_trace_metadata(mut file: impl Write, insn: Instruction) -> Result<()> {
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

fn emit_native_next_pc_immediate(
    mut file: impl Write,
    next_pc: u32,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if trace_style.carries_next_pc_in_register() {
        writeln!(file, "    movl ${next_pc:#010x}, %r15d")?;
    } else {
        writeln!(
            file,
            "    movl ${next_pc:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
        )?;
    }
    Ok(())
}

fn emit_native_next_pc_register(
    mut file: impl Write,
    next_pc_reg: &str,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if trace_style.carries_next_pc_in_register() {
        writeln!(file, "    movl {next_pc_reg}, %r15d")?;
    } else {
        writeln!(
            file,
            "    movl {next_pc_reg}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
        )?;
    }
    Ok(())
}

fn emit_native_compute(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    let execution_reserved = if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        None
    } else {
        reserved_block_step
    };
    let rd = insn.rd_internal();
    if !execution_reserved.is_some_and(|step| step.registers_resident) {
        writeln!(file, "    movq %r13, %r10")?;
    }
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
    if trace_style.is_layered_record()
        || execution_reserved.is_none_or(|step| step.remaining_after == 0)
    {
        emit_native_next_pc_immediate(
            &mut file,
            pc.wrapping_add(PC_STEP_SIZE as u32),
            trace_style,
        )?;
    }
    emit_after_native_step(
        &mut file,
        pc,
        program,
        insn,
        trace_style,
        false,
        false,
        reserved_block_step,
    )?;
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
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    let execution_reserved = if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        None
    } else {
        reserved_block_step
    };
    if !execution_reserved.is_some_and(|step| step.registers_resident) {
        writeln!(file, "    movq %r13, %r10")?;
    }
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
        emit_native_next_pc_immediate(&mut file, branch_target(pc, insn)?, trace_style)?;
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
        emit_native_next_pc_register(&mut file, "%edx", trace_style)?;
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
        emit_after_native_step(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            false,
            false,
            reserved_block_step,
        )?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{slow_label}:")?;
        emit_rollback_reserved_block_steps(&mut file, execution_reserved)?;
        emit_rollback_gpu_replay_packed_steps(&mut file, trace_style, reserved_block_step)?;
        let gpu_family_restore = emit_gpu_replay_packed_family_rollback(
            &mut file,
            program,
            pc,
            insn,
            trace_style,
            reserved_block_step,
        )?;
        emit_call_one(&mut file, pc, AOT_FALLBACK_EXCEPTIONAL, trace_style)?;
        emit_gpu_replay_packed_family_restore(&mut file, pc, gpu_family_restore)?;
        emit_restore_reserved_block_steps(&mut file, execution_reserved)?;
        emit_restore_gpu_replay_packed_steps(&mut file, trace_style, reserved_block_step)?;
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
        emit_native_next_pc_immediate(&mut file, fallthrough_pc, trace_style)?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{taken_label}:")?;
        emit_native_next_pc_immediate(&mut file, target_pc, trace_style)?;
        writeln!(file, "{done_label}:")?;
    }

    emit_after_native_step(
        &mut file,
        pc,
        program,
        insn,
        trace_style,
        false,
        false,
        reserved_block_step,
    )?;
    Ok(())
}

fn emit_native_memory(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    let execution_reserved = if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        None
    } else {
        reserved_block_step
    };
    let slow_label = format!(".L_memory_slow_{pc:x}");
    let done_label = format!(".L_memory_done_{pc:x}");
    let heap_ok_label = format!(".L_memory_heap_ok_{pc:x}");
    let stack_ok_label = format!(".L_memory_stack_ok_{pc:x}");
    let hints_ok_label = format!(".L_memory_hints_ok_{pc:x}");
    let dense_ok_label = format!(".L_memory_dense_ok_{pc:x}");
    let body_label = format!(".L_memory_body_{pc:x}");
    let rd = insn.rd_internal();
    let tracks_memory_latest = !trace_style.is_pure()
        && trace_style.preflight_feature_enabled(PreflightFeature::MemoryLatest);
    let tracks_mmio_bounds = !trace_style.is_pure()
        && trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds);
    let emits_memory_event_early = !cfg!(debug_assertions)
        && execution_reserved.is_some()
        && trace_style.uses_preflight_block_plan()
        && trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents);
    let memory_guard_hoisted = execution_reserved
        .map(|step| step.memory_guard_hoisted)
        .unwrap_or(false);
    let encoded_memory_region = execution_reserved.and_then(|step| step.memory_region_index);
    let memory_cells_resident = execution_reserved.is_some_and(|step| step.memory_cells_resident);
    let memory_ordinal_resident =
        execution_reserved.is_some_and(|step| step.memory_ordinal_resident);
    let memory_cells = if trace_style.is_pure() {
        "%rbx"
    } else {
        "%r11"
    };

    if !trace_style.is_pure() && !memory_cells_resident {
        writeln!(file, "    movq {AOT_CTX_MEMORY_CELLS_OFFSET}(%r12), %r11")?;
    }
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
    }
    if trace_style.is_layered_record()
        || execution_reserved.is_none_or(|step| step.remaining_after == 0)
    {
        emit_native_next_pc_immediate(
            &mut file,
            pc.wrapping_add(PC_STEP_SIZE as u32),
            trace_style,
        )?;
    }
    if trace_style.needs_callback_values() {
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
    }
    if !execution_reserved.is_some_and(|step| step.registers_resident) {
        writeln!(file, "    movq %r13, %r10")?;
    }
    writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
        )?;
    }
    writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
    if trace_style != AssemblyTraceStyle::PureBlock && !memory_guard_hoisted {
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
    }
    if trace_style == AssemblyTraceStyle::PureBlock {
        // Alignment and dense-memory membership were checked once at block
        // entry, using bases that this block cannot overwrite.
    } else if trace_style.is_pure() {
        // Value-only execution does not maintain heap/stack/hints extrema, so
        // one unsigned dense-memory check is sufficient. Traced modes retain
        // exact region classification and bounds updates below.
        if trace_style.is_layered_record() {
            writeln!(file, "    movl %edx, %eax")?;
            writeln!(file, "    shrl $2, %eax")?;
            writeln!(file, "    movl %eax, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
        }
        writeln!(file, "    subl %r14d, %edx")?;
        writeln!(file, "    cmpl 64(%rsp), %edx")?;
        writeln!(file, "    jae {slow_label}")?;
    } else if tracks_mmio_bounds && encoded_memory_region.is_none() {
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
    } else if !memory_guard_hoisted {
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
        writeln!(file, "    jae {slow_label}")?;
    }
    if trace_style.is_pure() {
        if trace_style.is_layered_record() && memory_guard_hoisted {
            writeln!(file, "    movl %edx, %eax")?;
            writeln!(file, "    shrl $2, %eax")?;
            writeln!(file, "    movl %eax, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
            writeln!(file, "    subl %r14d, %edx")?;
        } else if trace_style == AssemblyTraceStyle::PureBlock {
            writeln!(file, "    subl %r14d, %edx")?;
        }
        if matches!(insn.kind, InsnKind::LW | InsnKind::SW) {
            // Word accesses are already aligned, and neither operation needs
            // a byte-lane shift or an address mask.
        } else {
            writeln!(file, "    movl %edx, %r8d")?;
            // Variable 32-bit shifts mask the count to five bits, so after
            // multiplying the byte address by eight the upper address bits
            // cannot affect the selected byte lane.
            writeln!(file, "    shll $3, %r8d")?;
            writeln!(file, "    andl $0xfffffffc, %edx")?;
        }
    } else {
        if !matches!(insn.kind, InsnKind::LW | InsnKind::SW) {
            writeln!(file, "    movl %edx, %r8d")?;
            writeln!(file, "    andl $3, %r8d")?;
            writeln!(file, "    shll $3, %r8d")?;
        }
        writeln!(file, "    shrl $2, %edx")?;
        if should_publish_trace_memory_address(
            trace_style,
            tracks_mmio_bounds,
            emits_memory_event_early,
        ) {
            writeln!(file, "    movl %edx, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
        }
        if let Some(region_index) = encoded_memory_region {
            emit_preflight_direct_encoded_memory_region(&mut file, pc, region_index, &body_label)?;
        }
    }

    writeln!(file, "{body_label}:")?;
    if !trace_style.is_pure() && !memory_cells_resident {
        writeln!(
            file,
            "    subl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %edx"
        )?;
    }
    writeln!(file, "    movl %edx, %esi")?;
    if trace_style.is_pure() {
        writeln!(file, "    movl ({memory_cells},%rsi,2), %eax")?;
        if trace_style.has_layered_memory() {
            writeln!(file, "    movl 4({memory_cells},%rsi,2), %ecx")?;
            writeln!(
                file,
                "    movq %rcx, {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12)"
            )?;
        }
    } else if tracks_memory_latest {
        writeln!(file, "    movq ({memory_cells},%rsi,8), %rax")?;
        writeln!(file, "    movq %rax, %rcx")?;
        writeln!(file, "    shrq $32, %rcx")?;
        if emits_memory_event_early {
            if trace_style == AssemblyTraceStyle::PreflightProductionCapture {
                writeln!(
                    file,
                    "    movq %rcx, {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12)"
                )?;
            }
            emit_preflight_direct_memory_access_cached(
                &mut file,
                pc,
                "%esi",
                execution_reserved
                    .map(|step| step.cycle_offset)
                    .unwrap_or(0),
                Some("%rcx"),
                "%rcx",
                &format!("{AOT_CTX_PREFLIGHT_MEMORY_SHARD_START_ORDINAL_OFFSET}(%r12)"),
                true,
                !memory_cells_resident,
            )?;
        } else {
            writeln!(
                file,
                "    movq %rcx, {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12)"
            )?;
        }
    } else {
        writeln!(file, "    movl ({memory_cells},%rsi,8), %eax")?;
    }
    match insn.kind {
        InsnKind::LB | InsnKind::LH | InsnKind::LW | InsnKind::LBU | InsnKind::LHU => {
            writeln!(file, "    movl %eax, %r9d")?;
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
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12)"
                )?;
            }
        }
        _ => unreachable!("unsupported native memory instruction: {:?}", insn.kind),
    }
    if trace_style.is_pure() || !tracks_memory_latest {
        if !native_step_loads_memory(insn.kind) {
            // Update only the value half; pure execution deliberately leaves
            // the packed latest-access half untouched.
            let scale = if trace_style.is_pure() { 2 } else { 8 };
            writeln!(file, "    movl %eax, ({memory_cells},%rsi,{scale})")?;
        }
        if trace_style.has_layered_memory() {
            writeln!(
                file,
                "    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %rcx"
            )?;
            writeln!(file, "    movq (%rcx), %rcx")?;
            writeln!(file, "    shrq $2, %rcx")?;
            writeln!(file, "    movl %ecx, 4({memory_cells},%rsi,2)")?;
        }
    } else {
        if memory_ordinal_resident {
            let instruction_index = execution_reserved
                .expect("resident memory ordinal requires a reserved block")
                .cycle_offset
                / PC_STEP_SIZE as u64;
            writeln!(file, "    leaq {instruction_index}(%r15), %rcx")?;
        } else {
            writeln!(
                file,
                "    movq {AOT_CTX_MEMORY_START_ORDINAL_OFFSET}(%r12), %rcx"
            )?;
            writeln!(file, "    addq 0(%rsp), %rcx")?;
            if let Some(step) = execution_reserved {
                writeln!(file, "    subq ${}, %rcx", step.remaining_after + 1)?;
            } else if trace_style == AssemblyTraceStyle::GpuReplayDirect {
                if let Some(step) = reserved_block_step {
                    let unreserved = format!(".L_gpu_replay_memory_ordinal_{pc:08x}");
                    writeln!(
                        file,
                        "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
                    )?;
                    writeln!(file, "    je {unreserved}")?;
                    writeln!(file, "    subq ${}, %rcx", step.remaining_after + 1)?;
                    writeln!(file, "{unreserved}:")?;
                }
            }
        }
        writeln!(file, "    shlq $32, %rcx")?;
        if native_step_loads_memory(insn.kind) {
            writeln!(file, "    movl %r9d, %eax")?;
        }
        writeln!(file, "    orq %rax, %rcx")?;
        writeln!(file, "    movq %rcx, ({memory_cells},%rsi,8)")?;
    }
    emit_after_native_step(
        &mut file,
        pc,
        program,
        insn,
        trace_style,
        tracks_mmio_bounds,
        emits_memory_event_early,
        reserved_block_step,
    )?;
    // Keep the valid-access path contiguous. The per-PC callback stub lives in
    // a cold section and jumps back only when an alignment or range guard
    // actually fails.
    writeln!(file, ".pushsection .text.unlikely,\"ax\",@progbits")?;
    writeln!(file, "{slow_label}:")?;
    emit_rollback_reserved_block_steps(&mut file, execution_reserved)?;
    emit_rollback_gpu_replay_packed_steps(&mut file, trace_style, reserved_block_step)?;
    let gpu_family_restore = emit_gpu_replay_packed_family_rollback(
        &mut file,
        program,
        pc,
        insn,
        trace_style,
        reserved_block_step,
    )?;
    let l7_restore = if trace_style == AssemblyTraceStyle::PreflightCompactClosureL7 {
        let reserved = reserved_block_step.expect("L7 memory fallback must be block-admitted");
        let (family_count, static_rank) = l7_block_family_rank(
            program,
            reserved.block_start_pc,
            reserved.block_end_pc,
            pc,
            insn.kind,
        )?;
        let state_offset = insn.kind as usize
            * std::mem::size_of::<crate::gpu_typed_ingress::GpuTypedNativeKindState>();
        writeln!(
            file,
            "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
        )?;
        writeln!(file, "    addq ${state_offset}, %r10")?;
        writeln!(file, "    subl ${}, 108(%r10)", family_count - static_rank)?;
        Some((state_offset, family_count - static_rank - 1))
    } else {
        None
    };
    emit_call_one(&mut file, pc, AOT_FALLBACK_MEMORY_GUARD, trace_style)?;
    if let Some((state_offset, restore)) = l7_restore.filter(|(_, restore)| *restore != 0) {
        writeln!(
            file,
            "    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10"
        )?;
        writeln!(file, "    addq ${state_offset}, %r10")?;
        writeln!(file, "    addl ${restore}, 108(%r10)")?;
    }
    if trace_style == AssemblyTraceStyle::PreflightCompactClosureL7
        && reserved_block_step.is_some_and(|reserved| reserved.registers_resident)
    {
        writeln!(file, "    movq %r13, %r10")?;
    }
    emit_gpu_replay_packed_family_restore(&mut file, pc, gpu_family_restore)?;
    emit_restore_reserved_block_steps(&mut file, execution_reserved)?;
    emit_restore_gpu_replay_packed_steps(&mut file, trace_style, reserved_block_step)?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, ".popsection")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

fn should_publish_trace_memory_address(
    trace_style: AssemblyTraceStyle,
    tracks_mmio_bounds: bool,
    emits_memory_event_early: bool,
) -> bool {
    trace_style.needs_callback_values()
        || tracks_mmio_bounds
        || (trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents)
            && !emits_memory_event_early)
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
    if !trace_style.is_pure() {
        writeln!(file, "    movl %edx, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
    }
    if trace_style.is_preflight_direct() {
        emit_preflight_direct_memory_bound_known_region(
            &mut file,
            "%edx",
            min_ptr_offset,
            max_ptr_offset,
        )?;
    } else if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        let max_offset = match max_ptr_offset {
            AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET => Some(AOT_CTX_GPU_REPLAY_MAX_HEAP_OFFSET),
            AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET => Some(AOT_CTX_GPU_REPLAY_MAX_HINT_OFFSET),
            _ => None,
        };
        if let Some(max_offset) = max_offset {
            let done = format!("{label}_gpu_bound_done");
            writeln!(
                file,
                "    cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
            )?;
            writeln!(file, "    je {done}")?;
            writeln!(file, "    leal 4(,%rdx,4), %eax")?;
            writeln!(file, "    movq {max_offset}(%r12), %r9")?;
            writeln!(file, "    cmpl (%r9), %eax")?;
            writeln!(file, "    jbe {done}")?;
            writeln!(file, "    movl %eax, (%r9)")?;
            writeln!(file, "{done}:")?;
        }
    }
    writeln!(file, "    jmp {body_label}")?;
    Ok(())
}

fn emit_preflight_direct_encoded_memory_region(
    mut file: impl Write,
    pc: u32,
    region_index: usize,
    body_label: &str,
) -> Result<()> {
    let heap_label = format!(".L_memory_encoded_heap_{pc:x}");
    let stack_label = format!(".L_memory_encoded_stack_{pc:x}");
    let hints_label = format!(".L_memory_encoded_hints_{pc:x}");
    writeln!(file, "    movq 64(%rsp), %rax")?;
    if region_index != 0 {
        writeln!(file, "    shrq ${}, %rax", region_index * 2)?;
    }
    writeln!(file, "    andl $3, %eax")?;
    writeln!(file, "    cmpl $1, %eax")?;
    writeln!(file, "    je {heap_label}")?;
    writeln!(file, "    cmpl $2, %eax")?;
    writeln!(file, "    je {stack_label}")?;
    writeln!(file, "    cmpl $3, %eax")?;
    writeln!(file, "    je {hints_label}")?;
    writeln!(file, "    jmp {body_label}")?;
    for (label, min_offset, max_offset) in [
        (
            heap_label,
            AOT_CTX_PREFLIGHT_HEAP_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET,
        ),
        (
            stack_label,
            AOT_CTX_PREFLIGHT_STACK_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_STACK_MAX_OFFSET,
        ),
        (
            hints_label,
            AOT_CTX_PREFLIGHT_HINTS_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET,
        ),
    ] {
        writeln!(file, "{label}:")?;
        emit_preflight_direct_memory_bound_known_region(&mut file, "%edx", min_offset, max_offset)?;
        writeln!(file, "    jmp {body_label}")?;
    }
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
            writeln!(file, "    jne ceno_aot_dispatch")?;
        }
        return Ok(());
    }
    writeln!(file, "    jmp ceno_aot_dispatch")?;
    Ok(())
}

#[inline(always)]
unsafe extern "C" fn aot_exec_one<T: Tracer>(
    context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_FALLBACK, "fallback");
    let fallback_started = Instant::now();
    let context = unsafe { &mut *(context as *mut AotRuntimeContext) };
    if context.trace_mode == AOT_TRACE_MODE_GPU_REPLAY_DIRECT {
        let replay_vm = unsafe { &mut *(context.vm as *mut VMState<crate::GpuReplayTracer>) };
        if let Err(message) = replay_vm.tracer_mut().sync_native_range() {
            LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!(message)));
            return AOT_STATUS_ERROR;
        }
        if !matches!(
            context.fallback_reason,
            AOT_FALLBACK_ECALL | AOT_FALLBACK_EXCEPTIONAL
        ) {
            LAST_AOT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(anyhow!(
                    "GPU_REPLAY_DIRECT rejected fallback category {}",
                    context.fallback_reason
                ))
            });
            return AOT_STATUS_ERROR;
        }
    }
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
            context.fallback_time_ns = context
                .fallback_time_ns
                .saturating_add(fallback_started.elapsed().as_nanos() as u64);
            return AOT_STATUS_ERROR;
        }
    }
    if vm.halted() {
        unsafe {
            *next_pc = vm.get_pc().0;
        }
        context.fallback_time_ns = context
            .fallback_time_ns
            .saturating_add(fallback_started.elapsed().as_nanos() as u64);
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

    if matches!(
        context.trace_mode,
        AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
    ) {
        let preflight_vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
        (context.preflight_event_cursor, context.preflight_event_end) =
            preflight_vm.tracer_mut().native_next_access_ptrs();
        let shard_start = unsafe { *context.preflight_current_shard_start };
        if shard_start != context.preflight_register_shard_start {
            context.preflight_register_touched_mask = 0;
            context.preflight_register_shard_start = shard_start;
            context.preflight_memory_shard_start_ordinal = shard_start >> 2;
        }
    }

    let status = match result {
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
    };
    if context.trace_mode == AOT_TRACE_MODE_GPU_REPLAY_DIRECT && status != AOT_STATUS_ERROR {
        let replay_vm = unsafe { &mut *(context.vm as *mut VMState<crate::GpuReplayTracer>) };
        let state = replay_vm.tracer_mut().prepare_native_range();
        context.gpu_replay_kinds = state.kinds;
        context.gpu_replay_kind_count = state.kind_count;
        context.gpu_replay_ordinal = state.ordinal;
        context.gpu_replay_pending_cycle = state.pending_cycle;
        context.gpu_replay_latest_cells = state.latest_cells;
        context.gpu_replay_latest_base = state.latest_base.0;
        context.gpu_replay_latest_len = state.latest_len;
        context.gpu_replay_max_heap = state.max_heap_addr_access;
        context.gpu_replay_max_hint = state.max_hint_addr_access;
        context.gpu_replay_events = state.next_access_events;
        context.gpu_replay_events_len = state.next_access_len;
        context.gpu_replay_event_cursor = state.next_access_cursor;
        context.gpu_replay_error = state.error;
    }
    context.fallback_time_ns = context
        .fallback_time_ns
        .saturating_add(fallback_started.elapsed().as_nanos() as u64);
    status
}

/// Stable symbol for benchmark-only, value-only Pure AOT syscalls.
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn ceno_aot_pure_ecall_callback(
    raw_context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let fallback_started = Instant::now();
    let context = unsafe { &mut *(raw_context as *mut AotRuntimeContext) };
    if context.fallback_reason == AOT_FALLBACK_ECALL
        && !matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        )
    {
        let code = unsafe { *context.registers.add(Platform::reg_ecall() as usize) };
        let arg0 = unsafe { *context.registers.add(Platform::reg_arg0() as usize) };
        let arg1 = unsafe { *context.registers.add(Platform::reg_arg1() as usize) };
        if let Some(index) = pure_ecall_index(code) {
            if unsafe {
                crate::syscalls::pure::execute(
                    code,
                    context.registers,
                    context.memory_cells,
                    context.memory_base_word,
                    context.memory_end_word,
                    context.pure_double_cache,
                )
            } {
                if matches!(
                    context.trace_mode,
                    AOT_TRACE_MODE_FUTURE_ACCESS_L5 | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                ) {
                    let (registers, memory) =
                        crate::syscalls::pure::future_access_addresses(code, arg0, arg1)
                            .expect("successful pure syscall must have an L5 access description");
                    let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
                    vm.tracer_mut()
                        .record_layered_syscall_addresses(registers, memory);
                }
                context.fallback_steps += 1;
                context.fallback_ecall += 1;
                unsafe {
                    (*context.pure_ecall_counts)[index] += 1;
                    *next_pc = pc.wrapping_add(PC_STEP_SIZE as u32);
                }
                context.fallback_time_ns = context
                    .fallback_time_ns
                    .saturating_add(fallback_started.elapsed().as_nanos() as u64);
                return AOT_STATUS_CONTINUE;
            }
        }
    }
    unsafe { aot_exec_one::<PureAotTracer>(raw_context, pc, next_pc) }
}

fn layered_memory_value(context: &AotRuntimeContext, addr: WordAddr) -> Option<Word> {
    addr.0
        .checked_sub(context.memory_base_word)
        .filter(|_| addr.0 < context.memory_end_word)
        .map(|index| unsafe { *context.memory_cells.add(index as usize) as u32 })
}

fn layered_memory_previous_cycle(context: &AotRuntimeContext, addr: WordAddr) -> Option<Cycle> {
    addr.0
        .checked_sub(context.memory_base_word)
        .filter(|_| addr.0 < context.memory_end_word)
        .map(|index| unsafe { *context.memory_cells.add(index as usize) })
        .map(|cell| crate::dense_addr_space::PackedMemory::decode_stamp((cell >> 32) as u32))
}

unsafe fn write_compact_values_fallback(
    context: &mut AotRuntimeContext,
    cursor: usize,
    pc: u32,
    pc_after: u32,
    insn: Instruction,
    memory_addr: Option<WordAddr>,
    rs1: Word,
    rs2: Word,
    rd_before: Word,
    memory_before: Option<Word>,
) {
    let byte_cursor = unsafe { *context.compact_bytes_cursor };
    let mut destination = unsafe {
        context
            .fulltracer_records
            .cast::<u8>()
            .add(byte_cursor)
            .cast::<u32>()
    };
    let mut write = |value: u32| unsafe {
        destination.write_unaligned(value);
        destination = destination.add(1);
    };
    write(u32::try_from(cursor).expect("L2C ordinal exceeds u32"));
    write(pc);
    write(pc_after);
    write(memory_addr.map_or(COMPACT_SKELETON_NO_MEMORY, |addr| addr.0));
    if native_step_reads_rs1(insn.kind) {
        write(rs1);
    }
    if native_step_reads_rs2(insn.kind) {
        write(rs2);
    }
    if native_step_writes_rd(insn.kind) {
        write(rd_before);
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        write(memory_before.expect("L2C memory row has no before value"));
    }
    unsafe {
        *context.compact_bytes_cursor = byte_cursor + compact_values_row_size(insn);
    }
}

struct CompactRegistersPacker {
    chunks: [u64; 4],
    bit: usize,
}

impl CompactRegistersPacker {
    fn new() -> Self {
        Self {
            chunks: [0; 4],
            bit: 0,
        }
    }

    fn push(&mut self, value: u32, width: usize) {
        debug_assert!(width <= 32);
        debug_assert!(width == 32 || u64::from(value) < 1u64 << width);
        let chunk = self.bit / 64;
        let shift = self.bit % 64;
        self.chunks[chunk] |= u64::from(value) << shift;
        if shift + width > 64 {
            self.chunks[chunk + 1] |= u64::from(value) >> (64 - shift);
        }
        self.bit += width;
    }

    unsafe fn commit(self, destination: *mut u8, byte_len: usize) {
        debug_assert_eq!(self.bit.div_ceil(8), byte_len);
        let mut offset = 0;
        for chunk in self.chunks.iter().take(byte_len / 8) {
            unsafe {
                destination
                    .add(offset)
                    .cast::<u64>()
                    .write_unaligned(*chunk)
            };
            offset += 8;
        }
        let remainder = byte_len - offset;
        let tail = self.chunks[byte_len / 8];
        if remainder >= 4 {
            unsafe {
                destination
                    .add(offset)
                    .cast::<u32>()
                    .write_unaligned(tail as u32)
            };
            offset += 4;
        }
        if remainder & 2 != 0 {
            unsafe {
                destination
                    .add(offset)
                    .cast::<u16>()
                    .write_unaligned((tail >> (offset % 8 * 8)) as u16)
            };
            offset += 2;
        }
        if remainder & 1 != 0 {
            unsafe {
                destination
                    .add(offset)
                    .write((tail >> (offset % 8 * 8)) as u8)
            };
        }
    }
}

unsafe fn write_compact_registers_fallback(
    context: &mut AotRuntimeContext,
    pc: u32,
    pc_after: u32,
    insn: Instruction,
    rs1: Word,
    rs2: Word,
    rd_before: Word,
    memory_before: Option<Word>,
    register_previous: [Cycle; 3],
    memory_previous: Option<Cycle>,
) -> Result<()> {
    let future_l5 = matches!(
        context.trace_mode,
        AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
            | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
            | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
    );
    let memory_l4 = context.trace_mode == AOT_TRACE_MODE_COMPACT_MEMORY_L4C || future_l5;
    let pc_offset = pc
        .checked_sub(context.program_base)
        .filter(|offset| offset % PC_STEP_SIZE as u32 == 0)
        .map(|offset| offset / PC_STEP_SIZE as u32)
        .filter(|offset| *offset < 1 << COMPACT_REGISTERS_PC_BITS)
        .ok_or_else(|| anyhow!("L3C PC exceeds aligned 20-bit program window"))?;
    for (enabled, previous) in [
        native_step_reads_rs1(insn.kind),
        native_step_reads_rs2(insn.kind),
        native_step_writes_rd(insn.kind),
    ]
    .into_iter()
    .zip(register_previous)
    {
        if enabled && previous >= 1 << COMPACT_REGISTERS_CYCLE_BITS {
            bail!("L3C predecessor cycle exceeds 27-bit compact width");
        }
    }
    if memory_l4
        && memory_previous.is_some_and(|previous| previous >= 1 << COMPACT_REGISTERS_CYCLE_BITS)
    {
        bail!("L4C memory predecessor cycle exceeds 27-bit compact width");
    }
    let mut packer = CompactRegistersPacker::new();
    packer.push(pc_offset, COMPACT_REGISTERS_PC_BITS);
    packer.push(insn.raw >> 7, COMPACT_REGISTERS_RAW_BITS);
    for (enabled, previous, value) in [
        (native_step_reads_rs1(insn.kind), register_previous[0], rs1),
        (native_step_reads_rs2(insn.kind), register_previous[1], rs2),
        (
            native_step_writes_rd(insn.kind),
            register_previous[2],
            rd_before,
        ),
    ] {
        if enabled {
            packer.push(previous as u32, COMPACT_REGISTERS_CYCLE_BITS);
            packer.push(value, 32);
        }
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        packer.push(
            memory_before.ok_or_else(|| anyhow!("L3C memory row has no before value"))?,
            32,
        );
        if memory_l4 {
            packer.push(
                memory_previous.expect("L4C memory row has no predecessor") as u32,
                COMPACT_REGISTERS_CYCLE_BITS,
            );
        }
    }
    if insn.kind == InsnKind::ECALL {
        packer.push(pc_after, 32);
        if memory_l4 {
            packer.push(unsafe { (*context.fulltracer_max_heap).0 }, 32);
            packer.push(unsafe { (*context.fulltracer_max_hint).0 }, 32);
        }
    }
    if future_l5 {
        let cycle = unsafe { *context.fulltracer_pending_cycle };
        let mut accesses = [(0, WordAddr(0), 0); 4];
        let mut access_count = 0;
        if native_step_reads_rs1(insn.kind) {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_RS1,
                Platform::register_vma(insn.rs1).into(),
                crate::StepRecord::FUTURE_ACCESS_RS1,
            );
            access_count += 1;
        }
        if native_step_reads_rs2(insn.kind) {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_RS2,
                Platform::register_vma(insn.rs2).into(),
                crate::StepRecord::FUTURE_ACCESS_RS2,
            );
            access_count += 1;
        }
        if native_step_writes_rd(insn.kind) {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_RD,
                Platform::register_vma(insn.rd_internal() as RegIdx).into(),
                crate::StepRecord::FUTURE_ACCESS_RD,
            );
            access_count += 1;
        }
        if let Some(address) = (native_step_loads_memory(insn.kind)
            || native_step_stores_memory(insn.kind))
        .then(|| ByteAddr(rs1.wrapping_add(insn.imm as u32)).waddr())
        {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_MEM,
                address,
                crate::StepRecord::FUTURE_ACCESS_MEM,
            );
            access_count += 1;
        }
        let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
        let mask = vm
            .tracer_mut()
            .consume_compact_row_future_accesses(cycle, &accesses[..access_count]);
        for (enabled, bit) in [
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
            if enabled {
                packer.push(u32::from(mask & bit != 0), 1);
            }
        }
    }
    let byte_cursor = unsafe { *context.compact_bytes_cursor };
    let row_size = if future_l5 {
        compact_future_access_row_size(insn)
    } else if memory_l4 {
        compact_memory_row_size(insn)
    } else {
        compact_registers_row_size(insn)
    };
    unsafe {
        packer.commit(
            context.fulltracer_records.cast::<u8>().add(byte_cursor),
            row_size,
        );
        *context.compact_bytes_cursor = byte_cursor + row_size;
    }
    Ok(())
}

/// Scalar L7 ordinary fallback writes the retained GPU packed-AoS family
/// directly. Admission is a one-row transaction: validate first, pack into the
/// unpublished row, and publish the family cursor only after the final store.
unsafe fn write_l7_compact_fallback(
    context: &mut AotRuntimeContext,
    pc: u32,
    insn: Instruction,
    rs1: Word,
    rs2: Word,
    rd_before: Word,
    memory_before: Option<Word>,
    memory_previous: Option<Cycle>,
) -> Result<()> {
    let spec = crate::gpu_typed_kind_spec(insn.kind)
        .ok_or_else(|| anyhow!("L7 scalar ordinary kind has no compact family"))?;
    let kind_index = insn.kind as usize;
    if context.gpu_replay_kinds.is_null() || kind_index >= context.gpu_replay_kind_count {
        bail!("L7 scalar compact family is absent");
    }
    let state = unsafe { &mut *context.gpu_replay_kinds.add(kind_index) };
    if state.sentinel != crate::gpu_typed_ingress::GPU_COMPACT_NATIVE_SENTINEL
        || state.layout != spec.layout as u32
        || state.fields[0].is_null()
    {
        bail!("L7 scalar compact family state mismatch");
    }
    let row = state.cursor;
    if row >= state.capacity {
        bail!("L7 scalar compact family capacity exceeded");
    }
    let ordinal = unsafe { *context.gpu_replay_ordinal };
    let local_ordinal = u32::try_from(ordinal)?
        .checked_sub(state.range_start)
        .filter(|ordinal| *ordinal < 1 << 18)
        .ok_or_else(|| anyhow!("L7 scalar compact ordinal exceeds range"))?;
    if state.pc_base == 0 {
        state.pc_base = pc & !((1 << 22) - 1);
    }
    let pc_offset = pc
        .checked_sub(state.pc_base)
        .filter(|offset| offset & 3 == 0 && offset >> 2 < 1 << 20)
        .map(|offset| offset >> 2)
        .ok_or_else(|| anyhow!("L7 scalar compact PC exceeds aligned window"))?;
    let cycle = unsafe { *context.gpu_replay_pending_cycle };
    let latest = context.gpu_replay_latest_cells;
    let access = |reg: RegIdx, subcycle: Cycle, value: Word| -> Result<(u32, Word)> {
        // L7 borrows PureAotTracer's dense 32-register predecessor array, not
        // GpuReplayTracer's address-indexed latest-cell domain.
        let index = reg as usize;
        let cell = unsafe { latest.add(index) };
        let previous = unsafe { *cell };
        if previous == 0 {
            unsafe { *context.gpu_replay_latest_len += 1 };
        }
        unsafe { *cell = cycle + subcycle };
        Ok((u32::try_from(previous)?, value))
    };
    let rs1_access = native_step_reads_rs1(insn.kind)
        .then(|| access(insn.rs1, crate::FullTracer::SUBCYCLE_RS1, rs1))
        .transpose()?;
    let rs2_access = native_step_reads_rs2(insn.kind)
        .then(|| access(insn.rs2, crate::FullTracer::SUBCYCLE_RS2, rs2))
        .transpose()?;
    let rd_access = native_step_writes_rd(insn.kind)
        .then(|| {
            access(
                insn.rd_internal() as RegIdx,
                crate::FullTracer::SUBCYCLE_RD,
                rd_before,
            )
        })
        .transpose()?;

    let mut accesses = [(0, WordAddr(0), 0); 4];
    let mut access_count = 0;
    for (enabled, subcycle, address, bit) in [
        (
            native_step_reads_rs1(insn.kind),
            crate::FullTracer::SUBCYCLE_RS1,
            Platform::register_vma(insn.rs1).into(),
            crate::StepRecord::FUTURE_ACCESS_RS1,
        ),
        (
            native_step_reads_rs2(insn.kind),
            crate::FullTracer::SUBCYCLE_RS2,
            Platform::register_vma(insn.rs2).into(),
            crate::StepRecord::FUTURE_ACCESS_RS2,
        ),
        (
            native_step_writes_rd(insn.kind),
            crate::FullTracer::SUBCYCLE_RD,
            Platform::register_vma(insn.rd_internal() as RegIdx).into(),
            crate::StepRecord::FUTURE_ACCESS_RD,
        ),
    ] {
        if enabled {
            accesses[access_count] = (subcycle, address, bit);
            access_count += 1;
        }
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        accesses[access_count] = (
            crate::FullTracer::SUBCYCLE_MEM,
            ByteAddr(rs1.wrapping_add(insn.imm as u32)).waddr(),
            crate::StepRecord::FUTURE_ACCESS_MEM,
        );
        access_count += 1;
    }
    let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
    let mask = vm
        .tracer_mut()
        .consume_compact_row_future_accesses(cycle, &accesses[..access_count]);

    let mut packer = CompactRegistersPacker::new();
    packer.push(local_ordinal, 18);
    packer.push(pc_offset, 20);
    packer.push(insn.raw >> 7, 25);
    let push_access = |packer: &mut CompactRegistersPacker, access: (u32, Word)| {
        packer.push(access.0, 27);
        packer.push(access.1, 32);
    };
    match spec.layout {
        crate::gpu_typed_ingress::GpuTypedLayout::R => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rs2_access.unwrap());
            push_access(&mut packer, rd_access.unwrap());
        }
        crate::gpu_typed_ingress::GpuTypedLayout::I
        | crate::gpu_typed_ingress::GpuTypedLayout::Jalr => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rd_access.unwrap());
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Branch => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rs2_access.unwrap());
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Jal => {
            push_access(&mut packer, rd_access.unwrap())
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Load => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rd_access.unwrap());
            push_access(
                &mut packer,
                (
                    u32::try_from(memory_previous.expect("L7 load predecessor"))?,
                    memory_before.expect("L7 load value"),
                ),
            );
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Store => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rs2_access.unwrap());
            push_access(
                &mut packer,
                (
                    u32::try_from(memory_previous.expect("L7 store predecessor"))?,
                    memory_before.expect("L7 store value"),
                ),
            );
        }
        crate::gpu_typed_ingress::GpuTypedLayout::U => {
            // The retained typed oracle represents U-family's implicit x0
            // lane as cycle-only, without an accompanying value lane.
            packer.push(rs1_access.expect("L7 U implicit x0 access").0, 27);
            push_access(&mut packer, rd_access.unwrap());
        }
    }
    packer.push(u32::from(mask), 4);
    let stride = spec.layout.compact_bytes();
    unsafe {
        packer.commit(
            state.fields[0].cast::<u8>().add(row as usize * stride),
            stride,
        );
    }
    state.cursor = row + 1;
    Ok(())
}

/// Private layered fallback: execute with the L0 value lane, then publish the
/// completed step's fields into the pre-reserved generic buffer.
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn ceno_aot_skeleton_l1_callback(
    raw_context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let context = unsafe { &mut *(raw_context as *mut AotRuntimeContext) };
    let insn_index = pc.wrapping_sub(context.program_base) as usize / PC_STEP_SIZE;
    let insn = unsafe { *context.instructions.add(insn_index) };
    let rs1_value = unsafe { *context.registers.add(insn.rs1 as usize) };
    let rs2_value = unsafe { *context.registers.add(insn.rs2 as usize) };
    let rd = insn.rd_internal() as usize;
    let rd_before = unsafe { *context.registers.add(rd) };
    let memory_addr = (native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind))
        .then(|| ByteAddr(rs1_value.wrapping_add(insn.imm as u32)).waddr());
    let memory_before = memory_addr.and_then(|addr| layered_memory_value(context, addr));
    let layered_memory = matches!(
        context.trace_mode,
        AOT_TRACE_MODE_COMPACT_MEMORY_L4C
            | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
            | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
            | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
            | AOT_TRACE_MODE_MEMORY_L4
            | AOT_TRACE_MODE_FUTURE_ACCESS_L5
    );
    let memory_previous_cycle = if layered_memory {
        memory_addr.and_then(|addr| layered_memory_previous_cycle(context, addr))
    } else {
        None
    };
    let bounds_before = if layered_memory {
        Some(unsafe { (*context.fulltracer_max_heap, *context.fulltracer_max_hint) })
    } else {
        None
    };
    let status = unsafe { ceno_aot_pure_ecall_callback(raw_context, pc, next_pc) };
    if status != AOT_STATUS_ERROR {
        let cursor = unsafe { *context.fulltracer_pending_index };
        let cycle = unsafe { *context.fulltracer_pending_cycle };
        if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        ) && insn.kind == InsnKind::ECALL
        {
            let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
            vm.tracer_mut().finish_compact_l6_ecall();
        }
        if context.trace_mode == AOT_TRACE_MODE_COMPACT_CLOSURE_L7 && insn.kind != InsnKind::ECALL {
            if let Err(err) = unsafe {
                write_l7_compact_fallback(
                    context,
                    pc,
                    insn,
                    rs1_value,
                    rs2_value,
                    rd_before,
                    memory_before,
                    memory_previous_cycle,
                )
            } {
                LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
                return AOT_STATUS_ERROR;
            }
            unsafe {
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        if context.trace_mode == AOT_TRACE_MODE_COMPACT_SKELETON_L1C {
            let record = CompactSkeletonRecord::new(cursor, pc, unsafe { *next_pc }, memory_addr);
            unsafe {
                context
                    .fulltracer_records
                    .cast::<CompactSkeletonRecord>()
                    .add(cursor)
                    .write(record);
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        if context.trace_mode == AOT_TRACE_MODE_COMPACT_VALUES_L2C {
            unsafe {
                write_compact_values_fallback(
                    context,
                    cursor,
                    pc,
                    *next_pc,
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    rd_before,
                    memory_before,
                );
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        let mut register_previous = [crate::StepRecord::L1_POISON_CYCLE; 3];
        if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                | AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
                | AOT_TRACE_MODE_REGISTERS_L3
                | AOT_TRACE_MODE_MEMORY_L4
                | AOT_TRACE_MODE_FUTURE_ACCESS_L5
        ) {
            let latest = context.fulltracer_latest_cells;
            if native_step_reads_rs1(insn.kind) {
                let cell = unsafe { latest.add(insn.rs1 as usize) };
                register_previous[0] = unsafe { *cell };
                unsafe { *cell = cycle + crate::FullTracer::SUBCYCLE_RS1 };
            }
            if native_step_reads_rs2(insn.kind) {
                let cell = unsafe { latest.add(insn.rs2 as usize) };
                register_previous[1] = unsafe { *cell };
                unsafe { *cell = cycle + crate::FullTracer::SUBCYCLE_RS2 };
            }
            if native_step_writes_rd(insn.kind) {
                let cell = unsafe { latest.add(insn.rd_internal() as usize) };
                register_previous[2] = unsafe { *cell };
                unsafe { *cell = cycle + crate::FullTracer::SUBCYCLE_RD };
            }
        }
        if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                | AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        ) {
            if let Err(err) = unsafe {
                write_compact_registers_fallback(
                    context,
                    pc,
                    *next_pc,
                    insn,
                    rs1_value,
                    rs2_value,
                    rd_before,
                    memory_before,
                    register_previous,
                    memory_previous_cycle,
                )
            } {
                LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
                return AOT_STATUS_ERROR;
            }
            unsafe {
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        let record = if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_VALUES_L2
                | AOT_TRACE_MODE_REGISTERS_L3
                | AOT_TRACE_MODE_MEMORY_L4
                | AOT_TRACE_MODE_FUTURE_ACCESS_L5
        ) {
            let rd_after = unsafe { *context.registers.add(rd) };
            let memory_value = memory_addr
                .and_then(|addr| layered_memory_value(context, addr))
                .zip(memory_before)
                .map(|(after, before)| Change::new(before, after));
            if layered_memory {
                let (heap_before, hint_before) = bounds_before
                    .expect("L4 fallback must snapshot heap/hint bounds before execution");
                crate::StepRecord::l4_memory(
                    cycle,
                    Change::new(pc.into(), unsafe { *next_pc }.into()),
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    Change::new(rd_before, rd_after),
                    memory_value,
                    register_previous,
                    memory_previous_cycle,
                    Change::new(heap_before, unsafe { *context.fulltracer_max_heap }),
                    Change::new(hint_before, unsafe { *context.fulltracer_max_hint }),
                )
            } else if context.trace_mode == AOT_TRACE_MODE_REGISTERS_L3 {
                crate::StepRecord::l3_registers(
                    cycle,
                    Change::new(pc.into(), unsafe { *next_pc }.into()),
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    Change::new(rd_before, rd_after),
                    memory_value,
                    register_previous,
                )
            } else {
                crate::StepRecord::l2_values(
                    cycle,
                    Change::new(pc.into(), unsafe { *next_pc }.into()),
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    Change::new(rd_before, rd_after),
                    memory_value,
                )
            }
        } else {
            crate::StepRecord::l1_skeleton(
                cycle,
                Change::new(pc.into(), unsafe { *next_pc }.into()),
                insn,
                memory_addr,
            )
        };
        unsafe {
            context.fulltracer_records.add(cursor).write(record);
            *context.fulltracer_pending_index = cursor + 1;
            *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
            *context.fulltracer_len = cursor + 1;
        }
    }
    status
}

/// Stable symbol covering the Rust fallback path, including syscall bodies.
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn ceno_aot_preflight_fallback_callback(
    raw_context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let fallback_started = Instant::now();
    let context = unsafe { &mut *(raw_context as *mut AotRuntimeContext) };
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    invalidate_preflight_bucket_cache(context);
    if context.trace_mode != AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        && context.fallback_reason == AOT_FALLBACK_ECALL
    {
        let code = unsafe { *context.registers.add(Platform::reg_ecall() as usize) };
        let arg0 = unsafe { *context.registers.add(Platform::reg_arg0() as usize) };
        let arg1 = unsafe { *context.registers.add(Platform::reg_arg1() as usize) };
        if let (Some(index), Some(plan)) = (
            pure_ecall_index(code),
            crate::syscalls::pure::access_plan(code, arg0, arg1),
        ) {
            let executed = unsafe {
                crate::syscalls::pure::execute(
                    code,
                    context.registers,
                    context.memory_cells,
                    context.memory_base_word,
                    context.memory_end_word,
                    context.pure_double_cache,
                )
            };
            if executed {
                let pc = ByteAddr(pc);
                vm.set_pc(pc);
                let insn = vm
                    .fetch(pc.waddr())
                    .expect("direct syscall PC must belong to the compiled program");
                debug_assert_eq!(insn.kind, InsnKind::ECALL);
                let loaded_code = vm
                    .load_register(Platform::reg_ecall())
                    .expect("register load cannot fail");
                debug_assert_eq!(loaded_code, code);
                vm.finish_direct_preflight_syscall(plan);

                context.fallback_steps += 1;
                context.fallback_ecall += 1;
                unsafe {
                    (*context.pure_ecall_counts)[index] += 1;
                    *next_pc = vm.get_pc().0;
                }
                (context.preflight_event_cursor, context.preflight_event_end) =
                    vm.tracer_mut().native_next_access_ptrs();
                let shard_start = unsafe { *context.preflight_current_shard_start };
                if shard_start != context.preflight_register_shard_start {
                    context.preflight_register_touched_mask = 0;
                    context.preflight_register_shard_start = shard_start;
                    context.preflight_memory_shard_start_ordinal = shard_start >> 2;
                }
                context.fallback_time_ns = context
                    .fallback_time_ns
                    .saturating_add(fallback_started.elapsed().as_nanos() as u64);
                return AOT_STATUS_CONTINUE;
            }
        }
    }
    unsafe { aot_exec_one::<PreflightTracer>(raw_context, pc, next_pc) }
}

unsafe extern "C" fn aot_trace_native_compute<T: Tracer>(context: *mut AotRuntimeContext) -> u32 {
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_TRACE, "trace");
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
        if aot_native_diagnostic_only() && AOT_NATIVE_CALLBACK_TRACE.load(Ordering::Relaxed) == 1 {
            aot_native_diagnostic_boundary(
                "FIRST_CALLBACK_CONTEXT",
                "OBSERVE",
                &format!(
                    "callback_ordinal=0,trace_pc={:#010x},trace_next_pc={:#010x},raw_trace_kind={},program_pc={:#010x},program_kind={:?},mode={}",
                    context.trace_pc,
                    context.trace_next_pc,
                    context.trace_kind,
                    pc.0,
                    insn.kind,
                    context.trace_mode,
                ),
            );
        }
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
            #[cfg(any(test, debug_assertions))]
            {
                if context.memory_prev_stamp == 0 {
                    vm.record_native_memory_first_touch(WordAddr(context.trace_mem_addr));
                }
            }
            let previous_cycle = crate::dense_addr_space::PackedMemory::decode_stamp(
                context.memory_prev_stamp as u32,
            );
            vm.tracer_mut().load_memory(
                WordAddr(context.trace_mem_addr),
                context.trace_mem_after,
                previous_cycle,
            );
        }
        if native_step_stores_memory(insn.kind) {
            #[cfg(any(test, debug_assertions))]
            {
                if context.memory_prev_stamp == 0 {
                    vm.record_native_memory_first_touch(WordAddr(context.trace_mem_addr));
                }
            }
            let previous_cycle = crate::dense_addr_space::PackedMemory::decode_stamp(
                context.memory_prev_stamp as u32,
            );
            vm.tracer_mut().store_memory(
                WordAddr(context.trace_mem_addr),
                Change {
                    before: context.trace_mem_before,
                    after: context.trace_mem_after,
                },
                previous_cycle,
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

fn invalidate_preflight_bucket_cache(context: &mut AotRuntimeContext) {
    context.preflight_bucket_generation = context.preflight_bucket_generation.wrapping_add(1);
    if context.preflight_bucket_generation == 0 {
        if !context.preflight_bucket_generations.is_null() {
            let generations = unsafe {
                std::slice::from_raw_parts_mut(
                    context.preflight_bucket_generations,
                    context.preflight_num_chips,
                )
            };
            generations.fill(0);
        }
        context.preflight_bucket_generation = 1;
    }
}

unsafe extern "C" fn aot_trace_native_preflight(context: *mut AotRuntimeContext) -> u32 {
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_TRACE, "trace");
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
        memory_previous_cycle: crate::dense_addr_space::PackedMemory::decode_stamp(
            context.memory_prev_stamp as u32,
        ),
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
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_PREFLIGHT, "preflight-direct");
    let context = unsafe { &mut *context };
    let diagnostic_variant = match context.preflight_helper_kind {
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_ENTRY => Some(("COMMIT_ENTRY", "adaptive_exact")),
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_EXIT => Some(("COMMIT_EXIT", "adaptive_exact")),
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_ENTRY => Some(("COMMIT_ENTRY", "block_plan")),
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_EXIT => Some(("COMMIT_EXIT", "block_plan")),
        _ => None,
    };
    if let Some((phase, variant)) = diagnostic_variant {
        aot_plan_commit_diagnostic_state(phase, variant, context);
        return AOT_STATUS_CONTINUE;
    }
    invalidate_preflight_bucket_cache(context);
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
            let specialized_count = context
                .preflight_pending_specialized
                .checked_sub(1)
                .map(|count| count as usize);
            let adaptive_descriptor = (!context.preflight_block_cost_descriptors.is_null()
                && specialized_count.is_none()
                && context.preflight_pending_block != usize::MAX)
                .then(|| unsafe {
                    *context
                        .preflight_block_cost_descriptors
                        .add(context.preflight_pending_block)
                });
            if let Some(count) = specialized_count {
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                for index in 0..count {
                    let chip = context.preflight_pending_chips[index] as usize;
                    counts[chip] =
                        counts[chip].saturating_sub(context.preflight_pending_deltas[index]);
                }
            } else if let Some(descriptor) = adaptive_descriptor {
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
            if let Err(message) = vm.tracer_mut().sync_combined_capture() {
                LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!(message)));
                return AOT_STATUS_ERROR;
            }
            if let Some(count) = specialized_count {
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                for index in 0..count {
                    counts[context.preflight_pending_chips[index] as usize] =
                        context.preflight_pending_deltas[index];
                }
                unsafe {
                    *context.preflight_planner_cur_trace_cells = context.preflight_pending_trace;
                    *context.preflight_planner_cur_main_peak = context.preflight_pending_main;
                    *context.preflight_planner_cur_tower_peak = context.preflight_pending_tower;
                    *context.preflight_planner_cur_cells =
                        context.preflight_pending_trace.saturating_add(
                            context
                                .preflight_pending_main
                                .max(context.preflight_pending_tower),
                        );
                }
                context.preflight_pending_specialized = 0;
                context.preflight_pending_block = usize::MAX;
            } else if let Some(descriptor) = adaptive_descriptor {
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
        AOT_PREFLIGHT_HELPER_REPLAY_BLOCK_CUT => {
            let block_index = context.preflight_pending_block;
            if context.preflight_block_kind_histograms.is_null()
                || block_index >= context.preflight_block_kind_histogram_count
            {
                LAST_AOT_ERROR.with(|slot| {
                    *slot.borrow_mut() = Some(anyhow!(
                        "AOT replay block metadata index {block_index} is out of bounds"
                    ))
                });
                AOT_STATUS_ERROR
            } else {
                let descriptor =
                    unsafe { &*context.preflight_block_kind_histograms.add(block_index) };
                let instructions = unsafe {
                    std::slice::from_raw_parts(
                        context
                            .instructions
                            .add(descriptor.instruction_offset as usize),
                        descriptor.instruction_count as usize,
                    )
                };
                let ordered_kinds = instructions
                    .iter()
                    .map(|instruction| instruction.kind)
                    .collect::<Vec<_>>();
                vm.tracer_mut()
                    .record_admitted_native_block(&descriptor.counts, &ordered_kinds);
                if let Err(message) = vm.tracer_mut().sync_combined_capture() {
                    LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!(message)));
                    return AOT_STATUS_ERROR;
                }
                context.preflight_pending_block = usize::MAX;
                AOT_STATUS_CONTINUE
            }
        }
        AOT_PREFLIGHT_HELPER_FIRST_TOUCH => {
            vm.tracer_mut()
                .record_native_first_touch(WordAddr(context.preflight_event_addr));
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_MEMORY_FIRST_TOUCH => {
            #[cfg(any(test, debug_assertions))]
            vm.record_native_memory_first_touch(WordAddr(context.preflight_event_addr));
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
        context.preflight_memory_shard_start_ordinal = shard_start >> 2;
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
    fn cache_temporary_names_fit_longest_active_key_component_limit() {
        let cache_dir = Path::new("cache");
        let longest_active_key = "k".repeat(234);
        let (so_path, metadata_path) = cache_paths(cache_dir, &longest_active_key);
        let first = cache_temporary_paths(cache_dir, u32::MAX, u64::MAX - 1);
        let second = cache_temporary_paths(cache_dir, u32::MAX, u64::MAX);

        assert_ne!(first, second);
        for path in [so_path, metadata_path]
            .into_iter()
            .chain(first)
            .chain(second)
        {
            assert!(
                path.file_name().unwrap().as_encoded_bytes().len() <= 255,
                "cache filename component exceeds NAME_MAX: {}",
                path.display()
            );
        }
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
        assert!(conditional.contains("jne ceno_aot_dispatch"));

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
    fn llvm_static_roots_admit_unobserved_blocks_and_change_cache_identity() {
        let base = CENO_PLATFORM.pc_base();
        let mut program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);
        let training_only_key = aot_cache_key(&program, AssemblyTraceStyle::Pure);

        program.static_aot_roots = Some(vec![base, base + 8]);
        let blocks = partition_basic_blocks(&program).unwrap();

        assert_eq!(
            blocks
                .iter()
                .map(|block| block.start_pc)
                .collect::<Vec<_>>(),
            vec![base, base + 4, base + 8, base + 12]
        );
        assert_ne!(
            aot_cache_key(&program, AssemblyTraceStyle::Pure),
            training_only_key
        );
    }

    #[test]
    fn static_preflight_roots_include_metadata_and_all_resume_pcs() {
        let base = CENO_PLATFORM.pc_base();
        let mut program = program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 1, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::INVALID, 0, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
        ]);
        program.static_aot_roots = Some(vec![base, base + 12]);

        assert_eq!(
            static_preflight_roots(&program).unwrap(),
            vec![base, base + 4, base + 8, base + 12]
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
            std::mem::offset_of!(AotRuntimeContext, preflight_pc_before),
            AOT_CTX_PREFLIGHT_PC_BEFORE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pc_after),
            AOT_CTX_PREFLIGHT_PC_AFTER_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_last_kind),
            AOT_CTX_PREFLIGHT_LAST_KIND_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_current_shard_start),
            AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, memory_prev_stamp),
            AOT_CTX_MEMORY_PREV_STAMP_OFFSET
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
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, memory_start_ordinal),
            AOT_CTX_MEMORY_START_ORDINAL_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_bucket_ceilings),
            AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_bucket_generations),
            AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_bucket_generation),
            AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_specialized),
            AOT_CTX_PREFLIGHT_PENDING_SPECIALIZED_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_chips),
            AOT_CTX_PREFLIGHT_PENDING_CHIPS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_deltas),
            AOT_CTX_PREFLIGHT_PENDING_DELTAS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_trace),
            AOT_CTX_PREFLIGHT_PENDING_TRACE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_main),
            AOT_CTX_PREFLIGHT_PENDING_MAIN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_pending_tower),
            AOT_CTX_PREFLIGHT_PENDING_TOWER_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_memory_shard_start_ordinal),
            AOT_CTX_PREFLIGHT_MEMORY_SHARD_START_ORDINAL_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_block_kind_histograms),
            AOT_CTX_PREFLIGHT_BLOCK_KIND_HISTOGRAMS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_block_kind_histogram_count),
            AOT_CTX_PREFLIGHT_BLOCK_KIND_HISTOGRAM_COUNT_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_replay_range_len),
            AOT_CTX_PREFLIGHT_REPLAY_RANGE_LEN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_replay_family_counts),
            AOT_CTX_PREFLIGHT_REPLAY_FAMILY_COUNTS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_replay_fallback_count),
            AOT_CTX_PREFLIGHT_REPLAY_FALLBACK_COUNT_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_replay_unsupported_count),
            AOT_CTX_PREFLIGHT_REPLAY_UNSUPPORTED_COUNT_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, preflight_replay_range_capacity),
            AOT_CTX_PREFLIGHT_REPLAY_RANGE_CAPACITY_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_kinds),
            AOT_CTX_GPU_REPLAY_KINDS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_kind_count),
            AOT_CTX_GPU_REPLAY_KIND_COUNT_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_ordinal),
            AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_pending_cycle),
            AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_latest_cells),
            AOT_CTX_GPU_REPLAY_LATEST_CELLS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_latest_base),
            AOT_CTX_GPU_REPLAY_LATEST_BASE_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_latest_len),
            AOT_CTX_GPU_REPLAY_LATEST_LEN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_max_heap),
            AOT_CTX_GPU_REPLAY_MAX_HEAP_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_max_hint),
            AOT_CTX_GPU_REPLAY_MAX_HINT_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_events),
            AOT_CTX_GPU_REPLAY_EVENTS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_events_len),
            AOT_CTX_GPU_REPLAY_EVENTS_LEN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_event_cursor),
            AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_error),
            AOT_CTX_GPU_REPLAY_ERROR_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_ordinary_callbacks),
            AOT_CTX_GPU_REPLAY_ORDINARY_CALLBACKS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, combined_saved),
            AOT_CTX_COMBINED_SAVED_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, layered_rs1_previous),
            AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, layered_rs2_previous),
            AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, layered_rd_previous),
            AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, compact_bytes_cursor),
            AOT_CTX_COMPACT_BYTES_CURSOR_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, layered_next_access_events),
            AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, layered_next_access_events_len),
            AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_LEN_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, layered_next_access_cursor),
            AOT_CTX_LAYERED_NEXT_ACCESS_CURSOR_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(AotRuntimeContext, gpu_replay_packed_block),
            AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET
        );
    }

    #[test]
    fn next_cost_bucket_ceiling_matches_ceil_log2_transitions() {
        assert_eq!(next_cost_bucket_ceiling(0), 1);
        assert_eq!(next_cost_bucket_ceiling(1), 2);
        assert_eq!(next_cost_bucket_ceiling(2), 3);
        assert_eq!(next_cost_bucket_ceiling(3), 5);
        assert_eq!(next_cost_bucket_ceiling(4), 5);
        assert_eq!(next_cost_bucket_ceiling(5), 9);
    }

    #[test]
    fn invalid_instruction_errors_if_executed() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::INVALID, 0, 0, 0, 0)]));
        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

        let tracer_config = crate::FullTracerConfig {
            max_step_shard: 100,
        };
        let mut interp = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            tracer_config,
        );
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
        let mut aot_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            tracer_config,
        );
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
    fn one_and_many_compile_workers_have_identical_semantics() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 4),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let blocks = partition_basic_blocks(&program).unwrap();
        let layout = pc_order_layout(&blocks);

        let compile = |jobs| {
            let dir = tempfile::tempdir().unwrap();
            let asm = dir.path().join("program.S");
            let so = dir.path().join("program.so");
            compile_native_to_with_jobs(
                &program,
                &blocks,
                &layout.emission_order,
                AssemblyTraceStyle::FullTracerDirect,
                None,
                &asm,
                &so,
                jobs,
            )
            .unwrap();
            let (library, entry) = load_native(&so, "fulltracer-direct", "test").unwrap();
            AotProgram {
                program: program.clone(),
                cache_identity: String::new(),
                artifact_path: None,
                blocks: blocks.clone(),
                layout_profile: layout.clone(),
                _library: library,
                entry,
                compile_load_time: Duration::ZERO,
                trace_style: AssemblyTraceStyle::FullTracerDirect,
                next_access_capacity: 0,
                planner_fingerprint: None,
            }
        };
        let one = compile(1);
        let many = compile(4);
        let config = crate::FullTracerConfig { max_step_shard: 16 };
        let mut one_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config,
        );
        let mut many_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let one_report = one.run_to_halt(&mut one_vm, 32).unwrap();
        let many_report = many.run_to_halt(&mut many_vm, 32).unwrap();

        assert_eq!(one_report.executed_steps, many_report.executed_steps);
        assert_eq!(one_report.fallback, many_report.fallback);
        assert_eq!(one_vm.peek_register(1), many_vm.peek_register(1));
        assert_eq!(
            one_vm.tracer().recorded_steps(),
            many_vm.tracer().recorded_steps()
        );
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
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
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
        let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
        let (aot_plan, aot_next, _) = aot_vm.take_tracer().into_shard_plan();
        assert_eq!(aot_next, interp_next);
        assert_eq!(
            aot_plan.shard_cycle_boundaries(),
            interp_plan.shard_cycle_boundaries()
        );
    }

    #[test]
    fn i049_preflight_capture_emits_exact_typed_ranges_and_sparse_halt() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ADDI, 1, 0, 2, 5),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 64 },
        );
        while reference.next_step_record().unwrap().is_some() {}

        let config = crate::PreflightTracerConfig::new(true, 2, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep))
            .with_replay_range_capacity(2)
            .with_combined_capture(true);
        let aot =
            AotProgram::compile_preflight_capture_with_extra_roots(program.clone(), Vec::new())
                .unwrap();
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let report = aot.run_to_halt(&mut vm, 16).unwrap();
        assert_eq!(report.executed_steps, 4);
        let (ranges, syscalls, patches, initialization) =
            vm.tracer_mut().finish_combined_capture_for_test().unwrap();
        let patch_events = patches
            .iter()
            .map(|patch| {
                crate::NextAccessEvent::new(patch.source_cycle, patch.target_cycle, patch.address)
            })
            .chain(initialization.iter().copied())
            .collect::<Vec<_>>();
        reference
            .tracer_mut()
            .apply_next_access_events_for_test(&patch_events);
        assert_eq!(ranges.len(), 3);
        assert!(ranges.iter().all(|range| {
            range
                .typed
                .iter()
                .flatten()
                .map(crate::GpuTypedSoaArena::len)
                .sum::<usize>()
                + range.fallback.len()
                <= 2
        }));
        let ordinary = ranges
            .iter()
            .flat_map(|range| range.typed.iter().flatten())
            .map(crate::GpuTypedSoaArena::len)
            .sum::<usize>();
        let fallback = ranges
            .iter()
            .map(|range| range.fallback.len())
            .sum::<usize>();
        assert_eq!((ordinary, fallback, syscalls.len()), (3, 1, 0));
        let ordinals = ranges
            .iter()
            .filter_map(|range| range.typed[InsnKind::ADDI as usize].as_ref())
            .flat_map(|arena| arena.fields()[0][..arena.len()].iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(ordinals, [0, 1, 2]);
        assert_eq!(ranges.last().unwrap().fallback[0].ordinal, 3);
        let expected = reference.tracer().recorded_steps();
        for range in ranges {
            for arena in range.typed.iter().flatten() {
                for row in 0..arena.len() {
                    let ordinal = arena.fields()[0][row] as usize;
                    let mut oracle = crate::GpuTypedSoaArena::new(arena.kind(), 1).unwrap();
                    oracle
                        .push_step(ordinal as u32, &expected[ordinal])
                        .unwrap();
                    for (field_index, (actual, expected)) in
                        arena.fields().iter().zip(oracle.fields()).enumerate()
                    {
                        assert_eq!(
                            actual[row],
                            expected[0],
                            "typed word mismatch kind={:?} ordinal={ordinal} field={field_index}",
                            arena.kind()
                        );
                    }
                }
            }
            for fallback in &range.fallback {
                assert_eq!(
                    fallback.record, expected[fallback.ordinal as usize],
                    "sparse record mismatch ordinal={}",
                    fallback.ordinal
                );
            }
        }
    }

    #[test]
    fn i049_preflight_capture_matches_fulltracer_for_memory_and_multishard_reuse() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::SW, 20, 1, 0, 4),
            encode_rv32(InsnKind::LW, 20, 0, 2, 4),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 64 },
        );
        reference.init_register_unsafe(20, base);
        reference.init_memory(ByteAddr(base).waddr(), 37);
        reference.init_memory(ByteAddr(base + 4).waddr(), 0);
        while reference.next_step_record().unwrap().is_some() {}

        let config = crate::PreflightTracerConfig::new(true, 1, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep))
            .with_replay_range_capacity(2)
            .with_combined_capture(true);
        let roots = (1..6)
            .map(|index| CENO_PLATFORM.pc_base() + index * PC_STEP_SIZE as u32)
            .collect();
        let aot =
            AotProgram::compile_preflight_capture_with_extra_roots(program.clone(), roots).unwrap();
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        vm.init_register_unsafe(20, base);
        vm.init_memory(ByteAddr(base).waddr(), 37);
        vm.init_memory(ByteAddr(base + 4).waddr(), 0);
        assert_eq!(aot.run_to_halt(&mut vm, 16).unwrap().executed_steps, 6);
        let (ranges, syscalls, patches, initialization) =
            vm.tracer_mut().finish_combined_capture_for_test().unwrap();
        assert!(syscalls.is_empty());
        assert!(!initialization.is_empty());
        assert!(patches.iter().any(|patch| {
            patch.ram_class == crate::tracer::PatchRamClass::Memory
                && patch.target_shard > patch.source_shard + 1
        }));
        let events = patches
            .iter()
            .map(|patch| {
                crate::NextAccessEvent::new(patch.source_cycle, patch.target_cycle, patch.address)
            })
            .chain(initialization.iter().copied())
            .collect::<Vec<_>>();
        reference
            .tracer_mut()
            .apply_next_access_events_for_test(&events);
        let expected = reference.tracer().recorded_steps();
        for range in ranges {
            for arena in range.typed.iter().flatten() {
                for row in 0..arena.len() {
                    let ordinal = arena.fields()[0][row] as usize;
                    let mut oracle = crate::GpuTypedSoaArena::new(arena.kind(), 1).unwrap();
                    oracle
                        .push_step(ordinal as u32, &expected[ordinal])
                        .unwrap();
                    for (actual, expected) in arena.fields().iter().zip(oracle.fields()) {
                        assert_eq!(actual[row], expected[0]);
                    }
                }
            }
            for fallback in &range.fallback {
                assert_eq!(fallback.record, expected[fallback.ordinal as usize]);
            }
        }
    }

    #[test]
    fn i049_preflight_capture_matches_fulltracer_for_multiop_syscall() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
            crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 64 },
        );
        let config = crate::PreflightTracerConfig::new(true, 1, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep))
            .with_replay_range_capacity(2)
            .with_combined_capture(true);
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config,
        );
        for state in [
            &mut reference as &mut dyn SyscallTestVm,
            &mut vm as &mut dyn SyscallTestVm,
        ] {
            state.init_register(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
            state.init_register(Platform::reg_arg0(), base);
            state.init_register(20, base);
            for (offset, value) in input.into_iter().enumerate() {
                state.init_word(ByteAddr(base).waddr() + offset, value);
            }
        }
        while reference.next_step_record().unwrap().is_some() {}
        let roots = (1..4)
            .map(|index| CENO_PLATFORM.pc_base() + index * PC_STEP_SIZE as u32)
            .collect();
        let aot = AotProgram::compile_preflight_capture_with_extra_roots(program, roots).unwrap();
        assert_eq!(aot.run_to_halt(&mut vm, 16).unwrap().executed_steps, 4);
        let (ranges, syscalls, patches, initialization) =
            vm.tracer_mut().finish_combined_capture_for_test().unwrap();
        let events = patches
            .iter()
            .map(|patch| {
                crate::NextAccessEvent::new(patch.source_cycle, patch.target_cycle, patch.address)
            })
            .chain(initialization.iter().copied())
            .collect::<Vec<_>>();
        reference
            .tracer_mut()
            .apply_next_access_events_for_test(&events);
        assert_eq!(syscalls, reference.tracer().syscall_witnesses());
        let expected = reference.tracer().recorded_steps();
        for fallback in ranges.iter().flat_map(|range| &range.fallback) {
            assert_eq!(fallback.record, expected[fallback.ordinal as usize]);
        }
        assert!(patches.iter().any(|patch| matches!(
            patch.source_lane,
            crate::tracer::PatchSourceLane::SyscallMemory
                | crate::tracer::PatchSourceLane::SyscallRegister
        )));
    }

    trait SyscallTestVm {
        fn init_register(&mut self, index: RegIdx, value: Word);
        fn init_word(&mut self, address: WordAddr, value: Word);
    }

    impl<T: crate::Tracer> SyscallTestVm for VMState<T> {
        fn init_register(&mut self, index: RegIdx, value: Word) {
            self.init_register_unsafe(index, value);
        }

        fn init_word(&mut self, address: WordAddr, value: Word) {
            self.init_memory(address, value);
        }
    }

    #[test]
    fn i049_production_capture_syscalls_match_canonical_raw_next_access_tape() {
        let codes = [267, 268, 270, 65801, 65802, 65840];
        assert_eq!(crate::SECP256K1_DOUBLE, codes[0]);
        assert_eq!(crate::SECP256K1_DECOMPRESS, codes[1]);
        assert_eq!(crate::SECP256K1_SCALAR_INVERT, codes[2]);
        assert_eq!(crate::KECCAK_PERMUTE, codes[3]);
        assert_eq!(crate::SECP256K1_ADD, codes[4]);
        assert_eq!(crate::KECCAK_XORIN, codes[5]);

        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let roots = (1..4)
            .map(|index| CENO_PLATFORM.pc_base() + index * PC_STEP_SIZE as u32)
            .collect::<Vec<_>>();
        let production =
            AotProgram::compile_preflight_with_extra_roots(program.clone(), roots.clone()).unwrap();
        let capture =
            AotProgram::compile_preflight_capture_with_extra_roots(program.clone(), roots).unwrap();
        let generator: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
            crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();
        let doubled = crate::syscalls::secp256k1::double_words(generator);

        for code in codes {
            let first = CENO_PLATFORM.heap.start;
            let second = first + 256;
            let arg1 = if code == crate::SECP256K1_DECOMPRESS {
                0
            } else {
                second
            };
            let config = crate::PreflightTracerConfig::new(true, 1, Cycle::MAX)
                .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
            let mut expected = VMState::<crate::PreflightTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                config.clone(),
            );
            let mut actual = VMState::<crate::PreflightTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                config.with_combined_capture(true),
            );
            let mut first_words = [0; 64];
            let mut second_words = [0; 64];
            match code {
                crate::SECP256K1_DOUBLE | crate::SECP256K1_ADD => {
                    first_words[..generator.len()].copy_from_slice(&generator);
                    second_words[..doubled.len()].copy_from_slice(&doubled);
                }
                crate::SECP256K1_DECOMPRESS => {
                    let encoded = secp::Point::generator().serialize_uncompressed();
                    let x: [u8; 32] = encoded[1..33].try_into().unwrap();
                    let x: [Word; crate::syscalls::secp256k1::COORDINATE_WORDS] =
                        unsafe { std::mem::transmute(x) };
                    first_words[..x.len()].copy_from_slice(&x);
                }
                crate::SECP256K1_SCALAR_INVERT => {
                    first_words[..crate::syscalls::secp256k1::COORDINATE_WORDS].fill(1);
                }
                _ => {
                    for (offset, (first, second)) in
                        first_words.iter_mut().zip(&mut second_words).enumerate()
                    {
                        *first = offset as Word;
                        *second = !*first;
                    }
                }
            }
            for vm in [&mut expected, &mut actual] {
                vm.init_register_unsafe(Platform::reg_ecall(), code);
                vm.init_register_unsafe(Platform::reg_arg0(), first);
                vm.init_register_unsafe(Platform::reg_arg1(), arg1);
                for offset in 0usize..64 {
                    vm.init_memory(ByteAddr(first).waddr() + offset, first_words[offset]);
                    vm.init_memory(ByteAddr(second).waddr() + offset, second_words[offset]);
                }
            }

            let expected_report = production.run_to_halt(&mut expected, 16).unwrap();
            let actual_report = capture.run_to_halt(&mut actual, 16).unwrap();
            assert_eq!(expected_report.executed_steps, 4, "code={code}");
            assert_eq!(actual_report.executed_steps, 4, "code={code}");
            assert_eq!(
                expected_report.fallback.ecall_by_code[&code], 2,
                "code={code}"
            );
            assert_eq!(
                actual_report.fallback.ecall_by_code[&code], 2,
                "code={code}"
            );
            let expected_events = expected.tracer().raw_next_access_events_for_test().to_vec();
            let actual_events = actual.tracer().raw_next_access_events_for_test().to_vec();
            assert_eq!(
                actual_events, expected_events,
                "raw tape differs for code={code}"
            );
            let (expected_plan, _, _) = expected.take_tracer().into_shard_plan();
            let (actual_plan, _, _) = actual.take_tracer().into_shard_plan();
            assert_eq!(
                actual_plan.shard_cycle_boundaries(),
                expected_plan.shard_cycle_boundaries(),
                "shard boundaries differ for code={code}",
            );
        }
    }

    #[test]
    fn aot_preflight_direct_syscall_matches_generic_tracking() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, 64, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
            crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();

        let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        let mut direct = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config,
        );
        for vm in [&mut interp, &mut direct] {
            vm.init_register_unsafe(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
            vm.init_register_unsafe(Platform::reg_arg0(), base);
            for (offset, value) in input.into_iter().enumerate() {
                vm.init_memory(ByteAddr(base).waddr() + offset, value);
            }
        }
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile_preflight_with_extra_roots(program, Vec::new()).unwrap();
        let report = aot.run_to_halt(&mut direct, 64).unwrap();
        assert_eq!(report.executed_steps, 3);
        assert_eq!(report.fallback.ecall_by_code[&crate::SECP256K1_DOUBLE], 1);
        for offset in 0..crate::syscalls::secp256k1::SECP256K1_ARG_WORDS {
            let addr = ByteAddr(base).waddr() + offset;
            assert_eq!(direct.peek_memory(addr), interp.peek_memory(addr));
            assert_eq!(
                direct.final_access_cycle(addr),
                interp.final_access_cycle(addr)
            );
        }
        assert_eq!(direct.final_access_count(), interp.final_access_count());
        for addr in interp.final_access_addresses() {
            assert_eq!(
                direct.final_access_cycle(addr),
                interp.final_access_cycle(addr)
            );
        }
        let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
        let (direct_plan, direct_next, _) = direct.take_tracer().into_shard_plan();
        assert_eq!(direct_next, interp_next);
        assert_eq!(
            direct_plan.shard_cycle_boundaries(),
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
            ecalls.insert(crate::SECP256K1_DOUBLE, vec![0]);
            ecalls.insert(crate::SECP256K1_ADD, vec![0]);
            ecalls.insert(crate::SECP256K1_DECOMPRESS, vec![0]);
            ecalls.insert(crate::KECCAK_PERMUTE, vec![0]);
            ecalls.insert(crate::KECCAK_XORIN, vec![0]);
            ecalls.insert(crate::SECP256K1_SCALAR_INVERT, vec![0]);
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
    fn pure_and_full_paths_match_guest_state() {
        let base = CENO_PLATFORM.stack.start + 64;
        let memory_addr = ByteAddr(base).waddr();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
            encode_rv32(InsnKind::SW, 20, 2, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let full_aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
        let mut full = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 5 },
        );
        full.init_register_unsafe(20, base);
        full.init_memory(memory_addr, 0);
        let full_report = full_aot.run_to_halt(&mut full, 16).unwrap();

        let pure_aot = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::Pure,
        )
        .unwrap();
        let mut pure = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        pure.init_register_unsafe(20, base);
        pure.init_memory(memory_addr, 0);
        let pure_report = pure_aot.run_pure_to_halt(&mut pure, 16).unwrap();

        assert_eq!(full_report.executed_steps, 5);
        assert_eq!(pure_report.executed_steps, full_report.executed_steps);
        assert_eq!(
            pure.halted_state().map(|state| state.exit_code),
            full.halted_state().map(|state| state.exit_code)
        );
        assert_eq!(pure.get_pc(), full.get_pc());
        for register in [1, 2, 3, 20] {
            assert_eq!(pure.peek_register(register), full.peek_register(register));
        }
        assert_eq!(pure.peek_memory(memory_addr), 14);
        assert_eq!(pure.peek_memory(memory_addr), full.peek_memory(memory_addr));
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
            [(ByteAddr(CENO_PLATFORM.heap.start).waddr(), 0x1234)],
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
        for addr in cold_vm.final_access_addresses() {
            assert_eq!(
                cold_vm.final_access_cycle(addr),
                warm_vm.final_access_cycle(addr)
            );
        }
        let (cold_plan, cold_next, _) = cold_vm.take_tracer().into_shard_plan();
        let (warm_plan, warm_next, _) = warm_vm.take_tracer().into_shard_plan();
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
            planner_cache_key(
                &program,
                production_preflight_trace_style(),
                &config
                    .step_cell_extractor()
                    .and_then(|extractor| extractor.shard_cost_model())
                    .unwrap(),
            ),
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
    fn specialized_planner_matches_generic_finite_cell_shards() {
        let cache = tempfile::tempdir().unwrap();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 8),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, 4, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let generic_aot =
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
        let mut generic = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        let generic_report = generic_aot.run_to_halt(&mut generic, 64).unwrap();

        let aot = AotProgram::load_or_train_preflight_in(
            &CENO_PLATFORM,
            program.clone(),
            [],
            config.clone(),
            cache.path(),
        )
        .unwrap();
        let mut direct = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let report = aot.run_to_halt(&mut direct, 64).unwrap();
        assert_eq!(report.fallback, generic_report.fallback);
        let (generic_plan, generic_next, _) = generic.take_tracer().into_shard_plan();
        let (direct_plan, direct_next, _) = direct.take_tracer().into_shard_plan();
        assert_eq!(
            direct_plan.shard_cycle_boundaries(),
            generic_plan.shard_cycle_boundaries()
        );
        assert_eq!(
            direct_plan.predicted_shard_costs(),
            generic_plan.predicted_shard_costs()
        );
        assert_eq!(direct_next, generic_next);
    }

    #[test]
    fn unseen_later_indirect_target_uses_dynamic_pc_fallback() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), vec![base + 4])
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
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let report = aot.run_to_halt(&mut vm, 100).unwrap();
        let (plan, _, _) = vm.take_tracer().into_shard_plan();
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
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
        let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        aot.run_to_halt(&mut vm, 100).unwrap();
        let (plan, _, _) = vm.take_tracer().into_shard_plan();
        assert_eq!(plan.shard_cycle_boundaries(), &[4, 16, 28, 32]);
        assert_eq!(plan.predicted_shard_costs(), &[7, 19, 1]);
    }

    #[test]
    fn preflight_block_aot_requires_shard_cost_model() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::ADDI, 0, 0, 1, 1)]));
        let aot =
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
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
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
        assert_eq!(aot.trace_style, production_preflight_trace_style());
        let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
        assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
        assert_eq!(aot_vm.final_access_count(), interp.final_access_count());
        for addr in interp.final_access_addresses() {
            assert_eq!(
                aot_vm.final_access_cycle(addr),
                interp.final_access_cycle(addr),
                "final access mismatch at {addr:?}"
            );
        }

        let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
        let (aot_plan, aot_next, _) = aot_vm.take_tracer().into_shard_plan();
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
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
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

        let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
        let (aot_plan, aot_next, _) = aot_vm.take_tracer().into_shard_plan();
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
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
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
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

        let tracer_config = crate::FullTracerConfig {
            max_step_shard: 100,
        };
        let mut interp = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            tracer_config,
        );
        interp.init_register_unsafe(20, base);
        interp.init_memory(ByteAddr(base).waddr(), 37);
        interp.init_memory(ByteAddr(base + 4).waddr(), 0);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
        let mut aot_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            tracer_config,
        );
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

        let aot = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::Pure,
        )
        .unwrap();
        let mut aot_vm = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
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
        assert_eq!(aot_vm.final_access_cycle(ByteAddr(base).waddr()), 0);
        assert_eq!(report.fallback_steps, 1);
        assert_eq!(
            report.execute_time,
            report.native_time() + report.fallback_time
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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
        let lw_aot = AotProgram::compile_fulltracer(lw_program.clone()).unwrap();
        let mut lw_vm = VMState::new(CENO_PLATFORM.clone(), lw_program);
        lw_vm.init_register_unsafe(20, base);
        let err = lw_aot.run_to_halt(&mut lw_vm, 1).unwrap_err().to_string();
        assert!(err.contains("LoadAddressMisaligned"));

        let lh_program = Arc::new(program(vec![encode_rv32(InsnKind::LH, 20, 0, 1, 1)]));
        let lh_aot = AotProgram::compile_fulltracer(lh_program.clone()).unwrap();
        let mut lh_vm = VMState::new(CENO_PLATFORM.clone(), lh_program);
        lh_vm.init_register_unsafe(20, base);
        let err = lh_aot.run_to_halt(&mut lh_vm, 1).unwrap_err().to_string();
        assert!(err.contains("LoadAddressMisaligned"));

        let sw_program = Arc::new(program(vec![encode_rv32(InsnKind::SW, 20, 1, 0, 1)]));
        let sw_aot = AotProgram::compile_fulltracer(sw_program.clone()).unwrap();
        let mut sw_vm = VMState::new(CENO_PLATFORM.clone(), sw_program);
        sw_vm.init_register_unsafe(20, base);
        sw_vm.init_register_unsafe(1, 42);
        let err = sw_aot.run_to_halt(&mut sw_vm, 1).unwrap_err().to_string();
        assert!(err.contains("StoreAddressMisaligned"));

        let sh_program = Arc::new(program(vec![encode_rv32(InsnKind::SH, 20, 1, 0, 1)]));
        let sh_aot = AotProgram::compile_fulltracer(sh_program.clone()).unwrap();
        let mut sh_vm = VMState::new(CENO_PLATFORM.clone(), sh_program);
        sh_vm.init_register_unsafe(20, base);
        sh_vm.init_register_unsafe(1, 42);
        let err = sh_aot.run_to_halt(&mut sh_vm, 1).unwrap_err().to_string();
        assert!(err.contains("StoreAddressMisaligned"));
    }

    #[test]
    fn aot_memory_access_faults_use_exact_slow_path_traps() {
        let lb_program = Arc::new(program(vec![encode_rv32(InsnKind::LB, 20, 0, 1, 0)]));
        let lb_aot = AotProgram::compile_fulltracer(lb_program.clone()).unwrap();
        let mut lb_vm = VMState::new(CENO_PLATFORM.clone(), lb_program);
        lb_vm.init_register_unsafe(20, 0);
        let err = lb_aot.run_to_halt(&mut lb_vm, 1).unwrap_err().to_string();
        assert!(err.contains("LoadAccessFault"));

        let sb_program = Arc::new(program(vec![encode_rv32(InsnKind::SB, 20, 1, 0, 0)]));
        let sb_aot = AotProgram::compile_fulltracer(sb_program.clone()).unwrap();
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
        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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
    fn aot_pure_block_plan_respects_limit_inside_block() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let aot = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::Pure,
        )
        .unwrap();
        let mut vm = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);

        let report = aot.run_pure_to_halt(&mut vm, 2).unwrap();

        assert_eq!(report.executed_steps, 2);
        assert!(!vm.halted());
        assert_eq!(vm.get_pc().0, base + 8);
        assert_eq!(vm.peek_register(1), 2);
    }

    #[test]
    fn preflight_pure_l0_matches_production_state_counts_and_exit() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_arg0().into(), 7),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let production =
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
        let l0 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightPureL0,
        )
        .unwrap();
        let mut expected = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config,
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        expected.init_register_unsafe(20, base);
        expected.init_memory(ByteAddr(base).waddr(), 0);
        actual.init_register_unsafe(20, base);
        actual.init_memory(ByteAddr(base).waddr(), 0);

        let expected_report = production.run_to_halt(&mut expected, 64).unwrap();
        let actual_report = l0.run_pure_to_halt(&mut actual, 64).unwrap();

        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(
            (actual_report.executed_steps as Cycle + 1) * PureAotTracer::SUBCYCLES_PER_INSN,
            expected.tracer().cycle()
        );
        assert_eq!(actual.get_pc(), expected.get_pc());
        assert_eq!(
            actual.halted_state().map(|state| state.exit_code),
            expected.halted_state().map(|state| state.exit_code)
        );
        for idx in 0..VMState::<PureAotTracer>::REG_COUNT as RegIdx {
            assert_eq!(actual.peek_register(idx), expected.peek_register(idx));
        }
        assert_eq!(actual.peek_memory(ByteAddr(base).waddr()), 1);
        assert_eq!(
            actual.peek_memory(ByteAddr(base).waddr()),
            expected.peek_memory(ByteAddr(base).waddr())
        );
        assert_eq!(actual_report.next_access_events, 0);
        assert_eq!(actual_report.next_access_capacity, 0);
        assert_eq!(actual_report.next_access_growths, 0);
        assert_eq!(actual_report.next_access_growth_bytes, 0);
    }

    #[test]
    fn preflight_pure_l0_matches_production_trap() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
        let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let production =
            AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
        let l0 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightPureL0,
        )
        .unwrap();
        let mut expected = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config,
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        expected.init_register_unsafe(20, base);
        actual.init_register_unsafe(20, base);

        let expected_err = production
            .run_to_halt(&mut expected, 1)
            .unwrap_err()
            .to_string();
        let actual_err = l0.run_pure_to_halt(&mut actual, 1).unwrap_err().to_string();

        assert!(expected_err.contains("LoadAddressMisaligned"));
        assert!(actual_err.contains("LoadAddressMisaligned"));
        assert_eq!(actual.get_pc(), expected.get_pc());
        for idx in 0..VMState::<PureAotTracer>::REG_COUNT as RegIdx {
            assert_eq!(actual.peek_register(idx), expected.peek_register(idx));
        }
    }

    #[test]
    fn preflight_pure_l0_stops_at_direct_successor_boundary() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JAL, 0, 0, 0, 4),
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 9),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let l0 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightPureL0,
        )
        .unwrap();
        let mut vm = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);

        let first = l0.run_pure_to_halt(&mut vm, 1).unwrap();
        assert_eq!(first.executed_steps, 1);
        assert_eq!(vm.get_pc().0, base + 4);
        assert_eq!(vm.peek_register(1), 0);

        let second = l0.run_pure_to_halt(&mut vm, 1).unwrap();
        assert_eq!(second.executed_steps, 1);
        assert_eq!(vm.peek_register(1), 9);
    }

    #[test]
    fn preflight_pure_l0_assembly_has_no_record_or_planner_work() {
        assert_eq!(
            AssemblyTraceStyle::PreflightPureL0.cache_name(),
            "preflight-pure-l0-schema3"
        );
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l0.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightPureL0,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();

        assert!(assembly.contains("ceno_aot_bb_"));
        assert!(!assembly.contains("preflight_bucket"));
        assert!(!assembly.contains("preflight_plan"));
        assert!(!assembly.contains("ceno_aot_fulltracer_emit_step"));
        assert!(!assembly.contains("ceno_aot_gpu_replay_emit_step"));
        assert!(!assembly.contains("FULLTRACER_ACCESS"));
    }

    fn assert_layered_skeleton_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
        assert_eq!(actual.cycle(), reference.cycle());
        assert_eq!(actual.pc(), reference.pc());
        assert_eq!(actual.insn(), reference.insn());
        assert_eq!(
            actual.rs1().map(|op| op.addr),
            reference.rs1().map(|op| op.addr)
        );
        assert_eq!(
            actual.rs2().map(|op| op.addr),
            reference.rs2().map(|op| op.addr)
        );
        assert_eq!(
            actual.rd().map(|op| op.addr),
            reference.rd().map(|op| op.addr)
        );
        assert_eq!(
            actual.memory_op().map(|op| op.addr),
            reference.memory_op().map(|op| op.addr)
        );
    }

    fn assert_l1_skeleton_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
        assert_layered_skeleton_matches(reference, actual);
        assert!(actual.l1_disabled_fields_are_poisoned());
    }

    fn assert_l2_values_match(reference: &crate::StepRecord, actual: &crate::StepRecord) {
        assert_layered_skeleton_matches(reference, actual);
        assert_eq!(
            actual.rs1().map(|op| op.value),
            reference.rs1().map(|op| op.value)
        );
        assert_eq!(
            actual.rs2().map(|op| op.value),
            reference.rs2().map(|op| op.value)
        );
        assert_eq!(
            actual.rd().map(|op| op.value),
            reference.rd().map(|op| op.value)
        );
        assert_eq!(
            actual.memory_op().map(|op| op.value),
            reference.memory_op().map(|op| op.value)
        );
        assert!(actual.l2_later_fields_are_poisoned());
    }

    fn assert_l3_registers_match(reference: &crate::StepRecord, actual: &crate::StepRecord) {
        assert_layered_skeleton_matches(reference, actual);
        assert_eq!(
            actual.rs1().map(|op| op.value),
            reference.rs1().map(|op| op.value)
        );
        assert_eq!(
            actual.rs2().map(|op| op.value),
            reference.rs2().map(|op| op.value)
        );
        assert_eq!(
            actual.rd().map(|op| op.value),
            reference.rd().map(|op| op.value)
        );
        assert_eq!(
            actual.memory_op().map(|op| op.value),
            reference.memory_op().map(|op| op.value)
        );
        assert_eq!(
            actual.rs1().map(|op| op.previous_cycle),
            reference.rs1().map(|op| op.previous_cycle)
        );
        assert_eq!(
            actual.rs2().map(|op| op.previous_cycle),
            reference.rs2().map(|op| op.previous_cycle)
        );
        assert_eq!(
            actual.rd().map(|op| op.previous_cycle),
            reference.rd().map(|op| op.previous_cycle)
        );
        assert!(actual.l3_later_fields_are_poisoned());
    }

    fn assert_l4_memory_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
        assert_layered_skeleton_matches(reference, actual);
        assert_eq!(actual.rs1(), reference.rs1());
        assert_eq!(actual.rs2(), reference.rs2());
        assert_eq!(actual.rd(), reference.rd());
        assert_eq!(actual.memory_op(), reference.memory_op());
        assert_eq!(actual.heap_maxtouch_addr, reference.heap_maxtouch_addr);
        assert_eq!(actual.hint_maxtouch_addr, reference.hint_maxtouch_addr);
        assert!(actual.l4_later_fields_are_poisoned());
    }

    fn assert_l5_future_access_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
        assert_layered_skeleton_matches(reference, actual);
        assert_eq!(actual.rs1(), reference.rs1());
        assert_eq!(actual.rs2(), reference.rs2());
        assert_eq!(actual.rd(), reference.rd());
        assert_eq!(actual.memory_op(), reference.memory_op());
        assert_eq!(actual.heap_maxtouch_addr, reference.heap_maxtouch_addr);
        assert_eq!(actual.hint_maxtouch_addr, reference.hint_maxtouch_addr);
        assert_eq!(actual.future_access_mask(), reference.future_access_mask());
        assert!(actual.l5_later_fields_are_poisoned());
    }

    #[test]
    fn preflight_skeleton_l1_matches_direct_fields_and_poison_across_boundaries() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -20),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l1 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightSkeletonL1,
        )
        .unwrap();

        for capacity in [1, 2, 4, 5, 6, 7, 17, 31] {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig {
                    max_step_shard: capacity,
                },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            reference.init_register_unsafe(20, base);
            reference.init_memory(ByteAddr(base).waddr(), 0);
            actual.init_register_unsafe(20, base);
            actual.init_memory(ByteAddr(base).waddr(), 0);

            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            let actual_report = l1.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
            for (expected, actual) in reference
                .tracer()
                .recorded_steps()
                .iter()
                .zip(&actual_report.l1_skeleton_records)
            {
                assert_l1_skeleton_matches(expected, actual);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(base).waddr()),
                reference.peek_memory(ByteAddr(base).waddr())
            );
        }
    }

    #[test]
    fn preflight_skeleton_l1_assembly_reserves_blocks_and_has_no_tracking() {
        assert_eq!(
            AssemblyTraceStyle::PreflightSkeletonL1.cache_name(),
            "preflight-skeleton-l1-schema1"
        );
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l1.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightSkeletonL1,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();
        assert!(assembly.contains("ceno_aot_skeleton_l1_emit_step"));
        assert!(assembly.contains(&format!("movq {AOT_CTX_FULLTRACER_LEN_OFFSET}(%r12), %rcx")));
        assert!(!assembly.contains("preflight_bucket"));
        assert!(!assembly.contains("preflight_plan"));
        assert!(!assembly.contains("FULLTRACER_ACCESS"));
    }

    #[test]
    fn preflight_compact_skeleton_l1c_matches_l1_and_uses_forward_stores() {
        assert_eq!(
            AssemblyTraceStyle::PreflightCompactSkeletonL1C.cache_name(),
            "preflight-compact-skeleton-l1c-schema1"
        );
        assert_eq!(std::mem::size_of::<CompactSkeletonRecord>(), 16);

        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -20),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactSkeletonL1C,
        )
        .unwrap();

        for capacity in [1, 2, 4, 5, 6, 7, 17, 31] {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig {
                    max_step_shard: capacity,
                },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            reference.init_register_unsafe(20, base);
            reference.init_memory(ByteAddr(base).waddr(), 0);
            actual.init_register_unsafe(20, base);
            actual.init_memory(ByteAddr(base).waddr(), 0);

            direct.run_to_halt(&mut reference, capacity).unwrap();
            let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(report.l1_skeleton_records.len(), capacity);
            for (expected, decoded) in reference
                .tracer()
                .recorded_steps()
                .iter()
                .zip(&report.l1_skeleton_records)
            {
                assert_l1_skeleton_matches(expected, decoded);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(base).waddr()),
                reference.peek_memory(ByteAddr(base).waddr())
            );
        }

        let syscall_program = Arc::new(self::program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let syscall_l1 = AotProgram::compile_with_extra_roots_and_trace_style(
            syscall_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightSkeletonL1,
        )
        .unwrap();
        let syscall_compact = AotProgram::compile_with_extra_roots_and_trace_style(
            syscall_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactSkeletonL1C,
        )
        .unwrap();
        let mut syscall_reference = VMState::<PureAotTracer>::new_with_tracer(
            CENO_PLATFORM.clone(),
            syscall_program.clone(),
        );
        let mut syscall_actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program);
        let syscall_l1_report = syscall_l1
            .run_pure_to_halt(&mut syscall_reference, 2)
            .unwrap();
        let syscall_report = syscall_compact
            .run_pure_to_halt(&mut syscall_actual, 2)
            .unwrap();
        assert_eq!(syscall_report.fallback_steps, 1);
        for (expected, decoded) in syscall_l1_report
            .l1_skeleton_records
            .iter()
            .zip(&syscall_report.l1_skeleton_records)
        {
            assert_l1_skeleton_matches(expected, decoded);
        }

        let trap_program = Arc::new(self::program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
        let trap_compact = AotProgram::compile_with_extra_roots_and_trace_style(
            trap_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactSkeletonL1C,
        )
        .unwrap();
        let mut trap_vm =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
        trap_vm.init_register_unsafe(20, base);
        let trap = trap_compact
            .run_pure_to_halt(&mut trap_vm, 1)
            .unwrap_err()
            .to_string();
        assert!(trap.contains("LoadAddressMisaligned"));

        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l1c.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactSkeletonL1C,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();
        let recorder = assembly
            .split("ceno_aot_compact_skeleton_l1c_emit_step:\n")
            .nth(1)
            .unwrap()
            .split("    ret\n")
            .next()
            .unwrap();
        let stores = recorder
            .lines()
            .filter(|line| line.contains("(%r10)"))
            .collect::<Vec<_>>();
        assert_eq!(
            stores,
            [
                "    movl %ecx, 0(%r10)",
                "    movl %edx, 4(%r10)",
                "    movl %edx, 8(%r10)",
                "    movl %eax, 12(%r10)",
            ]
        );
        assert!(!recorder.contains("0xa5a5"));
        assert!(!recorder.contains("$136"));
        assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
    }

    #[test]
    fn preflight_values_l2_matches_direct_values_and_poison_across_boundaries() {
        assert_eq!(
            AssemblyTraceStyle::PreflightValuesL2.cache_name(),
            "preflight-values-l2-schema1"
        );
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l2 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightValuesL2,
        )
        .unwrap();

        for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig {
                    max_step_shard: capacity,
                },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            reference.init_register_unsafe(20, base);
            reference.init_memory(ByteAddr(base).waddr(), 0);
            actual.init_register_unsafe(20, base);
            actual.init_memory(ByteAddr(base).waddr(), 0);

            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            let actual_report = l2.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
            for (expected, actual) in reference
                .tracer()
                .recorded_steps()
                .iter()
                .zip(&actual_report.l1_skeleton_records)
            {
                assert_l2_values_match(expected, actual);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(0), 0);
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(base).waddr()),
                reference.peek_memory(ByteAddr(base).waddr())
            );
        }
    }

    #[test]
    fn preflight_compact_values_l2c_matches_l2_and_uses_forward_family_stores() {
        assert_eq!(
            AssemblyTraceStyle::PreflightCompactValuesL2C.cache_name(),
            "preflight-compact-values-l2c-schema1"
        );
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactValuesL2C,
        )
        .unwrap();

        for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig {
                    max_step_shard: capacity,
                },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            reference.init_register_unsafe(20, base);
            reference.init_memory(ByteAddr(base).waddr(), 0x8877_6655);
            actual.init_register_unsafe(20, base);
            actual.init_memory(ByteAddr(base).waddr(), 0x8877_6655);

            direct.run_to_halt(&mut reference, capacity).unwrap();
            let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(report.l1_skeleton_records.len(), capacity);
            assert!(report.compact_bytes_written >= capacity * 16);
            assert!(report.compact_bytes_written <= capacity * COMPACT_VALUES_MAX_BYTES);
            for (expected, decoded) in reference
                .tracer()
                .recorded_steps()
                .iter()
                .zip(&report.l1_skeleton_records)
            {
                assert_l2_values_match(expected, decoded);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(0), 0);
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(base).waddr()),
                reference.peek_memory(ByteAddr(base).waddr())
            );
        }

        let syscall_program = Arc::new(self::program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let syscall_l2 = AotProgram::compile_with_extra_roots_and_trace_style(
            syscall_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightValuesL2,
        )
        .unwrap();
        let syscall_compact = AotProgram::compile_with_extra_roots_and_trace_style(
            syscall_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactValuesL2C,
        )
        .unwrap();
        let mut syscall_reference = VMState::<PureAotTracer>::new_with_tracer(
            CENO_PLATFORM.clone(),
            syscall_program.clone(),
        );
        let mut syscall_actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program);
        let expected = syscall_l2
            .run_pure_to_halt(&mut syscall_reference, 2)
            .unwrap();
        let actual = syscall_compact
            .run_pure_to_halt(&mut syscall_actual, 2)
            .unwrap();
        assert_eq!(actual.fallback_steps, 1);
        for (expected, decoded) in expected
            .l1_skeleton_records
            .iter()
            .zip(&actual.l1_skeleton_records)
        {
            assert_l2_values_match(expected, decoded);
        }

        let trap_program = Arc::new(self::program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
        let trap_compact = AotProgram::compile_with_extra_roots_and_trace_style(
            trap_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactValuesL2C,
        )
        .unwrap();
        let mut trap_vm =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
        trap_vm.init_register_unsafe(20, base);
        assert!(
            trap_compact
                .run_pure_to_halt(&mut trap_vm, 1)
                .unwrap_err()
                .to_string()
                .contains("LoadAddressMisaligned")
        );

        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l2c.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactValuesL2C,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();
        let recorder = assembly
            .split("ceno_aot_compact_values_l2c_emit_step:\n")
            .nth(1)
            .unwrap()
            .split("    ret\n")
            .next()
            .unwrap();
        for line in recorder.lines().filter(|line| line.contains("(%r10)")) {
            assert!(
                line.trim_start().starts_with("movl %"),
                "destination load/RMW: {line}"
            );
        }
        for family in ["r", "i", "branch", "j", "load", "store"] {
            let body = recorder
                .split(&format!(".L_compact_values_l2c_{family}:\n"))
                .nth(1)
                .unwrap()
                .split("    jmp .L_compact_values_l2c_commit")
                .next()
                .unwrap();
            let offsets = body
                .lines()
                .filter_map(|line| line.split_once("(%r10)").map(|(prefix, _)| prefix))
                .filter_map(|prefix| prefix.split_whitespace().last())
                .map(|offset| offset.trim_end_matches(',').parse::<usize>().unwrap())
                .collect::<Vec<_>>();
            assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
        }
        assert!(!recorder.contains("0xa5a5"));
        assert!(!recorder.contains("$136"));
        assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
    }

    #[test]
    fn preflight_compact_values_l2c_executes_derived_value_edge_cases_and_resume() {
        let m_program = Arc::new(program(vec![
            encode_rv32(InsnKind::MUL, 1, 2, 5, 0),
            encode_rv32(InsnKind::MULH, 1, 2, 6, 0),
            encode_rv32(InsnKind::MULHSU, 1, 2, 7, 0),
            encode_rv32(InsnKind::MULHU, 1, 2, 8, 0),
            encode_rv32(InsnKind::DIV, 1, 2, 9, 0),
            encode_rv32(InsnKind::DIVU, 1, 2, 10, 0),
            encode_rv32(InsnKind::REM, 1, 2, 11, 0),
            encode_rv32(InsnKind::REMU, 1, 2, 12, 0),
            encode_rv32(InsnKind::DIV, 1, 4, 13, 0),
            encode_rv32(InsnKind::DIVU, 1, 4, 14, 0),
            encode_rv32(InsnKind::REM, 1, 4, 15, 0),
            encode_rv32(InsnKind::REMU, 1, 4, 16, 0),
        ]));
        let m_direct = AotProgram::compile_with_extra_roots_and_trace_style(
            m_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let m_compact = AotProgram::compile_with_extra_roots_and_trace_style(
            m_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactValuesL2C,
        )
        .unwrap();
        let mut m_reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            m_program.clone(),
            crate::FullTracerConfig { max_step_shard: 32 },
        );
        let mut m_actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), m_program);
        m_reference.init_register_unsafe(1, i32::MIN as u32);
        m_reference.init_register_unsafe(2, u32::MAX);
        m_reference.init_register_unsafe(4, 0);
        m_actual.init_register_unsafe(1, i32::MIN as u32);
        m_actual.init_register_unsafe(2, u32::MAX);
        m_actual.init_register_unsafe(4, 0);
        m_direct.run_to_halt(&mut m_reference, 12).unwrap();
        let m_report = m_compact.run_pure_to_halt(&mut m_actual, 12).unwrap();
        for (expected, decoded) in m_reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&m_report.l1_skeleton_records)
        {
            assert_l2_values_match(expected, decoded);
        }

        let pc_base = CENO_PLATFORM.pc_base();
        let jalr_program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 5, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
            encode_rv32(InsnKind::JALR, 2, 0, 6, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 8, 7),
        ]));
        let jalr_direct = AotProgram::compile_with_extra_roots_and_trace_style(
            jalr_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let jalr_compact = AotProgram::compile_with_extra_roots_and_trace_style(
            jalr_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactValuesL2C,
        )
        .unwrap();
        let mut jalr_reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            jalr_program.clone(),
            crate::FullTracerConfig { max_step_shard: 8 },
        );
        let mut jalr_actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), jalr_program);
        jalr_reference.init_register_unsafe(1, pc_base + 8);
        jalr_reference.init_register_unsafe(2, pc_base + 12);
        jalr_reference.init_register_unsafe(5, 0x1111_1111);
        jalr_reference.init_register_unsafe(6, 0x2222_2222);
        jalr_actual.init_register_unsafe(1, pc_base + 8);
        jalr_actual.init_register_unsafe(2, pc_base + 12);
        jalr_actual.init_register_unsafe(5, 0x1111_1111);
        jalr_actual.init_register_unsafe(6, 0x2222_2222);
        jalr_direct.run_to_halt(&mut jalr_reference, 3).unwrap();
        let jalr_report = jalr_compact.run_pure_to_halt(&mut jalr_actual, 3).unwrap();
        assert!(jalr_report.fallback.dynamic_pc_miss > 0);
        for (expected, decoded) in jalr_reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&jalr_report.l1_skeleton_records)
        {
            assert_l2_values_match(expected, decoded);
        }

        let heap = CENO_PLATFORM.heap.start;
        let subword_program = Arc::new(program(vec![
            encode_rv32(InsnKind::LB, 20, 0, 1, 2),
            encode_rv32(InsnKind::LBU, 20, 0, 2, 3),
            encode_rv32(InsnKind::LH, 20, 0, 3, 2),
            encode_rv32(InsnKind::LHU, 20, 0, 4, 0),
            encode_rv32(InsnKind::SB, 20, 5, 0, 1),
            encode_rv32(InsnKind::SH, 20, 6, 0, 2),
            encode_rv32(InsnKind::LW, 20, 0, 7, 0),
        ]));
        let subword_direct = AotProgram::compile_with_extra_roots_and_trace_style(
            subword_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let subword_compact = AotProgram::compile_with_extra_roots_and_trace_style(
            subword_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactValuesL2C,
        )
        .unwrap();
        let mut subword_reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            subword_program.clone(),
            crate::FullTracerConfig { max_step_shard: 32 },
        );
        let mut subword_actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), subword_program);
        subword_reference.init_register_unsafe(20, heap);
        subword_reference.init_register_unsafe(5, 0xaa);
        subword_reference.init_register_unsafe(6, 0xbbcc);
        subword_reference.init_memory(ByteAddr(heap).waddr(), 0x80ff_7f01);
        subword_actual.init_register_unsafe(20, heap);
        subword_actual.init_register_unsafe(5, 0xaa);
        subword_actual.init_register_unsafe(6, 0xbbcc);
        subword_actual.init_memory(ByteAddr(heap).waddr(), 0x80ff_7f01);
        for capacity in [1, 2, 1, 3] {
            let expected_start = subword_reference.tracer().recorded_steps().len();
            let expected_report = subword_direct
                .run_to_halt(&mut subword_reference, capacity)
                .unwrap();
            let actual_report = subword_compact
                .run_pure_to_halt(&mut subword_actual, capacity)
                .unwrap();
            let expected = &subword_reference.tracer().recorded_steps()
                [expected_start..expected_start + expected_report.executed_steps];
            for (expected, decoded) in expected.iter().zip(&actual_report.l1_skeleton_records) {
                assert_l2_values_match(expected, decoded);
            }
            assert_eq!(subword_actual.get_pc(), subword_reference.get_pc());
            assert_eq!(
                subword_actual.peek_memory(ByteAddr(heap).waddr()),
                subword_reference.peek_memory(ByteAddr(heap).waddr())
            );
        }
    }

    #[test]
    fn preflight_registers_l3_matches_direct_across_aliases_boundaries_and_resume() {
        assert_eq!(
            AssemblyTraceStyle::PreflightRegistersL3.cache_name(),
            "preflight-registers-l3-schema1"
        );
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l3 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightRegistersL3,
        )
        .unwrap();

        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: 256,
            },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(20, base);
        reference.init_memory(ByteAddr(base).waddr(), 0);
        actual.init_register_unsafe(20, base);
        actual.init_memory(ByteAddr(base).waddr(), 0);

        for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
            let expected_start = reference.tracer().recorded_steps().len();
            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            let actual_report = l3.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
            let expected = &reference.tracer().recorded_steps()
                [expected_start..expected_start + expected_report.executed_steps];
            for (expected, actual) in expected.iter().zip(&actual_report.l1_skeleton_records) {
                assert_l3_registers_match(expected, actual);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(0), 0);
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(base).waddr()),
                reference.peek_memory(ByteAddr(base).waddr())
            );
        }
    }

    #[test]
    fn preflight_compact_registers_l3c_matches_aliases_branches_and_repeated_bounds() {
        assert_eq!(
            AssemblyTraceStyle::PreflightCompactRegistersL3C.cache_name(),
            "preflight-compact-registers-l3c-schema1"
        );
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactRegistersL3C,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: 256,
            },
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        let heap = CENO_PLATFORM.heap.start;
        reference.init_register_unsafe(20, heap);
        reference.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);
        actual.init_register_unsafe(20, heap);
        actual.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);

        for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
            let expected_start = reference.tracer().recorded_steps().len();
            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
            let expected = &reference.tracer().recorded_steps()
                [expected_start..expected_start + expected_report.executed_steps];
            assert_eq!(
                actual_report.compact_bytes_written,
                expected
                    .iter()
                    .map(|record| compact_registers_row_size(record.insn()))
                    .sum::<usize>()
            );
            for (expected, actual) in expected.iter().zip(&actual_report.l1_skeleton_records) {
                assert_l3_registers_match(expected, actual);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(0), 0);
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(heap).waddr()),
                reference.peek_memory(ByteAddr(heap).waddr())
            );
        }
    }

    #[test]
    fn preflight_compact_registers_l3c_matches_dynamic_jalr_ecall_and_trap() {
        let pc_base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 6, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
            encode_rv32(InsnKind::ADDI, 6, 0, 7, 1),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactRegistersL3C,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 4 },
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        reference.init_register_unsafe(1, pc_base + 8);
        reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        actual.init_register_unsafe(1, pc_base + 8);
        actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        let expected_report = direct.run_to_halt(&mut reference, 4).unwrap();
        let actual_report = compact.run_pure_to_halt(&mut actual, 4).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert!(actual_report.fallback.dynamic_pc_miss > 0);
        assert!(actual_report.fallback_steps >= 2);
        for (expected, actual) in reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&actual_report.l1_skeleton_records)
        {
            if expected.insn().kind == InsnKind::ECALL {
                // Dynamic syscall register payload/index semantics remain L6C.
                assert_eq!(actual.cycle(), expected.cycle());
                assert_eq!(actual.pc(), expected.pc());
                assert_eq!(actual.insn(), expected.insn());
                assert!(actual.l3_later_fields_are_poisoned());
            } else {
                assert_l3_registers_match(expected, actual);
            }
        }
        assert_eq!(actual.get_pc(), reference.get_pc());

        let heap = CENO_PLATFORM.heap.start;
        let trap_program = Arc::new(self::program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            trap_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            trap_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactRegistersL3C,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            trap_program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
        reference.init_register_unsafe(20, heap);
        actual.init_register_unsafe(20, heap);
        let expected = direct
            .run_to_halt(&mut reference, 1)
            .unwrap_err()
            .to_string();
        let actual_error = compact
            .run_pure_to_halt(&mut actual, 1)
            .unwrap_err()
            .to_string();
        assert!(expected.contains("LoadAddressMisaligned"));
        assert!(actual_error.contains("LoadAddressMisaligned"));
        assert_eq!(actual.get_pc(), reference.get_pc());
    }

    #[test]
    fn preflight_compact_registers_l3c_has_no_262144_row_reset() {
        let capacity = 262_145;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 1, 0, 1, 1),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -4),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactRegistersL3C,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: capacity,
            },
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        direct.run_to_halt(&mut reference, capacity).unwrap();
        let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(report.executed_steps, capacity);
        assert_eq!(report.l1_skeleton_records.len(), capacity);
        for &index in &[0, 1, 262_143, 262_144] {
            assert_l3_registers_match(
                &reference.tracer().recorded_steps()[index],
                &report.l1_skeleton_records[index],
            );
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
    }

    #[test]
    fn preflight_compact_registers_l3c_rejects_overflow_before_forward_family_stores() {
        let program = program(vec![
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
            encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
            encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::SW, 20, 3, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l3c.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactRegistersL3C,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();

        let exact_boundary = "    movq 0(%rsp), %rax\n    cmpq %rbp, %rax\n    jae ceno_aot_done";
        assert!(
            assembly.matches(exact_boundary).count() >= blocks.len() + 1,
            "every L3C block leader plus the dispatcher must close an exact bound"
        );
        let recorder = assembly
            .split("ceno_aot_compact_registers_l3c_emit_step:\n")
            .nth(1)
            .unwrap()
            .split(".L_compact_registers_l3c_overflow:\n")
            .next()
            .unwrap();
        let first_family = recorder.find(".L_compact_registers_l3c_r:\n").unwrap();
        let prefix = &recorder[..first_family];
        assert!(prefix.contains("testl $3, %eax\n    jne .L_compact_registers_l3c_overflow"));
        assert!(prefix.contains("cmpl $1048576, %eax\n    jae .L_compact_registers_l3c_overflow"));
        assert!(!prefix.contains("(%r10)"));

        let expected = [
            (
                "r",
                &[
                    "    movq %rax, 0(%r10)",
                    "    movq %rax, 8(%r10)",
                    "    movq %rax, 16(%r10)",
                    "    movl %eax, 24(%r10)",
                ][..],
            ),
            (
                "i",
                &[
                    "    movq %rax, 0(%r10)",
                    "    movq %rax, 8(%r10)",
                    "    movl %eax, 16(%r10)",
                    "    movb %al, 20(%r10)",
                ][..],
            ),
            (
                "branch",
                &[
                    "    movq %rax, 0(%r10)",
                    "    movq %rax, 8(%r10)",
                    "    movl %eax, 16(%r10)",
                    "    movb %al, 20(%r10)",
                ][..],
            ),
            (
                "j",
                &[
                    "    movq %rax, 0(%r10)",
                    "    movl %eax, 8(%r10)",
                    "    movb %al, 12(%r10)",
                ][..],
            ),
            (
                "load",
                &[
                    "    movq %rax, 0(%r10)",
                    "    movq %rax, 8(%r10)",
                    "    movq %rax, 16(%r10)",
                    "    movb %al, 24(%r10)",
                ][..],
            ),
            (
                "store",
                &[
                    "    movq %rax, 0(%r10)",
                    "    movq %rax, 8(%r10)",
                    "    movq %rax, 16(%r10)",
                    "    movb %al, 24(%r10)",
                ][..],
            ),
            (
                "exceptional",
                &["    movq %rax, 0(%r10)", "    movw %ax, 8(%r10)"][..],
            ),
            (
                "header",
                &["    movl %eax, 0(%r10)", "    movw %ax, 4(%r10)"][..],
            ),
        ];
        for (index, (family, expected_stores)) in expected.iter().enumerate() {
            let label = format!(".L_compact_registers_l3c_{family}:\n");
            let body = recorder.split(&label).nth(1).unwrap();
            let body = if let Some((next_family, _)) = expected.get(index + 1) {
                body.split(&format!(".L_compact_registers_l3c_{next_family}:\n"))
                    .next()
                    .unwrap()
            } else {
                body
            };
            let stores = body
                .lines()
                .filter(|line| line.contains("(%r10)"))
                .collect::<Vec<_>>();
            assert_eq!(stores, *expected_stores, "L3C {family} store coverage");
            if !matches!(*family, "header" | "exceptional") {
                let last_cycle_check = body
                    .rfind("jae .L_compact_registers_l3c_overflow")
                    .expect("register family must validate predecessor widths");
                let first_store = body.find("(%r10)").unwrap();
                assert!(last_cycle_check < first_store);
            }
        }
        for line in recorder.lines().filter(|line| line.contains("(%r10)")) {
            assert!(
                line.trim_end().ends_with("(%r10)"),
                "destination load/RMW: {line}"
            );
        }
        assert!(!recorder.contains("0xa5a5"));
        assert!(!recorder.contains("memset"));
        assert!(!recorder.contains("StepRecord"));
        assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
        let overflow = assembly
            .split(".L_compact_registers_l3c_overflow:\n")
            .nth(1)
            .unwrap()
            .split("ceno_aot_error:\n")
            .next()
            .unwrap();
        assert!(overflow.contains(
            "    addq $32, %rsp\n    popq %r10\n    addq $8, %rsp\n    jmp ceno_aot_error"
        ));

        let overflow_program =
            Arc::new(self::program(vec![encode_rv32(InsnKind::ADDI, 1, 0, 2, 1)]));
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            overflow_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactRegistersL3C,
        )
        .unwrap();
        let mut vm =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), overflow_program);
        vm.tracer_mut().layered_register_latest[1] = 1 << COMPACT_REGISTERS_CYCLE_BITS;
        let error = compact
            .run_pure_to_halt(&mut vm, 1)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "AOT native step failed without error detail");
        assert_eq!(vm.tracer().layered_cycle, PureAotTracer::SUBCYCLES_PER_INSN);
    }

    #[test]
    fn preflight_compact_memory_l4c_matches_memory_aliases_bounds_fallback_and_resume() {
        assert_eq!(
            AssemblyTraceStyle::PreflightCompactMemoryL4C.cache_name(),
            "preflight-compact-memory-l4c-schema1"
        );
        assert_eq!(std::mem::size_of::<CompactMemoryLoad>(), 28);
        assert_eq!(std::mem::size_of::<CompactMemoryStore>(), 28);
        assert_eq!(std::mem::size_of::<CompactMemoryExceptional>(), 18);

        let pc_base = CENO_PLATFORM.pc_base();
        let heap = CENO_PLATFORM.heap.start;
        let hint = CENO_PLATFORM.hints.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
            encode_rv32(InsnKind::SB, 20, 1, 0, 1),
            encode_rv32(InsnKind::LBU, 20, 0, 2, 1),
            encode_rv32(InsnKind::SH, 20, 2, 0, 2),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::SW, 21, 3, 0, 8),
            encode_rv32(InsnKind::LW, 21, 0, 1, 8),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactMemoryL4C,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 32 },
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        reference.init_register_unsafe(1, 0x1122_3344);
        reference.init_register_unsafe(20, heap);
        reference.init_register_unsafe(21, hint);
        reference.init_register_unsafe(22, pc_base + 8);
        reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        reference.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);
        reference.init_memory(ByteAddr(hint + 8).waddr(), 0);
        actual.init_register_unsafe(1, 0x1122_3344);
        actual.init_register_unsafe(20, heap);
        actual.init_register_unsafe(21, hint);
        actual.init_register_unsafe(22, pc_base + 8);
        actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        actual.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);
        actual.init_memory(ByteAddr(hint + 8).waddr(), 0);

        for capacity in [1, 2, 1, 3, 1] {
            let expected_start = reference.tracer().recorded_steps().len();
            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            let expected = &reference.tracer().recorded_steps()
                [expected_start..expected_start + expected_report.executed_steps];
            assert_eq!(
                actual_report.compact_bytes_written,
                expected
                    .iter()
                    .map(|record| compact_memory_row_size(record.insn()))
                    .sum::<usize>()
            );
            for (expected, decoded) in expected.iter().zip(&actual_report.l1_skeleton_records) {
                if expected.insn().kind == InsnKind::ECALL {
                    assert_eq!(decoded.cycle(), expected.cycle());
                    assert_eq!(decoded.pc(), expected.pc());
                    assert_eq!(decoded.heap_maxtouch_addr, expected.heap_maxtouch_addr);
                    assert_eq!(decoded.hint_maxtouch_addr, expected.hint_maxtouch_addr);
                    assert!(decoded.l4_later_fields_are_poisoned());
                } else {
                    assert_l4_memory_matches(expected, decoded);
                }
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(
                actual.peek_memory(ByteAddr(heap).waddr()),
                reference.peek_memory(ByteAddr(heap).waddr())
            );
            assert_eq!(
                actual.peek_memory(ByteAddr(hint + 8).waddr()),
                reference.peek_memory(ByteAddr(hint + 8).waddr())
            );
        }
    }

    #[test]
    fn preflight_compact_memory_l4c_uses_only_forward_nonoverlapping_family_stores() {
        let program = program(vec![
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::SW, 20, 3, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l4c.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactMemoryL4C,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();
        let recorder = assembly
            .split("ceno_aot_compact_registers_l3c_emit_step:\n")
            .nth(1)
            .unwrap()
            .split(".L_compact_registers_l3c_overflow:\n")
            .next()
            .unwrap();
        for (family, next_family) in [("load", "store"), ("store", "exceptional")] {
            let body = recorder
                .split(&format!(".L_compact_registers_l3c_{family}:\n"))
                .nth(1)
                .unwrap()
                .split(&format!(".L_compact_registers_l3c_{next_family}:\n"))
                .next()
                .unwrap();
            let stores = body
                .lines()
                .filter(|line| line.contains("(%r10)"))
                .collect::<Vec<_>>();
            assert_eq!(
                stores,
                [
                    "    movq %rax, 0(%r10)",
                    "    movq %rax, 8(%r10)",
                    "    movq %rax, 16(%r10)",
                    "    movl %eax, 24(%r10)",
                ],
                "L4C {family} store coverage"
            );
            let last_width_check = body
                .rfind("jae .L_compact_registers_l3c_overflow")
                .expect("L4C memory family must validate predecessor width");
            assert!(last_width_check < body.find("(%r10)").unwrap());
        }
        let exceptional = recorder
            .split(".L_compact_registers_l3c_exceptional:\n")
            .nth(1)
            .unwrap()
            .split(".L_compact_registers_l3c_header:\n")
            .next()
            .unwrap();
        assert_eq!(
            exceptional
                .lines()
                .filter(|line| line.contains("(%r10)"))
                .collect::<Vec<_>>(),
            [
                "    movq %rax, 0(%r10)",
                "    movq %rax, 8(%r10)",
                "    movw %ax, 16(%r10)",
            ]
        );
        for line in recorder.lines().filter(|line| line.contains("(%r10)")) {
            assert!(
                line.trim_end().ends_with("(%r10)"),
                "destination load/RMW: {line}"
            );
        }
        assert!(!recorder.contains("0xa5a5"));
        assert!(!recorder.contains("memset"));
        assert!(!recorder.contains("StepRecord"));
        assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
    }

    #[test]
    fn preflight_memory_l4_matches_direct_repeated_subword_bounds_and_resume() {
        assert_eq!(
            AssemblyTraceStyle::PreflightMemoryL4.cache_name(),
            "preflight-memory-l4-schema1"
        );
        let heap = CENO_PLATFORM.heap.start;
        let hint = CENO_PLATFORM.hints.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::SB, 20, 1, 0, 1),
            encode_rv32(InsnKind::LBU, 20, 0, 2, 1),
            encode_rv32(InsnKind::SH, 20, 2, 0, 2),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::SW, 20, 3, 0, 4),
            encode_rv32(InsnKind::LW, 20, 0, 1, 4),
            encode_rv32(InsnKind::SW, 21, 1, 0, 8),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -32),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -40),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l4 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightMemoryL4,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: 256,
            },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(20, heap);
        reference.init_register_unsafe(21, hint);
        reference.init_memory(ByteAddr(heap).waddr(), 0);
        reference.init_memory(ByteAddr(heap + 4).waddr(), 0);
        reference.init_memory(ByteAddr(hint + 8).waddr(), 0);
        actual.init_register_unsafe(20, heap);
        actual.init_register_unsafe(21, hint);
        actual.init_memory(ByteAddr(heap).waddr(), 0);
        actual.init_memory(ByteAddr(heap + 4).waddr(), 0);
        actual.init_memory(ByteAddr(hint + 8).waddr(), 0);

        for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
            let expected_start = reference.tracer().recorded_steps().len();
            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            let actual_report = l4.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            let expected = &reference.tracer().recorded_steps()
                [expected_start..expected_start + expected_report.executed_steps];
            for (expected, actual) in expected.iter().zip(&actual_report.l1_skeleton_records) {
                assert_l4_memory_matches(expected, actual);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            for addr in [heap, heap + 4, hint + 8] {
                assert_eq!(
                    actual.peek_memory(ByteAddr(addr).waddr()),
                    reference.peek_memory(ByteAddr(addr).waddr())
                );
            }
        }
    }

    #[test]
    fn preflight_memory_l4_matches_direct_scalar_resume_and_ecall() {
        let pc_base = CENO_PLATFORM.pc_base();
        let heap = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 99),
            encode_rv32(InsnKind::SW, 20, 2, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l4 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightMemoryL4,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 8 },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(1, pc_base + 8);
        reference.init_register_unsafe(2, 7);
        reference.init_register_unsafe(20, heap);
        reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        reference.init_memory(ByteAddr(heap).waddr(), 0);
        actual.init_register_unsafe(1, pc_base + 8);
        actual.init_register_unsafe(2, 7);
        actual.init_register_unsafe(20, heap);
        actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        actual.init_memory(ByteAddr(heap).waddr(), 0);

        let expected_report = direct.run_to_halt(&mut reference, 8).unwrap();
        let actual_report = l4.run_pure_to_halt(&mut actual, 8).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert!(actual_report.fallback.dynamic_pc_miss > 0);
        assert!(actual_report.fallback_steps >= 2);
        for (expected, actual) in reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&actual_report.l1_skeleton_records)
        {
            if expected.insn().kind == InsnKind::ECALL {
                // Dynamic syscall operands/witnesses are intentionally L6.
                // L4 still owns the exact bounds surrounding the syscall and
                // must leave all later-layer fields poisoned.
                assert_eq!(actual.cycle(), expected.cycle());
                assert_eq!(actual.pc(), expected.pc());
                assert_eq!(actual.heap_maxtouch_addr, expected.heap_maxtouch_addr);
                assert_eq!(actual.hint_maxtouch_addr, expected.hint_maxtouch_addr);
                assert!(actual.l4_later_fields_are_poisoned());
            } else {
                assert_l4_memory_matches(expected, actual);
            }
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_memory(ByteAddr(heap).waddr()), 7);
    }

    #[test]
    fn preflight_future_access_l5_matches_direct_native_scalar_and_resume() {
        assert_eq!(
            AssemblyTraceStyle::PreflightFutureAccessL5.cache_name(),
            "preflight-future-access-l5-schema1"
        );
        let pc_base = CENO_PLATFORM.pc_base();
        let heap = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -16),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l5 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightFutureAccessL5,
        )
        .unwrap();

        let initialize = |vm: &mut VMState<_>| {
            vm.init_register_unsafe(20, heap);
            vm.init_register_unsafe(22, pc_base + 20);
            vm.init_memory(ByteAddr(heap).waddr(), 0);
        };
        let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 64 },
        );
        initialize(&mut seed);
        direct.run_to_halt(&mut seed, 31).unwrap();
        let mut events = Vec::new();
        for record in seed.tracer().recorded_steps() {
            for (subcycle, op) in [
                (
                    crate::FullTracer::SUBCYCLE_RS1,
                    record.rs1().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_RS2,
                    record.rs2().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_RD,
                    record.rd().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_MEM,
                    record.memory_op().map(|op| op.addr),
                ),
            ] {
                if let Some(address) = op {
                    let source = record.cycle() + subcycle;
                    events.push(NextAccessEvent::new(source, source + 1_000_000, address));
                }
            }
        }
        let tape = Arc::new(NextCycleAccess::from_unsorted(events));
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 64 },
            Some(tape.clone()),
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program,
            (),
            Some(tape),
        );
        initialize(&mut reference);
        actual.init_register_unsafe(20, heap);
        actual.init_register_unsafe(22, pc_base + 20);
        actual.init_memory(ByteAddr(heap).waddr(), 0);

        for capacity in [1, 2, 4, 5, 6, 7, 6] {
            let start = reference.tracer().recorded_steps().len();
            direct.run_to_halt(&mut reference, capacity).unwrap();
            reference.tracer_mut().annotate_recorded_steps(start);
            let report = l5.run_pure_to_halt(&mut actual, capacity).unwrap();
            let expected = &reference.tracer().recorded_steps()[start..start + capacity];
            assert_eq!(report.l1_skeleton_records.len(), capacity);
            for (expected, actual) in expected.iter().zip(&report.l1_skeleton_records) {
                assert_l5_future_access_matches(expected, actual);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(heap).waddr()),
                reference.peek_memory(ByteAddr(heap).waddr())
            );
        }
        assert_eq!(
            actual.tracer().layered_next_access_cursor,
            actual.tracer().layered_next_accesses.events().len()
        );
    }

    #[test]
    fn preflight_future_access_l5_matches_direct_syscall_masks() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l5 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightFutureAccessL5,
        )
        .unwrap();
        let initialize = |vm: &mut VMState<_>| {
            vm.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
            vm.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
            vm.init_register_unsafe(Platform::reg_arg1(), 0);
        };
        let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
        );
        initialize(&mut seed);
        direct.run_to_halt(&mut seed, 1).unwrap();
        let witness = &seed.tracer().syscall_witnesses()[0];
        let source = seed.tracer().recorded_steps()[0].cycle() + crate::FullTracer::SUBCYCLE_RD;
        let tape = Arc::new(NextCycleAccess::from_unsorted(
            witness
                .reg_ops
                .iter()
                .map(|op| NextAccessEvent::new(source, source + 100, op.addr))
                .collect(),
        ));
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
            Some(tape.clone()),
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program,
            (),
            Some(tape),
        );
        initialize(&mut reference);
        actual.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
        actual.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
        actual.init_register_unsafe(Platform::reg_arg1(), 0);
        direct.run_to_halt(&mut reference, 1).unwrap();
        reference.tracer_mut().annotate_recorded_steps(0);
        let report = l5.run_pure_to_halt(&mut actual, 1).unwrap();
        assert_eq!(report.l1_skeleton_records[0].future_access_mask(), 0);
        assert!(report.l1_skeleton_records[0].l5_later_fields_are_poisoned());
        let expected = &reference.tracer().syscall_witnesses()[0];
        let actual = &actual.tracer().layered_syscall_future_accesses[0];
        assert_eq!(actual.reg_masks, expected.reg_future_access);
        assert_eq!(actual.mem_masks, expected.mem_future_access);
        assert_eq!(actual.reg_masks, vec![1, 1]);
    }

    #[test]
    fn preflight_compact_future_access_l5c_matches_native_scalar_resume_and_closure() {
        assert_eq!(
            AssemblyTraceStyle::PreflightCompactFutureAccessL5C.cache_name(),
            "preflight-compact-future-access-l5c-schema2"
        );
        assert_eq!(std::mem::size_of::<CompactFutureJ>(), 14);
        assert_eq!(std::mem::size_of::<CompactFutureR>(), 29);
        assert_eq!(std::mem::size_of::<CompactFutureLoad>(), 29);
        assert_eq!(std::mem::size_of::<CompactFutureStore>(), 29);
        assert_eq!(std::mem::size_of::<CompactFutureSyscallMask>(), 11);

        let pc_base = CENO_PLATFORM.pc_base();
        let heap = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -16),
            encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
        )
        .unwrap();
        let initialize = |vm: &mut VMState<_>| {
            vm.init_register_unsafe(20, heap);
            vm.init_register_unsafe(22, pc_base + 20);
            vm.init_memory(ByteAddr(heap).waddr(), 0);
        };
        let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 64 },
        );
        initialize(&mut seed);
        direct.run_to_halt(&mut seed, 31).unwrap();
        let events = seed
            .tracer()
            .recorded_steps()
            .iter()
            .flat_map(|record| {
                [
                    (
                        crate::FullTracer::SUBCYCLE_RS1,
                        record.rs1().map(|op| op.addr),
                    ),
                    (
                        crate::FullTracer::SUBCYCLE_RS2,
                        record.rs2().map(|op| op.addr),
                    ),
                    (
                        crate::FullTracer::SUBCYCLE_RD,
                        record.rd().map(|op| op.addr),
                    ),
                    (
                        crate::FullTracer::SUBCYCLE_MEM,
                        record.memory_op().map(|op| op.addr),
                    ),
                ]
                .into_iter()
                .filter_map(|(subcycle, address)| {
                    address.map(|address| {
                        let source = record.cycle() + subcycle;
                        NextAccessEvent::new(source, source + 1_000_000, address)
                    })
                })
            })
            .collect::<Vec<_>>();
        let tape = Arc::new(NextCycleAccess::from_unsorted(events));
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 64 },
            Some(tape.clone()),
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program,
            (),
            Some(tape),
        );
        initialize(&mut reference);
        actual.init_register_unsafe(20, heap);
        actual.init_register_unsafe(22, pc_base + 20);
        actual.init_memory(ByteAddr(heap).waddr(), 0);

        for capacity in [1, 2, 4, 5, 6, 7, 6] {
            let start = reference.tracer().recorded_steps().len();
            direct.run_to_halt(&mut reference, capacity).unwrap();
            reference.tracer_mut().annotate_recorded_steps(start);
            let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
            let expected = &reference.tracer().recorded_steps()[start..start + capacity];
            assert_eq!(report.l1_skeleton_records.len(), capacity);
            assert_eq!(
                report.compact_bytes_written,
                expected
                    .iter()
                    .map(|record| compact_future_access_row_size(record.insn()))
                    .sum::<usize>()
            );
            for (expected, decoded) in expected.iter().zip(&report.l1_skeleton_records) {
                assert_l5_future_access_matches(expected, decoded);
            }
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.peek_register(1), reference.peek_register(1));
            assert_eq!(
                actual.peek_memory(ByteAddr(heap).waddr()),
                reference.peek_memory(ByteAddr(heap).waddr())
            );
        }
        assert_eq!(
            actual.tracer().layered_next_access_cursor,
            actual.tracer().layered_next_accesses.events().len()
        );
    }

    #[test]
    fn preflight_compact_future_access_l5c_matches_syscall_masks() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
        )
        .unwrap();
        let initialize = |vm: &mut VMState<_>| {
            vm.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
            vm.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
            vm.init_register_unsafe(Platform::reg_arg1(), 0);
        };
        let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
        );
        initialize(&mut seed);
        direct.run_to_halt(&mut seed, 1).unwrap();
        let witness = &seed.tracer().syscall_witnesses()[0];
        let source = seed.tracer().recorded_steps()[0].cycle() + crate::FullTracer::SUBCYCLE_RD;
        let tape = Arc::new(NextCycleAccess::from_unsorted(
            witness
                .reg_ops
                .iter()
                .map(|op| NextAccessEvent::new(source, source + 100, op.addr))
                .collect(),
        ));
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
            Some(tape.clone()),
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program,
            (),
            Some(tape),
        );
        initialize(&mut reference);
        actual.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
        actual.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
        actual.init_register_unsafe(Platform::reg_arg1(), 0);
        direct.run_to_halt(&mut reference, 1).unwrap();
        reference.tracer_mut().annotate_recorded_steps(0);
        let report = compact.run_pure_to_halt(&mut actual, 1).unwrap();
        assert_eq!(report.l1_skeleton_records[0].future_access_mask(), 0);
        let expected = &reference.tracer().syscall_witnesses()[0];
        let mask = actual.tracer().layered_compact_syscall_masks[0];
        let decoded = |index: usize| u8::from(mask.bits[index / 8] & (1 << (index % 8)) != 0);
        assert_eq!(mask.reg_count as usize, expected.reg_future_access.len());
        assert_eq!(mask.mem_count as usize, expected.mem_future_access.len());
        assert_eq!(
            (0..mask.reg_count as usize)
                .map(decoded)
                .collect::<Vec<_>>(),
            expected.reg_future_access
        );
        assert_eq!(
            (0..mask.mem_count as usize)
                .map(|index| decoded(mask.reg_count as usize + index))
                .collect::<Vec<_>>(),
            expected.mem_future_access
        );
    }

    #[test]
    fn preflight_compact_exceptional_l6c_matches_complete_steps_syscalls_and_resume() {
        assert_eq!(
            AssemblyTraceStyle::PreflightCompactExceptionalL6C.cache_name(),
            "preflight-compact-exceptional-l6c-schema2"
        );
        assert_eq!(std::mem::size_of::<CompactL6SyscallHeader>(), 30);
        assert_eq!(std::mem::size_of::<CompactL6WriteOp>(), 20);

        let base = CENO_PLATFORM.pc_base();
        let heap = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 99),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 2, 0),
            encode_rv32(InsnKind::SW, 20, 2, 0, 4),
            encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_arg0().into(), 0),
            encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_ecall().into(), 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            vec![base + 8],
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            vec![base + 8],
            AssemblyTraceStyle::PreflightCompactExceptionalL6C,
        )
        .unwrap();
        let initialize = |vm: &mut dyn SyscallTestVm| {
            vm.init_register(22, base + 8);
            vm.init_register(20, heap);
            vm.init_register(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
            vm.init_register(Platform::reg_arg0(), heap);
            vm.init_register(Platform::reg_arg1(), 0);
            vm.init_word(ByteAddr(heap).waddr(), 17);
            vm.init_word(ByteAddr(heap + 4).waddr(), 0);
        };
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 16 },
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
        initialize(&mut reference);
        initialize(&mut actual);

        for capacity in [1, 2, 1, 3] {
            let start = reference.tracer().recorded_steps().len();
            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            reference.tracer_mut().annotate_recorded_steps(start);
            let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(
                actual_report.fallback.dynamic_pc_miss,
                expected_report.fallback.dynamic_pc_miss
            );
            assert_eq!(
                actual_report.fallback.memory_guard,
                expected_report.fallback.memory_guard
            );
            assert_eq!(
                actual_report.fallback.exceptional_jump_or_trap,
                expected_report.fallback.exceptional_jump_or_trap
            );
            assert_eq!(
                actual_report.fallback.ecall_by_code,
                expected_report.fallback.ecall_by_code
            );
            assert_eq!(
                actual_report.l1_skeleton_records,
                reference.tracer().recorded_steps()[start..start + actual_report.executed_steps]
            );
            assert_eq!(
                actual_report.l6_syscall_witnesses,
                reference.tracer().syscall_witnesses()
            );
            assert_eq!(actual.get_pc(), reference.get_pc());
        }
        assert_eq!(
            actual.peek_register(1),
            0,
            "mid-block dynamic target was exact"
        );
        assert_eq!(actual.peek_memory(ByteAddr(heap + 4).waddr()), 17);
        assert_eq!(actual.tracer().layered_compact_l6_syscalls.len(), 2);
        assert_eq!(
            actual.tracer().layered_compact_l6_syscalls[1].syscall_index(),
            crate::StepRecord::NO_SYSCALL
        );
        assert_eq!(actual.tracer().layered_compact_l6_ops.len(), 3);
    }

    #[test]
    fn preflight_compact_exceptional_l6c_matches_multi_op_syscall_capacity_and_repeat() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactExceptionalL6C,
        )
        .unwrap();
        let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
            crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();

        for capacity in [3, 4] {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig { max_step_shard: 4 },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            for vm in [
                &mut reference as &mut dyn SyscallTestVm,
                &mut actual as &mut dyn SyscallTestVm,
            ] {
                vm.init_register(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
                vm.init_register(Platform::reg_arg0(), base);
                for (offset, value) in input.into_iter().enumerate() {
                    vm.init_word(ByteAddr(base).waddr() + offset, value);
                }
            }

            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            reference.tracer_mut().annotate_recorded_steps(0);
            let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, 3);
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(
                actual_report.l1_skeleton_records,
                reference.tracer().recorded_steps()
            );
            assert_eq!(
                actual_report.l6_syscall_witnesses,
                reference.tracer().syscall_witnesses()
            );
            assert_eq!(actual_report.l6_syscall_witnesses.len(), 1);
            assert_eq!(
                actual_report.l6_syscall_witnesses[0].mem_ops.len(),
                crate::syscalls::secp256k1::SECP256K1_ARG_WORDS
            );
            assert_eq!(
                actual_report.fallback.ecall_by_code,
                expected_report.fallback.ecall_by_code
            );
            assert_eq!(
                actual_report.fallback.ecall_by_code[&crate::SECP256K1_DOUBLE],
                2
            );
            assert_eq!(actual.get_pc(), reference.get_pc());
        }
    }

    #[test]
    fn preflight_compact_exceptional_l6c_matches_memory_guard_trap_and_repeat() {
        let base = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactExceptionalL6C,
        )
        .unwrap();

        for _ in 0..2 {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig { max_step_shard: 1 },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            reference.init_register_unsafe(20, base);
            actual.init_register_unsafe(20, base);
            let expected = direct
                .run_to_halt(&mut reference, 1)
                .unwrap_err()
                .to_string();
            let observed = compact
                .run_pure_to_halt(&mut actual, 1)
                .unwrap_err()
                .to_string();
            assert!(expected.contains("LoadAddressMisaligned"));
            assert_eq!(observed, expected);
            assert_eq!(actual.get_pc(), reference.get_pc());
            assert_eq!(actual.tracer().cycle(), reference.tracer().cycle());
        }
    }

    #[test]
    fn preflight_compact_exceptional_l6c_preserves_hot_assembly_and_side_layouts() {
        assert_eq!(std::mem::size_of::<CompactL6SyscallHeader>(), 30);
        assert_eq!(std::mem::size_of::<CompactL6WriteOp>(), 20);
        assert_eq!(std::mem::size_of::<CompactFutureSyscallMask>(), 11);
        let program = program(vec![
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
            encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
            encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::SW, 20, 3, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l6c.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactExceptionalL6C,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();
        let exact_boundary = "    movq 0(%rsp), %rax\n    cmpq %rbp, %rax\n    jae ceno_aot_done";
        assert!(assembly.matches(exact_boundary).count() >= blocks.len() + 1);
        let recorder = assembly
            .split("ceno_aot_compact_registers_l3c_emit_step:\n")
            .nth(1)
            .unwrap()
            .split(".L_compact_registers_l3c_overflow:\n")
            .next()
            .unwrap();
        for size in [6, 14, 18, 21, 29] {
            assert!(recorder.contains(&format!("    addq ${size}, %r9")));
        }
        assert!(!recorder.contains("0xa5a5"));
        assert!(!recorder.contains("memset"));
        assert!(!recorder.contains("StepRecord"));
        assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
        assert!(!assembly.contains("ceno_aot_fulltracer_emit_step:"));
    }

    #[test]
    fn preflight_compact_future_access_l5c_matches_mixed_keccak_xorin_masks() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let compact = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
        )
        .unwrap();
        let state = CENO_PLATFORM.heap.start;
        let block = state + 512;
        macro_rules! initialize {
            ($vm:expr) => {{
                $vm.init_register_unsafe(Platform::reg_ecall(), crate::KECCAK_XORIN);
                $vm.init_register_unsafe(Platform::reg_arg0(), state);
                $vm.init_register_unsafe(Platform::reg_arg1(), block);
                for index in 0..crate::syscalls::keccak_xorin::KECCAK_RATE_WORDS {
                    $vm.init_memory(
                        ByteAddr(state + (index * WORD_SIZE) as u32).waddr(),
                        index as u32,
                    );
                    $vm.init_memory(
                        ByteAddr(block + (index * WORD_SIZE) as u32).waddr(),
                        !(index as u32),
                    );
                }
            }};
        }
        let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
        );
        initialize!(seed);
        direct.run_to_halt(&mut seed, 1).unwrap();
        let witness = &seed.tracer().syscall_witnesses()[0];
        assert_eq!(witness.reg_ops.len(), 2);
        assert_eq!(witness.mem_ops.len(), 68);
        let cycle = seed.tracer().recorded_steps()[0].cycle();
        let mut events = vec![NextAccessEvent::new(
            cycle + crate::FullTracer::SUBCYCLE_RD,
            cycle + 100,
            witness.reg_ops[0].addr,
        )];
        events.extend([0, 2, 33, 34, 67].into_iter().map(|index| {
            NextAccessEvent::new(
                cycle + crate::FullTracer::SUBCYCLE_MEM,
                cycle + 100,
                witness.mem_ops[index].addr,
            )
        }));
        let tape = Arc::new(NextCycleAccess::from_unsorted(events));
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
            Some(tape.clone()),
        );
        let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
            CENO_PLATFORM.clone(),
            program,
            (),
            Some(tape),
        );
        initialize!(reference);
        initialize!(actual);
        direct.run_to_halt(&mut reference, 1).unwrap();
        reference.tracer_mut().annotate_recorded_steps(0);
        compact.run_pure_to_halt(&mut actual, 1).unwrap();

        let expected = &reference.tracer().syscall_witnesses()[0];
        let mask = actual.tracer().layered_compact_syscall_masks[0];
        let decoded = |index: usize| u8::from(mask.bits[index / 8] & (1 << (index % 8)) != 0);
        let actual_regs = (0..mask.reg_count as usize)
            .map(decoded)
            .collect::<Vec<_>>();
        let actual_mem = (0..mask.mem_count as usize)
            .map(|index| decoded(mask.reg_count as usize + index))
            .collect::<Vec<_>>();
        assert_eq!(actual_regs, expected.reg_future_access);
        assert_eq!(actual_mem, expected.mem_future_access);
        assert_eq!(actual_regs, vec![1, 0]);
        assert_eq!(actual_mem.iter().filter(|&&bit| bit != 0).count(), 5);
        assert!(actual_mem.iter().any(|&bit| bit == 0));
        assert_eq!(
            actual.tracer().layered_next_access_cursor,
            actual.tracer().layered_next_accesses.events().len()
        );
    }

    #[test]
    fn preflight_compact_future_access_l5c_validates_before_exact_forward_stores() {
        let program = program(vec![
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
            encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
            encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::SW, 20, 3, 0, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let cache = tempfile::tempdir().unwrap();
        let path = cache.path().join("l5c.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();
        let exact_boundary = "    movq 0(%rsp), %rax\n    cmpq %rbp, %rax\n    jae ceno_aot_done";
        assert!(
            assembly.matches(exact_boundary).count() >= blocks.len() + 1,
            "every L5C block leader plus the dispatcher must close an exact bound"
        );
        for block in &blocks {
            let label = format!("ceno_aot_bb_{:08x}:\n", block.start_pc);
            let leader = assembly
                .split(&label)
                .nth(1)
                .unwrap()
                .lines()
                .take(8)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                leader.contains(exact_boundary),
                "L5C block leader {:#010x} must close an exact bound",
                block.start_pc
            );
        }
        let recorder = assembly
            .split("ceno_aot_compact_registers_l3c_emit_step:\n")
            .nth(1)
            .unwrap()
            .split(".L_compact_registers_l3c_overflow:\n")
            .next()
            .unwrap();
        let first_family = recorder.find(".L_compact_registers_l3c_r:\n").unwrap();
        let validation = &recorder[..first_family];
        assert!(validation.contains(".L_compact_future_l5c_event_loop:"));
        assert!(validation.contains("cmpq %rdx, %rax\n    jb .L_compact_registers_l3c_overflow"));
        assert!(validation.contains("jne .L_compact_registers_l3c_overflow"));
        assert!(validation.contains("incq %rcx\n    movq %rcx, (%r8)"));
        assert!(
            !validation
                .lines()
                .any(|line| line.trim_end().ends_with("(%r10)")),
            "event validation must precede every destination store"
        );

        let expected = [
            ("r", 29, &["movq", "movq", "movq", "movl", "movb"][..]),
            ("i", 21, &["movq", "movq", "movl", "movb"][..]),
            ("branch", 21, &["movq", "movq", "movl", "movb"][..]),
            ("j", 14, &["movq", "movl", "movw"][..]),
            ("load", 29, &["movq", "movq", "movq", "movl", "movb"][..]),
            ("store", 29, &["movq", "movq", "movq", "movl", "movb"][..]),
            ("exceptional", 18, &["movq", "movq", "movw"][..]),
            ("header", 6, &["movl", "movw"][..]),
        ];
        for (index, (family, size, mnemonics)) in expected.iter().enumerate() {
            let label = format!(".L_compact_registers_l3c_{family}:\n");
            let body = recorder.split(&label).nth(1).unwrap();
            let body = if let Some((next_family, _, _)) = expected.get(index + 1) {
                body.split(&format!(".L_compact_registers_l3c_{next_family}:\n"))
                    .next()
                    .unwrap()
            } else {
                body
            };
            let stores = body
                .lines()
                .filter(|line| line.contains("(%r10)"))
                .collect::<Vec<_>>();
            assert_eq!(stores.len(), mnemonics.len(), "L5C {family} store count");
            for (store, mnemonic) in stores.iter().zip(*mnemonics) {
                assert!(store.trim_start().starts_with(mnemonic));
                assert!(
                    store.trim_end().ends_with("(%r10)"),
                    "destination load/RMW: {store}"
                );
            }
            assert!(body.contains(&format!("    addq ${size}, %r9")));
        }
        assert!(!recorder.contains("0xa5a5"));
        assert!(!recorder.contains("memset"));
        assert!(!recorder.contains("StepRecord"));
        assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
        assert!(!assembly.contains("ceno_aot_fulltracer_emit_step:"));
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

        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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
        let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
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

    #[test]
    #[cfg(not(debug_assertions))]
    fn gpu_replay_direct_typed_rows_match_interpreter_without_trace_callbacks() {
        let base = CENO_PLATFORM.heap.start;
        let pc_base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
            encode_rv32(InsnKind::BEQ, 1, 0, 0, 8),
            encode_rv32(InsnKind::LUI, 0, 0, 4, 0x12000),
            encode_rv32(InsnKind::JAL, 0, 0, 12, 4),
            encode_rv32(InsnKind::JALR, 11, 0, 7, 0),
            encode_rv32(InsnKind::SW, 20, 2, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let mut family_counts = [0usize; InsnKind::COUNT];
        family_counts[InsnKind::ADDI as usize] = 1;
        family_counts[InsnKind::ADD as usize] = 1;
        family_counts[InsnKind::BEQ as usize] = 1;
        family_counts[InsnKind::LUI as usize] = 1;
        family_counts[InsnKind::JAL as usize] = 1;
        family_counts[InsnKind::JALR as usize] = 1;
        family_counts[InsnKind::SW as usize] = 1;
        family_counts[InsnKind::LW as usize] = 1;
        let descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
            shard_id: 0,
            sequence: 0,
            range_start: 0,
            range_len: 9,
            family_counts,
            fallback_count: 1,
            unsupported_count: 0,
        }]);
        let config = crate::GpuReplayTracerConfig { chunk_capacity: 9 };

        let mut interp = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config,
        );
        interp
            .tracer_mut()
            .install_range_descriptors(descriptors.clone());
        interp.init_register_unsafe(20, base);
        interp.init_register_unsafe(11, pc_base + 24);
        interp.init_memory(ByteAddr(base).waddr(), 0);
        while interp.next_step_record().unwrap().is_some() {}
        interp.tracer_mut().finish_chunks();
        let expected = interp.tracer_mut().take_sealed_chunks().remove(0);

        let aot = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            vec![pc_base + 24],
            AssemblyTraceStyle::GpuReplayDirect,
        )
        .unwrap();
        let mut direct = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program,
            config,
        );
        direct.tracer_mut().install_range_descriptors(descriptors);
        direct.init_register_unsafe(20, base);
        direct.init_register_unsafe(11, pc_base + 24);
        direct.init_memory(ByteAddr(base).waddr(), 0);
        // Force two returns in the middle of one compiled basic block. The
        // next entry must use the native resume table, never dynamic-PC Rust
        // fallback.
        let reports = (0..9)
            .map(|_| aot.run_to_halt(&mut direct, 1).unwrap())
            .collect::<Vec<_>>();
        direct.tracer_mut().finish_chunks();
        let actual = direct.tracer_mut().take_sealed_chunks().remove(0);

        assert_eq!(
            reports
                .iter()
                .map(|report| report.executed_steps)
                .sum::<usize>(),
            9
        );
        assert_eq!(
            reports
                .iter()
                .map(|report| report.fallback_steps)
                .sum::<usize>(),
            1
        );
        assert_eq!(
            reports
                .iter()
                .map(|report| report.fallback.dynamic_pc_miss)
                .sum::<usize>(),
            0
        );
        assert_eq!(actual.sequence, expected.sequence);
        for (kind_index, (actual, expected)) in actual.typed.iter().zip(&expected.typed).enumerate()
        {
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::kind),
                expected.as_ref().map(crate::GpuTypedSoaArena::kind)
            );
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::len),
                expected.as_ref().map(crate::GpuTypedSoaArena::len)
            );
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::fields),
                expected.as_ref().map(crate::GpuTypedSoaArena::fields)
            );
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::payload_bytes),
                expected
                    .as_ref()
                    .map(crate::GpuTypedSoaArena::payload_bytes),
                "kind={:?}",
                InsnKind::iter().nth(kind_index)
            );
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::pc_base),
                expected.as_ref().map(crate::GpuTypedSoaArena::pc_base)
            );
        }
        assert_eq!(actual.fallback, expected.fallback);
        assert_eq!(AOT_NATIVE_CALLBACK_TRACE.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn i061_l8_gpu_replay_packed_whole_blocks_match_interpreter_initialized_prefixes() {
        let heap = CENO_PLATFORM.heap.start;
        let pc_base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
            // rs1/rs2/rd alias: predecessors must advance in subcycle order.
            encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
            encode_rv32(InsnKind::BEQ, 1, 0, 0, 8),
            encode_rv32(InsnKind::LUI, 0, 0, 4, 0x12000),
            encode_rv32(InsnKind::JAL, 0, 0, 12, 4),
            // rs1/rd alias while the target still uses the before value.
            encode_rv32(InsnKind::JALR, 11, 0, 11, 0),
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        macro_rules! initialize {
            ($vm:expr) => {{
                $vm.init_register_unsafe(20, heap);
                $vm.init_register_unsafe(11, pc_base + 24);
                $vm.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
                $vm.init_memory(ByteAddr(heap).waddr(), 0);
            }};
        }

        // Build a nonempty tape covering every enabled ordinary access. Both
        // implementations must consume it in exact source-cycle/subcycle order.
        let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 10 },
        );
        initialize!(seed);
        while seed.next_step_record().unwrap().is_some() {}
        let mut events = Vec::new();
        for record in seed.tracer().recorded_steps() {
            for (subcycle, address) in [
                (
                    crate::FullTracer::SUBCYCLE_RS1,
                    record.rs1().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_RS2,
                    record.rs2().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_RD,
                    record.rd().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_MEM,
                    record.memory_op().map(|op| op.addr),
                ),
            ] {
                if let Some(address) = address {
                    let source = record.cycle() + subcycle;
                    events.push(NextAccessEvent::new(source, source + 1_000_000, address));
                }
            }
        }
        assert!(!events.is_empty());
        let tape = Arc::new(NextCycleAccess::from_unsorted(events));

        let mut family_counts = [0usize; InsnKind::COUNT];
        for kind in [
            InsnKind::ADDI,
            InsnKind::ADD,
            InsnKind::BEQ,
            InsnKind::LUI,
            InsnKind::JAL,
            InsnKind::JALR,
            InsnKind::SW,
            InsnKind::LW,
        ] {
            family_counts[kind as usize] = 1;
        }
        let descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
            shard_id: 0,
            sequence: 0,
            range_start: 0,
            range_len: 9,
            family_counts,
            fallback_count: 1,
            unsupported_count: 0,
        }]);
        let config = crate::GpuReplayTracerConfig { chunk_capacity: 10 };

        let mut expected =
            VMState::<crate::GpuReplayTracer>::new_with_tracer_config_and_next_accesses(
                CENO_PLATFORM.clone(),
                program.clone(),
                config,
                Some(tape.clone()),
            );
        expected
            .tracer_mut()
            .install_range_descriptors(descriptors.clone());
        initialize!(expected);
        while expected.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            vec![pc_base + 24],
            AssemblyTraceStyle::GpuReplayDirect,
        )
        .unwrap();
        let mut actual =
            VMState::<crate::GpuReplayTracer>::new_with_tracer_config_and_next_accesses(
                CENO_PLATFORM.clone(),
                program,
                config,
                Some(tape.clone()),
            );
        actual.tracer_mut().install_range_descriptors(descriptors);
        initialize!(actual);
        let report = aot.run_to_halt(&mut actual, 10).unwrap();
        assert_eq!(report.executed_steps, 9);
        assert_eq!(report.fallback_steps, 1);
        assert_eq!(actual.get_pc(), expected.get_pc());
        assert_eq!(actual.peek_register(1), expected.peek_register(1));
        assert_eq!(actual.peek_memory(ByteAddr(heap).waddr()), 10);

        let snapshot = |tracer: &mut crate::GpuReplayTracer| {
            let state = tracer.prepare_native_range();
            let kinds = unsafe { std::slice::from_raw_parts(state.kinds, state.kind_count) };
            let cursors = kinds
                .iter()
                .map(|kind| {
                    (
                        kind.cursor,
                        kind.capacity,
                        kind.layout,
                        kind.sentinel,
                        kind.range_start,
                        kind.pc_base,
                    )
                })
                .collect::<Vec<_>>();
            unsafe {
                (
                    *state.ordinal,
                    *state.next_access_cursor,
                    *state.latest_len,
                    cursors,
                )
            }
        };
        let expected_snapshot = snapshot(expected.tracer_mut());
        let actual_snapshot = snapshot(actual.tracer_mut());
        assert_eq!(actual_snapshot, expected_snapshot);
        assert_eq!(actual_snapshot.0, 9);
        assert_eq!(actual_snapshot.1, tape.events().len());
        assert_eq!(actual_snapshot.3[InsnKind::ADD as usize].0, 1);
        assert_eq!(actual_snapshot.3[InsnKind::ADD as usize].4, 0);

        let mut addresses = expected
            .tracer()
            .final_register_accesses()
            .addresses()
            .chain(actual.tracer().final_register_accesses().addresses())
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        assert!(!addresses.is_empty());
        for address in addresses {
            assert_eq!(
                actual.tracer().final_register_accesses().cycle(address),
                expected.tracer().final_register_accesses().cycle(address),
                "latest state at {address:?}"
            );
        }

        expected.tracer_mut().finish_chunks();
        actual.tracer_mut().finish_chunks();
        let expected = expected.tracer_mut().take_sealed_chunks().remove(0);
        let actual = actual.tracer_mut().take_sealed_chunks().remove(0);
        for (kind_index, (actual, expected)) in actual.typed.iter().zip(&expected.typed).enumerate()
        {
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::len),
                expected.as_ref().map(crate::GpuTypedSoaArena::len)
            );
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::range_start),
                expected.as_ref().map(crate::GpuTypedSoaArena::range_start)
            );
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::pc_base),
                expected.as_ref().map(crate::GpuTypedSoaArena::pc_base)
            );
            assert_eq!(
                actual.as_ref().map(crate::GpuTypedSoaArena::payload_bytes),
                expected
                    .as_ref()
                    .map(crate::GpuTypedSoaArena::payload_bytes),
                "kind={:?}",
                InsnKind::iter().nth(kind_index)
            );
        }
        assert_eq!(actual.fallback, expected.fallback);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn i061_l8_gpu_replay_packed_fallback_errors_leave_no_gap_or_duplicate_on_retry() {
        let heap = CENO_PLATFORM.heap.start;
        let pc_base = CENO_PLATFORM.pc_base();

        let memory_program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 0)]));
        let mut memory_counts = [0usize; InsnKind::COUNT];
        memory_counts[InsnKind::LW as usize] = 1;
        let memory_descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
            shard_id: 0,
            sequence: 0,
            range_start: 0,
            range_len: 1,
            family_counts: memory_counts,
            fallback_count: 0,
            unsupported_count: 0,
        }]);
        let config = crate::GpuReplayTracerConfig { chunk_capacity: 3 };
        let memory_aot = AotProgram::compile_with_extra_roots_and_trace_style(
            memory_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::GpuReplayDirect,
        )
        .unwrap();
        let mut memory = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            memory_program.clone(),
            config,
        );
        memory
            .tracer_mut()
            .install_range_descriptors(memory_descriptors.clone());
        memory.init_register_unsafe(20, heap + 1);
        let error = memory_aot
            .run_to_halt(&mut memory, 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rejected fallback category 2"));
        let rolled = memory.tracer_mut().prepare_native_range();
        assert_eq!(unsafe { *rolled.ordinal }, 0);
        assert_eq!(
            unsafe { (*rolled.kinds.add(InsnKind::LW as usize)).cursor },
            0
        );

        memory.init_register_unsafe(20, heap);
        memory.init_memory(ByteAddr(heap).waddr(), 0x1122_3344);
        memory.set_pc(ByteAddr(pc_base));
        let retry = memory_aot.run_to_halt(&mut memory, 1).unwrap();
        assert_eq!(retry.executed_steps, 1);
        let retried = memory.tracer_mut().prepare_native_range();
        assert_eq!(unsafe { *retried.ordinal }, 1);
        assert_eq!(
            unsafe { (*retried.kinds.add(InsnKind::LW as usize)).cursor },
            1
        );

        let jalr_program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 11, 0, 11, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let mut jalr_counts = [0usize; InsnKind::COUNT];
        jalr_counts[InsnKind::JALR as usize] = 1;
        let jalr_descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
            shard_id: 0,
            sequence: 0,
            range_start: 0,
            range_len: 2,
            family_counts: jalr_counts,
            fallback_count: 1,
            unsupported_count: 0,
        }]);
        let jalr_aot = AotProgram::compile_with_extra_roots_and_trace_style(
            jalr_program.clone(),
            vec![pc_base + 4],
            AssemblyTraceStyle::GpuReplayDirect,
        )
        .unwrap();
        let mut jalr = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            jalr_program.clone(),
            config,
        );
        jalr.tracer_mut()
            .install_range_descriptors(jalr_descriptors.clone());
        jalr.init_register_unsafe(11, pc_base + 2);
        jalr.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        let error = jalr_aot.run_to_halt(&mut jalr, 2).unwrap_err().to_string();
        assert!(error.contains("InstructionAddressMisaligned"));
        let rolled = jalr.tracer_mut().prepare_native_range();
        assert_eq!(unsafe { *rolled.ordinal }, 0);
        assert_eq!(
            unsafe { (*rolled.kinds.add(InsnKind::JALR as usize)).cursor },
            0
        );

        // A trapped interpreter step retains partial pending tracer state, so
        // resume semantics are validated from a fresh VM at the same PC. The
        // failed owner above must nevertheless remain completely unpublished.
        let mut jalr_retry = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            jalr_program.clone(),
            config,
        );
        jalr_retry
            .tracer_mut()
            .install_range_descriptors(jalr_descriptors.clone());
        jalr_retry.init_register_unsafe(11, pc_base + 4);
        jalr_retry.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        let retry = jalr_aot.run_to_halt(&mut jalr_retry, 2).unwrap();
        assert_eq!(retry.executed_steps, 2);
        assert_eq!(retry.fallback_steps, 1);
        let retried = jalr_retry.tracer_mut().prepare_native_range();
        assert_eq!(unsafe { *retried.ordinal }, 2);
        assert_eq!(
            unsafe { (*retried.kinds.add(InsnKind::JALR as usize)).cursor },
            1
        );

        let mut expected = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            jalr_program,
            config,
        );
        expected
            .tracer_mut()
            .install_range_descriptors(jalr_descriptors);
        expected.init_register_unsafe(11, pc_base + 4);
        expected.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        while expected.next_step_record().unwrap().is_some() {}
        expected.tracer_mut().finish_chunks();
        jalr_retry.tracer_mut().finish_chunks();
        let expected = expected.tracer_mut().take_sealed_chunks().remove(0);
        let actual = jalr_retry.tracer_mut().take_sealed_chunks().remove(0);
        assert_eq!(
            actual.typed[InsnKind::JALR as usize]
                .as_ref()
                .unwrap()
                .payload_bytes(),
            expected.typed[InsnKind::JALR as usize]
                .as_ref()
                .unwrap()
                .payload_bytes()
        );
        assert_eq!(actual.fallback, expected.fallback);
    }

    #[test]
    fn production_preflight_uses_admitted_block_emitter() {
        assert_eq!(
            production_preflight_trace_style(),
            AssemblyTraceStyle::PreflightProduction
        );
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let model = crate::StepCellExtractor::shard_cost_model(&OneCellPerNativeStep).unwrap();
        let planner_metadata = build_aot_block_cost_descriptors(&program, &blocks, &model).unwrap();
        let cache = tempfile::tempdir().unwrap();
        let production = cache.path().join("production.S");
        write_assembly_with_planner(
            &production,
            &program,
            &blocks,
            &order,
            production_preflight_trace_style(),
            Some(&planner_metadata),
        )
        .unwrap();
        let production = fs::read(production).unwrap();
        let assembly = String::from_utf8(production).unwrap();
        assert!(assembly.contains("preflight_bucket_special_fail"));
        assert!(!assembly.contains(".L_preflight_cost_loop_0:"));
    }

    #[test]
    fn i049_capture_requires_memory_address_when_release_events_emit_early() {
        let trace_style = AssemblyTraceStyle::PreflightProductionCapture;
        assert!(trace_style.needs_callback_values());
        assert!(!trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds));
        assert!(trace_style.uses_preflight_block_plan());
        assert!(should_publish_trace_memory_address(
            trace_style,
            false,
            true
        ));
        assert!(!should_publish_trace_memory_address(
            AssemblyTraceStyle::PreflightProduction,
            false,
            true,
        ));
    }

    #[test]
    fn preflight_compact_closure_l7_assembly_admits_transactionally_and_uses_static_ranks() {
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
            encode_rv32(InsnKind::ADDI, 2, 0, 3, 1),
            encode_rv32(InsnKind::ADD, 2, 3, 4, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let dir = tempfile::tempdir().unwrap();
        let assembly_path = dir.path().join("l7.S");
        write_assembly_with_planner(
            &assembly_path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactClosureL7,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(assembly_path).unwrap();
        let admission_end = assembly
            .find(&format!(
                ".L_l7_admission_done_{:08x}:\n",
                CENO_PLATFORM.pc_base()
            ))
            .unwrap();
        let admission = &assembly[..admission_end];
        let first_publication = admission.find("addl $2, 108(%r10)").unwrap();
        let last_capacity_check = admission.rfind("ja .L_l7_admission_error_").unwrap();
        assert!(last_capacity_check < first_publication);
        assert_eq!(admission.matches("addl $2, 108(%r10)").count(), 2);

        // Both interleaved families address final_cursor-2 then
        // final_cursor-1. The latter needs no restoration.
        assert_eq!(assembly.matches("subl $2, 108(%r10)").count(), 2);
        assert_eq!(assembly.matches("subl $1, 108(%r10)").count(), 2);
        assert_eq!(
            l7_block_family_rank(
                &program,
                CENO_PLATFORM.pc_base(),
                CENO_PLATFORM.pc_base() + 16,
                CENO_PLATFORM.pc_base() + 8,
                InsnKind::ADDI,
            )
            .unwrap(),
            (2, 1)
        );
        assert_eq!(
            l7_block_family_rank(
                &program,
                CENO_PLATFORM.pc_base(),
                CENO_PLATFORM.pc_base() + 16,
                CENO_PLATFORM.pc_base() + 12,
                InsnKind::ADD,
            )
            .unwrap(),
            (2, 1)
        );
        let u_packer = assembly
            .split(".L_gpu_compact_pack_u:\n")
            .nth(1)
            .unwrap()
            .split("// Assemble the common 63-bit prefix")
            .next()
            .unwrap();
        assert_eq!(
            u_packer
                .lines()
                .filter(|line| line.contains("(%r9)"))
                .collect::<Vec<_>>(),
            [
                "    movq %r8, 0(%r9)",
                "    movq %r8, 8(%r9)",
                "    movl %r8d, 16(%r9)",
            ]
        );
        assert!(!assembly.contains("ceno_aot_fulltracer_emit_step:"));
        assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
        assert!(!assembly.contains("memset"));
        assert!(!assembly.contains("StepRecord"));
    }

    #[test]
    fn i061_l8_gpu_replay_packed_blocks_use_transactional_static_exact_stores() {
        let layout_program = program(vec![
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
            encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
            encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
            encode_rv32(InsnKind::JALR, 1, 0, 3, 0),
            encode_rv32(InsnKind::LW, 20, 0, 3, 0),
            encode_rv32(InsnKind::SW, 20, 2, 0, 0),
            encode_rv32(InsnKind::LUI, 0, 0, 3, 0x12000),
        ]);
        let blocks = partition_basic_blocks_with_roots(
            &layout_program,
            (0..layout_program.instructions.len())
                .map(|index| CENO_PLATFORM.pc_base() + (index * PC_STEP_SIZE) as u32)
                .collect(),
        )
        .unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let dir = tempfile::tempdir().unwrap();
        let assembly_path = dir.path().join("l8-packed.S");
        write_assembly_with_planner(
            &assembly_path,
            &layout_program,
            &blocks,
            &order,
            AssemblyTraceStyle::GpuReplayDirect,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(assembly_path).unwrap();

        let admission_end = assembly
            .find(&format!(
                ".L_l7_admission_done_{:08x}:\n",
                CENO_PLATFORM.pc_base()
            ))
            .unwrap();
        let admission = &assembly[..admission_end];
        assert!(
            admission.rfind("ja .L_l7_admission_error_").unwrap()
                < admission.find("addl $1, 108(%r10)").unwrap()
        );
        assert!(assembly.contains(&format!(
            "movl $1, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
        )));

        let expected = [
            (0usize, 6usize),
            (1, 3),
            (2, 3),
            (3, 2),
            (4, 3),
            (5, 6),
            (6, 6),
            (7, 3),
        ];
        for (instruction_index, expected_stores) in expected {
            let pc = CENO_PLATFORM.pc_base() + (instruction_index * PC_STEP_SIZE) as u32;
            let body = assembly
                .split(&format!(".L_gpu_replay_packed_static_{pc:x}:\n"))
                .nth(1)
                .unwrap()
                .split(&format!(".L_gpu_replay_emit_done_{pc:x}:\n"))
                .next()
                .unwrap();
            assert!(!body.contains("call ceno_aot_gpu_replay_emit_step"));
            assert!(!body.contains("call .L_gpu_compact_pack_common"));
            assert!(!body.contains("movq 8(%r9)"));
            let stores = body
                .lines()
                .filter(|line| {
                    line.contains("movq %r8, ")
                        || line.contains("movl %r8d, ")
                        || line.contains("movw %r8w, ")
                        || line.contains("movb %r8b, ")
                })
                .filter(|line| line.contains("(%r9)"))
                .count();
            assert_eq!(stores, expected_stores, "packed stores at {pc:#010x}");
            if expected_stores == 6 {
                assert!(body.contains("movl %r8d, 24(%r9)"));
                assert!(body.contains("movw %r8w, 28(%r9)"));
                assert!(body.contains("movb %r8b, 30(%r9)"));
                assert!(!body.contains("movq %r8, 24(%r9)"));
            }
            if instruction_index == 7 {
                assert!(body.contains(&format!(
                    "movl {AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET}(%r12), %eax"
                )));
                assert!(!body.contains("xorl %eax, %eax"));
            }
        }

        let memory_slow = assembly
            .split(&format!(
                ".L_memory_slow_{:x}:\n",
                CENO_PLATFORM.pc_base() + 5 * PC_STEP_SIZE as u32
            ))
            .nth(1)
            .unwrap()
            .split(".popsection")
            .next()
            .unwrap();
        assert!(memory_slow.contains("subl $1, 108(%r10)"));
        assert!(
            memory_slow.find("subl $1, 108(%r10)").unwrap()
                < memory_slow.find("call *72(%rsp)").unwrap()
        );
        assert!(!memory_slow.contains("addl $1, 108(%r10)"));

        let jalr_slow = assembly
            .split(&format!(
                ".L_jalr_slow_{:x}:\n",
                CENO_PLATFORM.pc_base() + 4 * PC_STEP_SIZE as u32
            ))
            .nth(1)
            .unwrap()
            .split(&format!(
                ".L_jalr_done_{:x}:\n",
                CENO_PLATFORM.pc_base() + 4 * PC_STEP_SIZE as u32
            ))
            .next()
            .unwrap();
        assert!(jalr_slow.contains("subq $1, 0(%rsp)"));
        assert!(jalr_slow.contains("subl $1, 108(%r10)"));
        assert!(
            jalr_slow.find("subq $1, 0(%rsp)").unwrap() < jalr_slow.find("call *72(%rsp)").unwrap()
        );
        assert!(
            jalr_slow.find("subl $1, 108(%r10)").unwrap()
                < jalr_slow.find("call *72(%rsp)").unwrap()
        );
        assert!(!jalr_slow.contains("addl $1, 108(%r10)"));

        // A nonterminal memory row rolls back the current and all later
        // reservations before the callback, then republishes only the rows
        // that remain after the callback-owned current row.
        let memory_program = program(vec![
            encode_rv32(InsnKind::SW, 20, 1, 0, 0),
            encode_rv32(InsnKind::LW, 20, 0, 2, 4),
            encode_rv32(InsnKind::SW, 20, 2, 0, 8),
            encode_rv32(InsnKind::LW, 20, 0, 3, 12),
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        ]);
        let memory_blocks = partition_basic_blocks(&memory_program).unwrap();
        let memory_order = memory_blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let memory_path = dir.path().join("l8-memory-remaining.S");
        write_assembly_with_planner(
            &memory_path,
            &memory_program,
            &memory_blocks,
            &memory_order,
            AssemblyTraceStyle::GpuReplayDirect,
            None,
        )
        .unwrap();
        let memory_assembly = fs::read_to_string(memory_path).unwrap();
        let memory_slow = memory_assembly
            .split(&format!(".L_memory_slow_{:x}:\n", CENO_PLATFORM.pc_base()))
            .nth(1)
            .unwrap()
            .split(".popsection")
            .next()
            .unwrap();
        for expected in ["subq $5, 0(%rsp)", "subl $2, 108(%r10)"] {
            assert!(memory_slow.contains(expected));
            assert!(
                memory_slow.find(expected).unwrap() < memory_slow.find("call *72(%rsp)").unwrap()
            );
        }
        for expected in ["addl $1, 108(%r10)", "addq $4, 0(%rsp)"] {
            assert!(memory_slow.contains(expected));
            assert!(
                memory_slow.find("call *72(%rsp)").unwrap() < memory_slow.find(expected).unwrap()
            );
        }
        for (index, expected_from_end) in [(0usize, 5u64), (1, 4), (2, 3), (3, 2)] {
            let pc = CENO_PLATFORM.pc_base() + (index * PC_STEP_SIZE) as u32;
            let body = memory_assembly
                .split(&format!(".L_memory_body_{pc:x}:\n"))
                .nth(1)
                .unwrap()
                .split(&format!(".L_fulltracer_direct_done_{pc:x}:\n"))
                .next()
                .unwrap();
            assert!(body.contains(&format!(
                "cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
            )));
            assert!(body.contains(&format!("subq ${expected_from_end}, %rcx")));
        }

        let rank_program = program(vec![
            encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
            encode_rv32(InsnKind::ADDI, 3, 0, 3, 1),
            encode_rv32(InsnKind::ADD, 3, 2, 3, 0),
        ]);
        let rank_blocks = partition_basic_blocks(&rank_program).unwrap();
        let rank_order = rank_blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let rank_path = dir.path().join("l8-static-ranks.S");
        write_assembly_with_planner(
            &rank_path,
            &rank_program,
            &rank_blocks,
            &rank_order,
            AssemblyTraceStyle::GpuReplayDirect,
            None,
        )
        .unwrap();
        let rank_assembly = fs::read_to_string(rank_path).unwrap();
        for (index, expected_rank_from_end) in [(0usize, 2u32), (2, 1)] {
            let pc = CENO_PLATFORM.pc_base() + (index * PC_STEP_SIZE) as u32;
            let body = rank_assembly
                .split(&format!(".L_gpu_replay_packed_static_{pc:x}:\n"))
                .nth(1)
                .unwrap()
                .split(&format!(".L_gpu_replay_emit_done_{pc:x}:\n"))
                .next()
                .unwrap();
            assert!(body.contains(&format!("subl ${expected_rank_from_end}, %eax")));
        }
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn preflight_compact_closure_l7_matches_compact_oracle_across_capacity_boundaries() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
            encode_rv32(InsnKind::ADDI, 2, 0, 3, 1),
            encode_rv32(InsnKind::ADD, 2, 3, 4, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactClosureL7,
        )
        .unwrap();

        for capacity in [3, 4, 5] {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig {
                    max_step_shard: capacity,
                },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
            actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            let actual_report = l7.run_pure_to_halt(&mut actual, capacity).unwrap();
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(actual.get_pc(), reference.get_pc());

            for kind in [InsnKind::ADDI, InsnKind::ADD] {
                let expected = reference
                    .tracer()
                    .recorded_steps()
                    .iter()
                    .enumerate()
                    .filter(|(_, record)| record.insn().kind == kind)
                    .collect::<Vec<_>>();
                let mut oracle =
                    crate::GpuTypedSoaArena::new_compact_with_range(kind, expected.len(), 0)
                        .unwrap();
                for (ordinal, record) in expected {
                    oracle.push_step(ordinal as u32, record).unwrap();
                }
                let actual = actual_report
                    .l7_family_payloads
                    .iter()
                    .find(|(actual_kind, _, _, _)| *actual_kind == kind)
                    .unwrap();
                assert_eq!(actual.1, oracle.range_start());
                assert_eq!(actual.2, oracle.pc_base());
                assert_eq!(
                    actual.3,
                    oracle.payload_bytes(),
                    "kind={kind:?}, capacity={capacity}"
                );
            }
        }
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn preflight_compact_closure_l7_matches_every_layout_scalar_native_and_repeat() {
        let base = CENO_PLATFORM.pc_base();
        let heap = CENO_PLATFORM.heap.start;
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
            encode_rv32(InsnKind::LUI, 0, 0, 3, 0x1000),
            encode_rv32(InsnKind::LW, 20, 0, 4, 0),
            encode_rv32(InsnKind::SW, 20, 4, 0, 4),
            encode_rv32(InsnKind::BNE, 1, 0, 0, 4),
            encode_rv32(InsnKind::JAL, 0, 0, 7, 4),
            encode_rv32(InsnKind::JALR, 22, 0, 8, 0),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            vec![base + 32],
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            vec![base + 32],
            AssemblyTraceStyle::PreflightCompactClosureL7,
        )
        .unwrap();

        for capacities in [&[1usize; 9][..], &[16usize][..]] {
            let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
                CENO_PLATFORM.clone(),
                program.clone(),
                crate::FullTracerConfig { max_step_shard: 16 },
            );
            let mut actual =
                VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
            for vm in [
                &mut reference as &mut dyn SyscallTestVm,
                &mut actual as &mut dyn SyscallTestVm,
            ] {
                vm.init_register(20, heap);
                vm.init_register(22, base + 32);
                vm.init_register(Platform::reg_ecall(), Platform::ecall_halt());
                vm.init_word(ByteAddr(heap).waddr(), 0x1122_3344);
                vm.init_word(ByteAddr(heap + 4).waddr(), 0);
            }

            for &capacity in capacities {
                let start = reference.tracer().recorded_steps().len();
                let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
                reference.tracer_mut().annotate_recorded_steps(start);
                let actual_report = l7.run_pure_to_halt(&mut actual, capacity).unwrap();
                let expected = &reference.tracer().recorded_steps()
                    [start..start + expected_report.executed_steps];
                assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
                assert_eq!(actual.get_pc(), reference.get_pc());

                let mut expected_family_bytes = 0;
                for kind in [
                    InsnKind::ADD,
                    InsnKind::ADDI,
                    InsnKind::BNE,
                    InsnKind::JAL,
                    InsnKind::JALR,
                    InsnKind::LW,
                    InsnKind::SW,
                    InsnKind::LUI,
                ] {
                    let records = expected
                        .iter()
                        .enumerate()
                        .filter(|(_, record)| record.insn().kind == kind)
                        .collect::<Vec<_>>();
                    if records.is_empty() {
                        continue;
                    }
                    let mut oracle =
                        crate::GpuTypedSoaArena::new_compact_with_range(kind, records.len(), 0)
                            .unwrap();
                    for (ordinal, record) in records {
                        oracle.push_step(ordinal as u32, record).unwrap();
                    }
                    expected_family_bytes += oracle.payload_bytes().len();
                    let routed = actual_report
                        .l7_family_payloads
                        .iter()
                        .find(|(actual_kind, _, _, _)| *actual_kind == kind)
                        .unwrap();
                    assert_eq!(routed.1, oracle.range_start(), "kind={kind:?}");
                    assert_eq!(routed.2, oracle.pc_base(), "kind={kind:?}");
                    assert_eq!(routed.3, oracle.payload_bytes(), "kind={kind:?}");
                }
                assert_eq!(
                    actual_report
                        .l7_family_payloads
                        .iter()
                        .map(|(_, _, _, payload)| payload.len())
                        .sum::<usize>(),
                    expected_family_bytes
                );
                assert_eq!(
                    actual_report.l6_syscall_witnesses,
                    reference.tracer().syscall_witnesses()
                );
                if actual.halted() {
                    break;
                }
            }
            assert!(actual.halted());
            assert_eq!(actual.peek_register(2), 2);
            assert_eq!(actual.peek_memory(ByteAddr(heap + 4).waddr()), 0x1122_3344);
            assert_eq!(actual.tracer().layered_compact_l6_syscalls.len(), 1);
            assert_eq!(
                actual.tracer().layered_compact_l6_syscalls[0].syscall_index(),
                crate::StepRecord::NO_SYSCALL
            );
            assert_eq!(actual.tracer().layered_compact_l6_ops.len(), 1);
        }
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn preflight_compact_closure_l7_reuses_reserved_row_after_memory_guard() {
        let heap = CENO_PLATFORM.heap.start;
        // The second load makes the block-wide guard reject, while the first
        // load remains a successful scalar memory-guard fallback. The later
        // trap keeps this fixture bounded; the assembly assertions prove that
        // the successful fallback targets and restores its reserved L7 row.
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::LW, 20, 0, 1, 0),
            encode_rv32(InsnKind::LW, 21, 0, 2, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
            program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactClosureL7,
        )
        .unwrap();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 2 },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        for vm in [
            &mut reference as &mut dyn SyscallTestVm,
            &mut actual as &mut dyn SyscallTestVm,
        ] {
            vm.init_register(20, heap);
            vm.init_register(21, heap + 1);
            vm.init_word(ByteAddr(heap).waddr(), 0x1122_3344);
        }

        let expected = direct
            .run_to_halt(&mut reference, 2)
            .unwrap_err()
            .to_string();
        let observed = l7.run_pure_to_halt(&mut actual, 2).unwrap_err().to_string();
        assert!(expected.contains("LoadAddressMisaligned"));
        assert_eq!(observed, expected);
        assert_eq!(actual.peek_register(1), 0x1122_3344);
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.tracer().cycle(), reference.tracer().cycle());

        let blocks = partition_basic_blocks(&program).unwrap();
        let order = blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l7-memory-guard.S");
        write_assembly_with_planner(
            &path,
            &program,
            &blocks,
            &order,
            AssemblyTraceStyle::PreflightCompactClosureL7,
            None,
        )
        .unwrap();
        let assembly = fs::read_to_string(path).unwrap();
        let slow = assembly
            .split(&format!(".L_memory_slow_{:x}:\n", CENO_PLATFORM.pc_base()))
            .nth(1)
            .unwrap()
            .split(".popsection")
            .next()
            .unwrap();
        assert!(slow.contains("subl $2, 108(%r10)"));
        assert!(slow.contains("call *72(%rsp)"));
        assert!(slow.contains("addl $1, 108(%r10)"));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn preflight_compact_closure_l7_preserves_multi_op_and_trap_side_totals() {
        let heap = CENO_PLATFORM.heap.start;
        let syscall_program = Arc::new(program(vec![
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            encode_rv32(
                InsnKind::ADDI,
                0,
                0,
                Platform::reg_ecall().into(),
                Platform::ecall_halt() as i32,
            ),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let direct = AotProgram::compile_with_extra_roots_and_trace_style(
            syscall_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::FullTracerDirect,
        )
        .unwrap();
        let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
            syscall_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactClosureL7,
        )
        .unwrap();
        let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
            crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            syscall_program.clone(),
            crate::FullTracerConfig { max_step_shard: 3 },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program);
        for vm in [
            &mut reference as &mut dyn SyscallTestVm,
            &mut actual as &mut dyn SyscallTestVm,
        ] {
            vm.init_register(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
            vm.init_register(Platform::reg_arg0(), heap);
            for (offset, value) in input.into_iter().enumerate() {
                vm.init_word(ByteAddr(heap).waddr() + offset, value);
            }
        }
        direct.run_to_halt(&mut reference, 3).unwrap();
        reference.tracer_mut().annotate_recorded_steps(0);
        let report = l7.run_pure_to_halt(&mut actual, 3).unwrap();
        assert_eq!(
            report.l6_syscall_witnesses,
            reference.tracer().syscall_witnesses()
        );
        assert_eq!(actual.tracer().layered_compact_l6_syscalls.len(), 2);
        assert_eq!(
            actual.tracer().layered_compact_l6_syscalls.len()
                * std::mem::size_of::<CompactL6SyscallHeader>(),
            60
        );
        let expected_ops = report
            .l6_syscall_witnesses
            .iter()
            .map(|witness| witness.reg_ops.len() + witness.mem_ops.len())
            .sum::<usize>()
            + 1;
        assert_eq!(actual.tracer().layered_compact_l6_ops.len(), expected_ops);
        assert_eq!(
            actual.tracer().layered_compact_l6_ops.len() * std::mem::size_of::<CompactL6WriteOp>(),
            expected_ops * 20
        );

        let trap_program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
        let trap_l7 = AotProgram::compile_with_extra_roots_and_trace_style(
            trap_program.clone(),
            Vec::new(),
            AssemblyTraceStyle::PreflightCompactClosureL7,
        )
        .unwrap();
        let mut trap =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
        trap.init_register_unsafe(20, heap);
        let err = trap_l7
            .run_pure_to_halt(&mut trap, 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("LoadAddressMisaligned"));
        assert_eq!(trap.tracer().layered_compact_l6_syscalls.len(), 0);
        assert_eq!(trap.tracer().layered_compact_l6_ops.len(), 0);
        assert_eq!(trap.tracer().layered_compact_syscall_masks.len(), 0);
    }

    #[test]
    fn planner_aware_parallel_compile_links() {
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);
        let blocks = partition_basic_blocks(&program).unwrap();
        let layout = pc_order_layout(&blocks);
        let model = crate::StepCellExtractor::shard_cost_model(&OneCellPerNativeStep).unwrap();
        let planner_metadata = build_aot_block_cost_descriptors(&program, &blocks, &model).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let asm = dir.path().join("program.S");
        let so = dir.path().join("program.so");

        compile_native_to_with_jobs(
            &program,
            &blocks,
            &layout.emission_order,
            production_preflight_trace_style(),
            Some(&planner_metadata),
            &asm,
            &so,
            4,
        )
        .unwrap();

        load_native(&so, "preflight-production", "test").unwrap();
    }
}
