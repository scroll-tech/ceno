/// GPU witness generation dispatcher for the proving pipeline.
///
/// This module provides `try_gpu_assign_instances` which:
/// 1. Runs the GPU kernel to fill the witness matrix (fast)
/// 2. Runs a lightweight CPU loop to collect side effects without witness replay
/// 3. Returns the GPU-generated witness + CPU-collected side effects
use ceno_emul::{StepIndex, StepRecord, WordAddr};
use ceno_gpu::{
    Buffer, CudaHal, CudaSlice, bb31::CudaHalBB31, common::transpose::matrix_transpose,
};
use ceno_gpu::bb31::ShardDeviceBuffers;
use ceno_gpu::common::witgen_types::{GpuRamRecordSlot, GpuShardScalars, RAM_SLOTS_PER_INST};
use ff_ext::ExtensionField;
use gkr_iop::{RAMType, tables::LookupTable, utils::lk_multiplicity::Multiplicity};
use p3::field::FieldAlgebra;
use std::cell::{Cell, RefCell};
use tracing::info_span;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    e2e::{RAMRecord, ShardContext},
    error::ZKVMError,
    instructions::{Instruction, cpu_collect_shard_side_effects, cpu_collect_side_effects},
    tables::RMMCollections,
    witness::LkMultiplicity,
};

#[derive(Debug, Clone, Copy)]
pub enum GpuWitgenKind {
    Add,
    Sub,
    LogicR(u32), // 0=AND, 1=OR, 2=XOR
    #[cfg(feature = "u16limb_circuit")]
    LogicI(u32), // 0=AND, 1=OR, 2=XOR
    #[cfg(feature = "u16limb_circuit")]
    Addi,
    #[cfg(feature = "u16limb_circuit")]
    Lui,
    #[cfg(feature = "u16limb_circuit")]
    Auipc,
    #[cfg(feature = "u16limb_circuit")]
    Jal,
    #[cfg(feature = "u16limb_circuit")]
    ShiftR(u32), // 0=SLL, 1=SRL, 2=SRA
    #[cfg(feature = "u16limb_circuit")]
    ShiftI(u32), // 0=SLLI, 1=SRLI, 2=SRAI
    #[cfg(feature = "u16limb_circuit")]
    Slt(u32), // 1=SLT(signed), 0=SLTU(unsigned)
    #[cfg(feature = "u16limb_circuit")]
    Slti(u32), // 1=SLTI(signed), 0=SLTIU(unsigned)
    #[cfg(feature = "u16limb_circuit")]
    BranchEq(u32), // 1=BEQ, 0=BNE
    #[cfg(feature = "u16limb_circuit")]
    BranchCmp(u32), // 1=signed (BLT/BGE), 0=unsigned (BLTU/BGEU)
    #[cfg(feature = "u16limb_circuit")]
    Jalr,
    #[cfg(feature = "u16limb_circuit")]
    Sw,
    #[cfg(feature = "u16limb_circuit")]
    Sh,
    #[cfg(feature = "u16limb_circuit")]
    Sb,
    #[cfg(feature = "u16limb_circuit")]
    LoadSub {
        load_width: u32,
        is_signed: u32,
    },
    #[cfg(feature = "u16limb_circuit")]
    Mul(u32), // 0=MUL, 1=MULH, 2=MULHU, 3=MULHSU
    #[cfg(feature = "u16limb_circuit")]
    Div(u32), // 0=DIV, 1=DIVU, 2=REM, 3=REMU
    Lw,
}

/// Cached shard_steps device buffer with metadata for logging.
struct ShardStepsCache {
    host_ptr: usize,
    byte_len: usize,
    shard_id: usize,
    n_steps: usize,
    device_buf: CudaSlice<u8>,
}

// Thread-local cache for shard_steps device buffer. Invalidated when shard changes.
thread_local! {
    static SHARD_STEPS_DEVICE: RefCell<Option<ShardStepsCache>> =
        const { RefCell::new(None) };
    /// Thread-local flag to force CPU path (used by debug comparison code).
    static FORCE_CPU_PATH: Cell<bool> = const { Cell::new(false) };
}

/// Force the current thread to use CPU path for all GPU witgen calls.
/// Used by debug comparison code in e2e.rs to run a CPU-only reference.
pub fn set_force_cpu_path(force: bool) {
    FORCE_CPU_PATH.with(|f| f.set(force));
}

fn is_force_cpu_path() -> bool {
    FORCE_CPU_PATH.with(|f| f.get())
}

/// Upload shard_steps to GPU, reusing cached device buffer if the same data.
fn upload_shard_steps_cached(
    hal: &CudaHalBB31,
    shard_steps: &[StepRecord],
    shard_id: usize,
) -> Result<(), ZKVMError> {
    let ptr = shard_steps.as_ptr() as usize;
    let byte_len = shard_steps.len() * std::mem::size_of::<StepRecord>();

    SHARD_STEPS_DEVICE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(c) = cache.as_ref() {
            if c.host_ptr == ptr && c.byte_len == byte_len {
                return Ok(()); // cache hit
            }
        }
        // Cache miss: upload
        let mb = byte_len as f64 / (1024.0 * 1024.0);
        tracing::info!(
            "[GPU witgen] uploading shard_steps: shard_id={}, n_steps={}, {:.2} MB",
            shard_id,
            shard_steps.len(),
            mb,
        );
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(shard_steps.as_ptr() as *const u8, byte_len) };
        let device_buf = hal.inner.htod_copy_stream(None, bytes).map_err(|e| {
            ZKVMError::InvalidWitness(format!("shard_steps H2D failed: {e}").into())
        })?;
        *cache = Some(ShardStepsCache {
            host_ptr: ptr,
            byte_len,
            shard_id,
            n_steps: shard_steps.len(),
            device_buf,
        });
        Ok(())
    })
}

/// Borrow the cached device buffer for kernel launch.
/// Panics if `upload_shard_steps_cached` was not called first.
fn with_cached_shard_steps<R>(f: impl FnOnce(&CudaSlice<u8>) -> R) -> R {
    SHARD_STEPS_DEVICE.with(|cache| {
        let cache = cache.borrow();
        let c = cache.as_ref().expect("shard_steps not uploaded");
        f(&c.device_buf)
    })
}

/// Invalidate the cached shard_steps device buffer.
/// Call this when shard processing is complete to free GPU memory.
pub fn invalidate_shard_steps_cache() {
    SHARD_STEPS_DEVICE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(c) = cache.as_ref() {
            let mb = c.byte_len as f64 / (1024.0 * 1024.0);
            tracing::info!(
                "[GPU witgen] releasing shard_steps cache: shard_id={}, n_steps={}, {:.2} MB",
                c.shard_id,
                c.n_steps,
                mb,
            );
        }
        *cache = None;
    });
}

/// Cached shard metadata device buffers for GPU shard records.
/// Invalidated when shard_id changes; shared across all kernel invocations in one shard.
struct ShardMetadataCache {
    shard_id: usize,
    device_bufs: ShardDeviceBuffers,
}

thread_local! {
    static SHARD_META_CACHE: RefCell<Option<ShardMetadataCache>> =
        const { RefCell::new(None) };
}

/// Build and cache shard metadata device buffers for GPU shard records.
/// Returns a reference to the cached `ShardDeviceBuffers`.
fn ensure_shard_metadata_cached(
    hal: &CudaHalBB31,
    shard_ctx: &ShardContext,
) -> Result<(), ZKVMError> {
    let shard_id = shard_ctx.shard_id;
    SHARD_META_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(c) = cache.as_ref() {
            if c.shard_id == shard_id {
                return Ok(()); // cache hit
            }
        }

        // Build sorted future-access arrays from HashMap
        let (fa_cycles_vec, fa_addrs_vec, fa_next_vec) = {
            let mut entries: Vec<(u64, u32, u64)> = Vec::new();
            for (cycle, pairs) in shard_ctx.addr_future_accesses.iter() {
                for &(addr, next_cycle) in pairs.iter() {
                    entries.push((*cycle, addr.0, next_cycle));
                }
            }
            entries.sort_unstable();
            let mut cycles = Vec::with_capacity(entries.len());
            let mut addrs = Vec::with_capacity(entries.len());
            let mut nexts = Vec::with_capacity(entries.len());
            for (c, a, n) in entries {
                cycles.push(c);
                addrs.push(a);
                nexts.push(n);
            }
            (cycles, addrs, nexts)
        };

        // Build GpuShardScalars
        let scalars = GpuShardScalars {
            shard_cycle_start: shard_ctx.cur_shard_cycle_range.start as u64,
            shard_cycle_end: shard_ctx.cur_shard_cycle_range.end as u64,
            shard_offset_cycle: shard_ctx.current_shard_offset_cycle(),
            shard_id: shard_id as u32,
            heap_start: shard_ctx.platform.heap.start,
            heap_end: shard_ctx.platform.heap.end,
            hint_start: shard_ctx.platform.hints.start,
            hint_end: shard_ctx.platform.hints.end,
            shard_heap_start: shard_ctx.shard_heap_addr_range.start,
            shard_heap_end: shard_ctx.shard_heap_addr_range.end,
            shard_hint_start: shard_ctx.shard_hint_addr_range.start,
            shard_hint_end: shard_ctx.shard_hint_addr_range.end,
            fa_count: fa_cycles_vec.len() as u32,
            num_prev_shards: shard_ctx.prev_shard_cycle_range.len() as u32,
            num_prev_heap_ranges: shard_ctx.prev_shard_heap_range.len() as u32,
            num_prev_hint_ranges: shard_ctx.prev_shard_hint_range.len() as u32,
        };

        // H2D copy scalar struct
        let scalars_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &scalars as *const GpuShardScalars as *const u8,
                std::mem::size_of::<GpuShardScalars>(),
            )
        };
        let scalars_device = hal.inner.htod_copy_stream(None, scalars_bytes).map_err(|e| {
            ZKVMError::InvalidWitness(format!("shard scalars H2D failed: {e}").into())
        })?;

        // H2D copy arrays (use empty slice [0] sentinel for empty arrays)
        let fa_cycles_device = hal
            .alloc_u64_from_host(if fa_cycles_vec.is_empty() { &[0u64] } else { &fa_cycles_vec }, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("fa_cycles H2D failed: {e}").into()))?;
        let fa_addrs_device = hal
            .alloc_u32_from_host(if fa_addrs_vec.is_empty() { &[0u32] } else { &fa_addrs_vec }, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("fa_addrs H2D failed: {e}").into()))?;
        let fa_next_device = hal
            .alloc_u64_from_host(if fa_next_vec.is_empty() { &[0u64] } else { &fa_next_vec }, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("fa_next H2D failed: {e}").into()))?;

        let pscr = &shard_ctx.prev_shard_cycle_range;
        let pscr_device = hal
            .alloc_u64_from_host(if pscr.is_empty() { &[0u64] } else { pscr }, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("pscr H2D failed: {e}").into()))?;

        let pshr = &shard_ctx.prev_shard_heap_range;
        let pshr_device = hal
            .alloc_u32_from_host(if pshr.is_empty() { &[0u32] } else { pshr }, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("pshr H2D failed: {e}").into()))?;

        let pshi = &shard_ctx.prev_shard_hint_range;
        let pshi_device = hal
            .alloc_u32_from_host(if pshi.is_empty() { &[0u32] } else { pshi }, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("pshi H2D failed: {e}").into()))?;

        let mb = (fa_cycles_vec.len() * 8 * 2 + fa_addrs_vec.len() * 4) as f64 / (1024.0 * 1024.0);
        tracing::info!(
            "[GPU shard] built ShardMetadataCache: shard_id={}, fa_entries={}, {:.2} MB",
            shard_id, fa_cycles_vec.len(), mb,
        );

        *cache = Some(ShardMetadataCache {
            shard_id,
            device_bufs: ShardDeviceBuffers {
                scalars: scalars_device,
                fa_cycles: fa_cycles_device,
                fa_addrs: fa_addrs_device,
                fa_next_cycles: fa_next_device,
                prev_shard_cycle_range: pscr_device,
                prev_shard_heap_range: pshr_device,
                prev_shard_hint_range: pshi_device,
            },
        });
        Ok(())
    })
}

/// Borrow the cached shard device buffers for kernel launch.
fn with_cached_shard_meta<R>(f: impl FnOnce(&ShardDeviceBuffers) -> R) -> R {
    SHARD_META_CACHE.with(|cache| {
        let cache = cache.borrow();
        let c = cache.as_ref().expect("shard metadata not uploaded");
        f(&c.device_bufs)
    })
}

/// Invalidate the shard metadata cache (call when shard processing is complete).
pub fn invalidate_shard_meta_cache() {
    SHARD_META_CACHE.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

/// CPU-side lightweight scan of GPU-produced RAM record slots.
///
/// Reconstructs BTreeMap read/write records and addr_accessed from the GPU output,
/// replacing the previous `collect_shard_side_effects()` CPU loop.
fn gpu_collect_shard_records(
    shard_ctx: &mut ShardContext,
    slots: &[GpuRamRecordSlot],
) {
    let current_shard_id = shard_ctx.shard_id;

    for slot in slots {
        // Check was_sent flag (bit 4): this slot corresponds to a send() call
        if slot.flags & (1 << 4) != 0 {
            shard_ctx.push_addr_accessed(WordAddr(slot.addr));
        }

        // Check active flag (bit 0): this slot has a read or write record
        if slot.flags & 1 == 0 {
            continue;
        }

        let ram_type = match (slot.flags >> 5) & 0x7 {
            1 => RAMType::Register,
            2 => RAMType::Memory,
            _ => continue,
        };
        let has_prev_value = slot.flags & (1 << 3) != 0;
        let prev_value = if has_prev_value { Some(slot.prev_value) } else { None };
        let addr = WordAddr(slot.addr);

        // Insert read record (bit 1)
        if slot.flags & (1 << 1) != 0 {
            shard_ctx.insert_read_record(
                addr,
                RAMRecord {
                    ram_type,
                    reg_id: slot.reg_id as u64,
                    addr,
                    prev_cycle: slot.prev_cycle,
                    cycle: slot.cycle,
                    shard_cycle: 0,
                    prev_value,
                    value: slot.value,
                    shard_id: slot.read_shard_id as usize,
                },
            );
        }

        // Insert write record (bit 2)
        if slot.flags & (1 << 2) != 0 {
            shard_ctx.insert_write_record(
                addr,
                RAMRecord {
                    ram_type,
                    reg_id: slot.reg_id as u64,
                    addr,
                    prev_cycle: slot.prev_cycle,
                    cycle: slot.cycle,
                    shard_cycle: slot.shard_cycle,
                    prev_value,
                    value: slot.value,
                    shard_id: current_shard_id,
                },
            );
        }
    }
}

/// Returns true if GPU shard records are verified for this kind.
fn kind_has_verified_shard(kind: GpuWitgenKind) -> bool {
    if is_shard_kind_disabled(kind) {
        return false;
    }
    match kind {
        GpuWitgenKind::Add => true,
        _ => false,
    }
}

/// Check if GPU shard records are disabled for a specific kind via env var.
fn is_shard_kind_disabled(kind: GpuWitgenKind) -> bool {
    thread_local! {
        static DISABLED: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
    }
    DISABLED.with(|cell| {
        let disabled = cell.get_or_init(|| {
            std::env::var("CENO_GPU_DISABLE_SHARD_KINDS")
                .ok()
                .map(|s| s.split(',').map(|t| t.trim().to_lowercase()).collect())
                .unwrap_or_default()
        });
        if disabled.is_empty() {
            return false;
        }
        if disabled.iter().any(|d| d == "all") {
            return true;
        }
        let tag = kind_tag(kind);
        disabled.iter().any(|d| d == tag)
    })
}

/// Returns true if GPU witgen is globally disabled via CENO_GPU_DISABLE_WITGEN env var.
/// The value is cached at first access so it's immune to runtime env var manipulation.
fn is_gpu_witgen_disabled() -> bool {
    use std::sync::OnceLock;
    static DISABLED: OnceLock<bool> = OnceLock::new();
    *DISABLED.get_or_init(|| {
        let val = std::env::var_os("CENO_GPU_DISABLE_WITGEN");
        let disabled = val.is_some();
        // Use eprintln to bypass tracing filters — always visible on stderr
        eprintln!(
            "[GPU witgen] CENO_GPU_DISABLE_WITGEN={:?} → disabled={}",
            val, disabled
        );
        disabled
    })
}

/// Try to run GPU witness generation for the given instruction.
/// Returns `Ok(Some(...))` if GPU was used, `Ok(None)` if GPU is unavailable (caller should fallback to CPU).
///
/// # Safety invariant
///
/// The caller **must** ensure that `I::InstructionConfig` matches `kind`:
/// - `GpuWitgenKind::Add` requires `I` to be `ArithInstruction` (config = `ArithConfig<E>`)
/// - `GpuWitgenKind::Lw`  requires `I` to be `LoadInstruction`  (config = `LoadConfig<E>`)
///
/// Violating this will cause undefined behavior via pointer cast in [`gpu_fill_witness`].
pub(crate) fn try_gpu_assign_instances<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<Option<(RMMCollections<E::BaseField>, Multiplicity<u64>)>, ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    if is_gpu_witgen_disabled() || is_force_cpu_path() {
        return Ok(None);
    }

    if !I::GPU_SIDE_EFFECTS {
        return Ok(None);
    }

    if is_kind_disabled(kind) {
        return Ok(None);
    }

    let total_instances = step_indices.len();
    if total_instances == 0 {
        // Empty: just return empty matrices
        let num_structural_witin = num_structural_witin.max(1);
        let raw_witin = RowMajorMatrix::<E::BaseField>::new(0, num_witin, I::padding_strategy());
        let raw_structural =
            RowMajorMatrix::<E::BaseField>::new(0, num_structural_witin, I::padding_strategy());
        let lk = LkMultiplicity::default();
        return Ok(Some((
            [raw_witin, raw_structural],
            lk.into_finalize_result(),
        )));
    }

    // GPU only supports BabyBear field
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField>()
    {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(hal) => hal,
        Err(_) => return Ok(None), // GPU not available, fallback to CPU
    };

    tracing::debug!("[GPU witgen] {:?} with {} instances", kind, total_instances);
    info_span!("gpu_witgen", kind = ?kind, n = total_instances).in_scope(|| {
        gpu_assign_instances_inner::<E, I>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            shard_steps,
            step_indices,
            kind,
            &hal,
        )
        .map(Some)
    })
}

fn gpu_assign_instances_inner<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
    hal: &CudaHalBB31,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    let num_structural_witin = num_structural_witin.max(1);
    let total_instances = step_indices.len();

    // Step 1: GPU fills witness matrix (+ LK counters + shard records for merged kinds)
    let (gpu_witness, gpu_lk_counters, gpu_ram_slots) = info_span!("gpu_kernel").in_scope(|| {
        gpu_fill_witness::<E, I>(
            hal,
            config,
            shard_ctx,
            num_witin,
            shard_steps,
            step_indices,
            kind,
        )
    })?;

    // Step 2: Collect side effects
    // Priority: GPU shard records > CPU shard records > full CPU side effects
    let lk_multiplicity = if gpu_lk_counters.is_some() && kind_has_verified_lk(kind) {
        let lk_multiplicity = info_span!("gpu_lk_d2h").in_scope(|| {
            gpu_lk_counters_to_multiplicity(gpu_lk_counters.unwrap())
        })?;

        if gpu_ram_slots.is_some() && kind_has_verified_shard(kind) {
            // GPU shard records path: D2H + lightweight CPU scan
            info_span!("gpu_shard_records").in_scope(|| {
                let ram_buf = gpu_ram_slots.unwrap();
                let slot_bytes: Vec<u32> = ram_buf.to_vec().map_err(|e| {
                    ZKVMError::InvalidWitness(format!("ram_slots D2H failed: {e}").into())
                })?;
                // Reinterpret u32 buffer as GpuRamRecordSlot slice
                let slots: &[GpuRamRecordSlot] = unsafe {
                    std::slice::from_raw_parts(
                        slot_bytes.as_ptr() as *const GpuRamRecordSlot,
                        slot_bytes.len() * 4 / std::mem::size_of::<GpuRamRecordSlot>(),
                    )
                };
                gpu_collect_shard_records(shard_ctx, slots);
                Ok::<(), ZKVMError>(())
            })?;
        } else {
            // CPU: collect shard records only (send/addr_accessed).
            info_span!("cpu_shard_records").in_scope(|| {
                let _ = collect_shard_side_effects::<E, I>(config, shard_ctx, shard_steps, step_indices)?;
                Ok::<(), ZKVMError>(())
            })?;
        }
        lk_multiplicity
    } else {
        // GPU LK counters missing or unverified — fall back to full CPU side effects
        info_span!("cpu_side_effects").in_scope(|| {
            collect_side_effects::<E, I>(config, shard_ctx, shard_steps, step_indices)
        })?
    };
    debug_compare_final_lk::<E, I>(config, shard_ctx, num_witin, num_structural_witin, shard_steps, step_indices, kind, &lk_multiplicity)?;
    debug_compare_shard_side_effects::<E, I>(config, shard_ctx, shard_steps, step_indices, kind)?;

    // Step 3: Build structural witness (just selector = ONE)
    let mut raw_structural = RowMajorMatrix::<E::BaseField>::new(
        total_instances,
        num_structural_witin,
        I::padding_strategy(),
    );
    for row in raw_structural.iter_mut() {
        *row.last_mut().unwrap() = E::BaseField::ONE;
    }
    raw_structural.padding_by_strategy();

    // Step 4: Transpose (column-major → row-major) on GPU, then D2H copy to RowMajorMatrix
    let mut raw_witin = info_span!("transpose_d2h").in_scope(|| {
        gpu_witness_to_rmm::<E>(
            hal,
            gpu_witness,
            total_instances,
            num_witin,
            I::padding_strategy(),
        )
    })?;
    raw_witin.padding_by_strategy();
    debug_compare_witness::<E, I>(
        config,
        shard_ctx,
        num_witin,
        num_structural_witin,
        shard_steps,
        step_indices,
        kind,
        &raw_witin,
    )?;

    Ok(([raw_witin, raw_structural], lk_multiplicity))
}

type WitBuf = ceno_gpu::common::BufferImpl<
    'static,
    <ff_ext::BabyBearExt4 as ExtensionField>::BaseField,
>;
type LkBuf = ceno_gpu::common::BufferImpl<'static, u32>;
type RamBuf = ceno_gpu::common::BufferImpl<'static, u32>;
type WitResult = ceno_gpu::common::witgen_types::GpuWitnessResult<WitBuf>;
type LkResult = ceno_gpu::common::witgen_types::GpuLookupCountersResult<LkBuf>;

/// Compute fetch counter parameters from step data.
fn compute_fetch_params(
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> (u32, usize) {
    let mut min_pc = u32::MAX;
    let mut max_pc = 0u32;
    for &idx in step_indices {
        let pc = shard_steps[idx].pc().before.0;
        min_pc = min_pc.min(pc);
        max_pc = max_pc.max(pc);
    }
    if min_pc > max_pc {
        return (0, 0);
    }
    let fetch_base_pc = min_pc;
    let fetch_num_slots = ((max_pc - min_pc) / 4 + 1) as usize;
    (fetch_base_pc, fetch_num_slots)
}

/// GPU kernel dispatch based on instruction kind.
/// All kinds return witness + LK counters (merged into single GPU kernel).
fn gpu_fill_witness<E: ExtensionField, I: Instruction<E>>(
    hal: &CudaHalBB31,
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<(WitResult, Option<LkResult>, Option<RamBuf>), ZKVMError> {
    // Upload shard_steps to GPU once (cached across ADD/LW calls within same shard).
    let shard_id = shard_ctx.shard_id;
    info_span!("upload_shard_steps")
        .in_scope(|| upload_shard_steps_cached(hal, shard_steps, shard_id))?;

    // Convert step_indices from usize to u32 for GPU.
    let indices_u32: Vec<u32> = info_span!("indices_u32", n = step_indices.len())
        .in_scope(|| step_indices.iter().map(|&i| i as u32).collect());
    let shard_offset = shard_ctx.current_shard_offset_cycle();

    // Helper to split GpuWitgenFullResult into (witness, Some(lk_counters))
    macro_rules! split_full {
        ($result:expr) => {{
            let full = $result?;
            Ok((full.witness, Some(full.lk_counters), None))
        }};
    }

    // Compute fetch params for all GPU kinds (LK counters are merged into all kernels)
    let (fetch_base_pc, fetch_num_slots) = compute_fetch_params(shard_steps, step_indices);

    match kind {
        GpuWitgenKind::Add => {
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::add::extract_add_column_map(arith_config, num_witin));
            ensure_shard_metadata_cached(hal, shard_ctx)?;
            info_span!("hal_witgen_add").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    with_cached_shard_meta(|shard_bufs| {
                        let full = hal
                            .witgen_add(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_add failed: {e}").into(),
                                )
                            })?;
                        Ok((full.witness, Some(full.lk_counters), full.ram_slots))
                    })
                })
            })
        }
        GpuWitgenKind::Sub => {
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::sub::extract_sub_column_map(arith_config, num_witin));
            info_span!("hal_witgen_sub").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_sub(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_sub failed: {e}").into())
                        }))
                })
            })
        }
        GpuWitgenKind::LogicR(logic_kind) => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic::logic_circuit::LogicConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::logic_r::extract_logic_r_column_map(logic_config, num_witin));
            info_span!("hal_witgen_logic_r").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_logic_r(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            logic_kind,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_logic_r failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LogicI(logic_kind) => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::logic_i::extract_logic_i_column_map(logic_config, num_witin));
            info_span!("hal_witgen_logic_i").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_logic_i(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            logic_kind,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_logic_i failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Addi => {
            let addi_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith_imm::arith_imm_circuit_v2::InstructionConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::addi::extract_addi_column_map(addi_config, num_witin));
            info_span!("hal_witgen_addi").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_addi(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_addi failed: {e}").into())
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Lui => {
            let lui_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::lui::LuiConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::lui::extract_lui_column_map(lui_config, num_witin));
            info_span!("hal_witgen_lui").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_lui(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_lui failed: {e}").into())
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Auipc => {
            let auipc_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::auipc::AuipcConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::auipc::extract_auipc_column_map(auipc_config, num_witin));
            info_span!("hal_witgen_auipc").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_auipc(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_auipc failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jal => {
            let jal_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::jump::jal_v2::JalConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::jal::extract_jal_column_map(jal_config, num_witin));
            info_span!("hal_witgen_jal").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_jal(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_jal failed: {e}").into())
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftR(shift_kind) => {
            let shift_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::shift::shift_circuit_v2::ShiftRTypeConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::shift_r::extract_shift_r_column_map(shift_config, num_witin));
            info_span!("hal_witgen_shift_r").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_shift_r(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            shift_kind,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_shift_r failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftI(shift_kind) => {
            let shift_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::shift::shift_circuit_v2::ShiftImmConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::shift_i::extract_shift_i_column_map(shift_config, num_witin));
            info_span!("hal_witgen_shift_i").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_shift_i(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            shift_kind,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_shift_i failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slt(is_signed) => {
            let slt_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::slt::slt_circuit_v2::SetLessThanConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::slt::extract_slt_column_map(slt_config, num_witin));
            info_span!("hal_witgen_slt").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_slt(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            is_signed,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_slt failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slti(is_signed) => {
            let slti_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::slti::extract_slti_column_map(slti_config, num_witin));
            info_span!("hal_witgen_slti").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_slti(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            is_signed,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_slti failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchEq(is_beq) => {
            let branch_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::branch_eq::extract_branch_eq_column_map(branch_config, num_witin)
            });
            info_span!("hal_witgen_branch_eq").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_branch_eq(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            is_beq,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_branch_eq failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchCmp(is_signed) => {
            let branch_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::branch_cmp::extract_branch_cmp_column_map(branch_config, num_witin)
            });
            info_span!("hal_witgen_branch_cmp").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_branch_cmp(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            is_signed,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_branch_cmp failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jalr => {
            let jalr_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::jump::jalr_v2::JalrConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::jalr::extract_jalr_column_map(jalr_config, num_witin));
            info_span!("hal_witgen_jalr").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_jalr(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_jalr failed: {e}").into())
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sw => {
            let sw_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 2>)
            };
            let mem_max_bits = sw_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::sw::extract_sw_column_map(sw_config, num_witin));
            info_span!("hal_witgen_sw").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_sw(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            mem_max_bits,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_sw failed: {e}").into())
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sh => {
            let sh_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 1>)
            };
            let mem_max_bits = sh_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::sh::extract_sh_column_map(sh_config, num_witin));
            info_span!("hal_witgen_sh").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_sh(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            mem_max_bits,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_sh failed: {e}").into())
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sb => {
            let sb_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 0>)
            };
            let mem_max_bits = sb_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::sb::extract_sb_column_map(sb_config, num_witin));
            info_span!("hal_witgen_sb").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_sb(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            mem_max_bits,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_sb failed: {e}").into())
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LoadSub {
            load_width,
            is_signed,
        } => {
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load_v2::LoadConfig<E>)
            };
            let is_byte = load_width == 8;
            let is_signed_bool = is_signed != 0;
            let col_map = info_span!("col_map").in_scope(|| {
                super::load_sub::extract_load_sub_column_map(
                    load_config,
                    num_witin,
                    is_byte,
                    is_signed_bool,
                )
            });
            let mem_max_bits = load_config.memory_addr.max_bits as u32;
            info_span!("hal_witgen_load_sub").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_load_sub(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            load_width,
                            is_signed,
                            mem_max_bits,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_load_sub failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Mul(mul_kind) => {
            let mul_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::mulh::mulh_circuit_v2::MulhConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::mul::extract_mul_column_map(mul_config, num_witin, mul_kind));
            info_span!("hal_witgen_mul").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_mul(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            mul_kind,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_mul failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Div(div_kind) => {
            let div_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::div::div_circuit_v2::DivRemConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::div::extract_div_column_map(div_config, num_witin));
            info_span!("hal_witgen_div").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_div(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            div_kind,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_div failed: {e}").into(),
                            )
                        }))
                })
            })
        }
        GpuWitgenKind::Lw => {
            #[cfg(feature = "u16limb_circuit")]
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load_v2::LoadConfig<E>)
            };
            #[cfg(not(feature = "u16limb_circuit"))]
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load::LoadConfig<E>)
            };
            let mem_max_bits = load_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::lw::extract_lw_column_map(load_config, num_witin));
            info_span!("hal_witgen_lw").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    split_full!(hal
                        .witgen_lw(
                            &col_map,
                            gpu_records,
                            &indices_u32,
                            shard_offset,
                            mem_max_bits,
                            fetch_base_pc,
                            fetch_num_slots,
                            None,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_lw failed: {e}").into())
                        }))
                })
            })
        }
    }
}

/// CPU-side loop to collect side effects only (shard_ctx.send, lk_multiplicity).
/// Runs assign_instance with a scratch buffer per thread.
fn collect_side_effects<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> Result<Multiplicity<u64>, ZKVMError> {
    cpu_collect_side_effects::<E, I>(config, shard_ctx, shard_steps, step_indices)
}

fn collect_shard_side_effects<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> Result<Multiplicity<u64>, ZKVMError> {
    cpu_collect_shard_side_effects::<E, I>(config, shard_ctx, shard_steps, step_indices)
}

fn kind_tag(kind: GpuWitgenKind) -> &'static str {
    match kind {
        GpuWitgenKind::Add => "add",
        GpuWitgenKind::Sub => "sub",
        GpuWitgenKind::LogicR(_) => "logic_r",
        GpuWitgenKind::Lw => "lw",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LogicI(_) => "logic_i",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Addi => "addi",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Lui => "lui",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Auipc => "auipc",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jal => "jal",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftR(_) => "shift_r",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftI(_) => "shift_i",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slt(_) => "slt",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slti(_) => "slti",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchEq(_) => "branch_eq",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchCmp(_) => "branch_cmp",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jalr => "jalr",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sw => "sw",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sh => "sh",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sb => "sb",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LoadSub { .. } => "load_sub",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Mul(_) => "mul",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Div(_) => "div",
    }
}

/// Returns true if the GPU CUDA kernel for this kind has been verified to produce
/// correct LK multiplicity counters matching the CPU baseline.
/// Unverified kinds fall back to CPU full side effects (GPU still handles witness).
///
/// Override with `CENO_GPU_DISABLE_LK_KINDS=add,sub,...` to force specific kinds
/// back to CPU LK (for binary-search debugging).
/// Set `CENO_GPU_DISABLE_LK_KINDS=all` to disable GPU LK for ALL kinds.
fn kind_has_verified_lk(kind: GpuWitgenKind) -> bool {
    if is_lk_kind_disabled(kind) {
        return false;
    }
    match kind {
        // Phase B verified (Add/Sub/LogicR/Lw)
        GpuWitgenKind::Add => true,
        GpuWitgenKind::Sub => true,
        GpuWitgenKind::LogicR(_) => true,
        GpuWitgenKind::Lw => true,
        // Phase C verified via debug_compare_final_lk
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Addi => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LogicI(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Lui => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slti(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchEq(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchCmp(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sw => true,
        // Phase C CUDA kernel fixes applied
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftI(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Auipc => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jal => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jalr => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sb => true,
        // Remaining kinds enabled
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftR(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slt(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sh => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LoadSub { .. } => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Mul(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Div(_) => true,
        _ => false,
    }
}

/// Check if GPU LK is disabled for a specific kind via CENO_GPU_DISABLE_LK_KINDS env var.
/// Format: CENO_GPU_DISABLE_LK_KINDS=add,sub,lw (comma-separated kind tags)
/// Special value: CENO_GPU_DISABLE_LK_KINDS=all (disables GPU LK for ALL kinds)
fn is_lk_kind_disabled(kind: GpuWitgenKind) -> bool {
    thread_local! {
        static DISABLED: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
    }
    DISABLED.with(|cell| {
        let disabled = cell.get_or_init(|| {
            std::env::var("CENO_GPU_DISABLE_LK_KINDS")
                .ok()
                .map(|s| s.split(',').map(|t| t.trim().to_lowercase()).collect())
                .unwrap_or_default()
        });
        if disabled.is_empty() {
            return false;
        }
        if disabled.iter().any(|d| d == "all") {
            return true;
        }
        let tag = kind_tag(kind);
        disabled.iter().any(|d| d == tag)
    })
}

/// Check if a specific GPU witgen kind is disabled via CENO_GPU_DISABLE_KINDS env var.
/// Format: CENO_GPU_DISABLE_KINDS=add,sub,lw (comma-separated kind tags)
fn is_kind_disabled(kind: GpuWitgenKind) -> bool {
    thread_local! {
        static DISABLED: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
    }
    DISABLED.with(|cell| {
        let disabled = cell.get_or_init(|| {
            std::env::var("CENO_GPU_DISABLE_KINDS")
                .ok()
                .map(|s| s.split(',').map(|t| t.trim().to_lowercase()).collect())
                .unwrap_or_default()
        });
        if disabled.is_empty() {
            return false;
        }
        let tag = kind_tag(kind);
        disabled.iter().any(|d| d == tag)
    })
}

fn debug_compare_final_lk<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
    mixed_lk: &Multiplicity<u64>,
) -> Result<(), ZKVMError> {
    if std::env::var_os("CENO_GPU_DEBUG_COMPARE_LK").is_none() {
        return Ok(());
    }

    // Compare against cpu_assign_instances (the true baseline using assign_instance)
    let mut cpu_ctx = shard_ctx.new_empty_like();
    let (_, cpu_assign_lk) = crate::instructions::cpu_assign_instances::<E, I>(
        config,
        &mut cpu_ctx,
        num_witin,
        num_structural_witin,
        shard_steps,
        step_indices,
    )?;
    tracing::info!("[GPU lk debug] kind={kind:?} comparing mixed_lk vs cpu_assign_instances lk");
    log_lk_diff(kind, &cpu_assign_lk, mixed_lk);
    Ok(())
}

fn log_lk_diff(kind: GpuWitgenKind, cpu_lk: &Multiplicity<u64>, actual_lk: &Multiplicity<u64>) {
    let limit = std::env::var("CENO_GPU_DEBUG_COMPARE_LK_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(32);

    let mut total_diffs = 0usize;
    for (table_idx, (cpu_table, actual_table)) in cpu_lk.iter().zip(actual_lk.iter()).enumerate() {
        let mut keys = cpu_table
            .keys()
            .chain(actual_table.keys())
            .copied()
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();

        let mut table_diffs = Vec::new();
        for key in keys {
            let cpu_count = cpu_table.get(&key).copied().unwrap_or(0);
            let actual_count = actual_table.get(&key).copied().unwrap_or(0);
            if cpu_count != actual_count {
                table_diffs.push((key, cpu_count, actual_count));
            }
        }

        if !table_diffs.is_empty() {
            total_diffs += table_diffs.len();
            tracing::error!(
                "[GPU lk debug] kind={kind:?} table={} diff_count={}",
                lookup_table_name(table_idx),
                table_diffs.len()
            );
            for (key, cpu_count, actual_count) in table_diffs.into_iter().take(limit) {
                tracing::error!(
                    "[GPU lk debug] kind={kind:?} table={} key={} cpu={} gpu={}",
                    lookup_table_name(table_idx),
                    key,
                    cpu_count,
                    actual_count
                );
            }
        }
    }

    if total_diffs == 0 {
        tracing::info!("[GPU lk debug] kind={kind:?} CPU/GPU lookup multiplicities match");
    }
}

fn debug_compare_witness<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
    gpu_witness: &RowMajorMatrix<E::BaseField>,
) -> Result<(), ZKVMError> {
    if std::env::var_os("CENO_GPU_DEBUG_COMPARE_WITNESS").is_none() {
        return Ok(());
    }

    let mut cpu_ctx = shard_ctx.new_empty_like();
    let (cpu_rmms, _) = crate::instructions::cpu_assign_instances::<E, I>(
        config,
        &mut cpu_ctx,
        num_witin,
        num_structural_witin,
        shard_steps,
        step_indices,
    )?;
    let cpu_witness = &cpu_rmms[0];
    let cpu_vals = cpu_witness.values();
    let gpu_vals = gpu_witness.values();
    if cpu_vals == gpu_vals {
        return Ok(());
    }

    let limit = std::env::var("CENO_GPU_DEBUG_COMPARE_WITNESS_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(16);
    let cpu_num_cols = cpu_witness.n_col();
    let cpu_num_rows = cpu_vals.len() / cpu_num_cols;
    let mut mismatches = 0usize;
    for row in 0..cpu_num_rows {
        for col in 0..cpu_num_cols {
            let idx = row * cpu_num_cols + col;
            if cpu_vals[idx] != gpu_vals[idx] {
                mismatches += 1;
                if mismatches <= limit {
                    tracing::error!(
                        "[GPU witness debug] kind={kind:?} row={} col={} cpu={:?} gpu={:?}",
                        row,
                        col,
                        cpu_vals[idx],
                        gpu_vals[idx]
                    );
                }
            }
        }
    }
    tracing::error!(
        "[GPU witness debug] kind={kind:?} total_mismatches={}",
        mismatches
    );
    Ok(())
}

fn debug_compare_shard_side_effects<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<(), ZKVMError> {
    if std::env::var_os("CENO_GPU_DEBUG_COMPARE_SHARD").is_none() {
        return Ok(());
    }

    let mut cpu_ctx = shard_ctx.new_empty_like();
    let _ = cpu_collect_side_effects::<E, I>(config, &mut cpu_ctx, shard_steps, step_indices)?;

    let mut mixed_ctx = shard_ctx.new_empty_like();
    let _ =
        cpu_collect_shard_side_effects::<E, I>(config, &mut mixed_ctx, shard_steps, step_indices)?;

    let cpu_addr = cpu_ctx.get_addr_accessed();
    let mixed_addr = mixed_ctx.get_addr_accessed();
    if cpu_addr != mixed_addr {
        tracing::error!(
            "[GPU shard debug] kind={kind:?} addr_accessed cpu={} gpu={}",
            cpu_addr.len(),
            mixed_addr.len()
        );
    }

    let cpu_reads = flatten_ram_records(cpu_ctx.read_records());
    let mixed_reads = flatten_ram_records(mixed_ctx.read_records());
    if cpu_reads != mixed_reads {
        log_ram_record_diff(kind, "read_records", &cpu_reads, &mixed_reads);
    }

    let cpu_writes = flatten_ram_records(cpu_ctx.write_records());
    let mixed_writes = flatten_ram_records(mixed_ctx.write_records());
    if cpu_writes != mixed_writes {
        log_ram_record_diff(kind, "write_records", &cpu_writes, &mixed_writes);
    }

    Ok(())
}

fn flatten_ram_records(
    records: &[std::collections::BTreeMap<ceno_emul::WordAddr, crate::e2e::RAMRecord>],
) -> Vec<(u32, u64, u64, u64, u64, Option<u32>, u32, usize)> {
    let mut flat = Vec::new();
    for table in records {
        for (addr, record) in table {
            flat.push((
                addr.0,
                record.reg_id,
                record.prev_cycle,
                record.cycle,
                record.shard_cycle,
                record.prev_value,
                record.value,
                record.shard_id,
            ));
        }
    }
    flat
}

fn log_ram_record_diff(
    kind: GpuWitgenKind,
    label: &str,
    cpu_records: &[(u32, u64, u64, u64, u64, Option<u32>, u32, usize)],
    mixed_records: &[(u32, u64, u64, u64, u64, Option<u32>, u32, usize)],
) {
    let limit = std::env::var("CENO_GPU_DEBUG_COMPARE_SHARD_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(16);
    tracing::error!(
        "[GPU shard debug] kind={kind:?} {} cpu={} gpu={}",
        label,
        cpu_records.len(),
        mixed_records.len()
    );
    let max_len = cpu_records.len().max(mixed_records.len());
    let mut logged = 0usize;
    for idx in 0..max_len {
        let cpu = cpu_records.get(idx);
        let gpu = mixed_records.get(idx);
        if cpu != gpu {
            tracing::error!(
                "[GPU shard debug] kind={kind:?} {} idx={} cpu={:?} gpu={:?}",
                label,
                idx,
                cpu,
                gpu
            );
            logged += 1;
            if logged >= limit {
                break;
            }
        }
    }
}

fn lookup_table_name(table_idx: usize) -> &'static str {
    match table_idx {
        x if x == LookupTable::Dynamic as usize => "Dynamic",
        x if x == LookupTable::DoubleU8 as usize => "DoubleU8",
        x if x == LookupTable::And as usize => "And",
        x if x == LookupTable::Or as usize => "Or",
        x if x == LookupTable::Xor as usize => "Xor",
        x if x == LookupTable::Ltu as usize => "Ltu",
        x if x == LookupTable::Pow as usize => "Pow",
        x if x == LookupTable::Instruction as usize => "Instruction",
        _ => "Unknown",
    }
}

fn gpu_lk_counters_to_multiplicity(counters: LkResult) -> Result<Multiplicity<u64>, ZKVMError> {
    let mut lk = LkMultiplicity::default();
    merge_dense_counter_table(
        &mut lk,
        LookupTable::Dynamic,
        &counters.dynamic.to_vec().map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU dynamic lk D2H failed: {e}").into())
        })?,
    );
    merge_dense_counter_table(
        &mut lk,
        LookupTable::DoubleU8,
        &counters.double_u8.to_vec().map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU double_u8 lk D2H failed: {e}").into())
        })?,
    );
    merge_dense_counter_table(
        &mut lk,
        LookupTable::And,
        &counters
            .and_table
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU and lk D2H failed: {e}").into()))?,
    );
    merge_dense_counter_table(
        &mut lk,
        LookupTable::Or,
        &counters
            .or_table
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU or lk D2H failed: {e}").into()))?,
    );
    merge_dense_counter_table(
        &mut lk,
        LookupTable::Xor,
        &counters
            .xor_table
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU xor lk D2H failed: {e}").into()))?,
    );
    merge_dense_counter_table(
        &mut lk,
        LookupTable::Ltu,
        &counters
            .ltu_table
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU ltu lk D2H failed: {e}").into()))?,
    );
    merge_dense_counter_table(
        &mut lk,
        LookupTable::Pow,
        &counters
            .pow_table
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU pow lk D2H failed: {e}").into()))?,
    );
    // Merge fetch (Instruction) table if present
    if let Some(fetch_buf) = counters.fetch {
        let base_pc = counters.fetch_base_pc;
        let fetch_counts = fetch_buf.to_vec().map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU fetch lk D2H failed: {e}").into())
        })?;
        for (slot_idx, &count) in fetch_counts.iter().enumerate() {
            if count != 0 {
                let pc = base_pc as u64 + (slot_idx as u64) * 4;
                lk.set_count(LookupTable::Instruction, pc, count as usize);
            }
        }
    }
    Ok(lk.into_finalize_result())
}

fn merge_dense_counter_table(lk: &mut LkMultiplicity, table: LookupTable, counts: &[u32]) {
    for (key, &count) in counts.iter().enumerate() {
        if count != 0 {
            lk.set_count(table, key as u64, count as usize);
        }
    }
}

/// Convert GPU device buffer (column-major) to RowMajorMatrix via GPU transpose + D2H copy.
///
/// GPU witgen kernels output column-major layout for better memory coalescing.
/// This function transposes to row-major on GPU before copying to host.
fn gpu_witness_to_rmm<E: ExtensionField>(
    hal: &CudaHalBB31,
    gpu_result: ceno_gpu::common::witgen_types::GpuWitnessResult<
        ceno_gpu::common::BufferImpl<'static, <ff_ext::BabyBearExt4 as ExtensionField>::BaseField>,
    >,
    num_rows: usize,
    num_cols: usize,
    padding: InstancePaddingStrategy,
) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
    // Transpose from column-major to row-major on GPU.
    // Column-major (num_rows x num_cols) is stored as num_cols groups of num_rows elements,
    // which is equivalent to a (num_cols x num_rows) row-major matrix.
    // Transposing with cols=num_rows, rows=num_cols produces (num_rows x num_cols) row-major.
    let mut rmm_buffer = hal
        .alloc_elems_on_device(num_rows * num_cols, false, None)
        .map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU alloc for transpose failed: {e}").into())
        })?;
    matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
        &hal.inner,
        &mut rmm_buffer,
        &gpu_result.device_buffer,
        num_rows,
        num_cols,
    )
    .map_err(|e| ZKVMError::InvalidWitness(format!("GPU transpose failed: {e}").into()))?;

    let gpu_data: Vec<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField> = rmm_buffer
        .to_vec()
        .map_err(|e| ZKVMError::InvalidWitness(format!("GPU D2H copy failed: {e}").into()))?;

    // Safety: BabyBear is the only supported GPU field, and E::BaseField must match
    let data: Vec<E::BaseField> = unsafe {
        let mut data = std::mem::ManuallyDrop::new(gpu_data);
        Vec::from_raw_parts(
            data.as_mut_ptr() as *mut E::BaseField,
            data.len(),
            data.capacity(),
        )
    };

    Ok(RowMajorMatrix::<E::BaseField>::new_by_values(
        data, num_cols, padding,
    ))
}
