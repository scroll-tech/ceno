/// GPU witness generation dispatcher for the proving pipeline.
///
/// This module provides `try_gpu_assign_instances` which:
/// 1. Runs the GPU kernel to fill the witness matrix (fast)
/// 2. Runs a lightweight CPU loop to collect lk and shardram without witness replay
/// 3. Returns the GPU-generated witness + CPU-collected lk and shardram
use ceno_emul::{StepIndex, StepRecord, WordAddr};
use ceno_gpu::{
    Buffer, CudaHal,
    bb31::CudaHalBB31,
    common::{
        transpose::matrix_transpose,
        witgen::types::{GpuRamRecordSlot, GpuShardRamRecord},
    },
};
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use p3::field::FieldAlgebra;
use std::cell::Cell;
use tracing::info_span;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use super::{
    config::{is_gpu_witgen_enabled, is_kind_disabled, should_keep_witness_device_backing},
    utils::debug_compare::{
        debug_compare_final_lk, debug_compare_shard_ec, debug_compare_shardram,
        debug_compare_witness,
    },
};
use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{Instruction, cpu_collect_lk_and_shardram, cpu_collect_shardram},
    tables::RMMCollections,
    witness::LkMultiplicity,
};

#[derive(Debug, Clone, Copy)]
pub enum GpuWitgenKind {
    Add,
    Sub,
    LogicR(u32), // 0=AND, 1=OR, 2=XOR
    LogicI(u32), // 0=AND, 1=OR, 2=XOR
    Addi,
    Lui,
    Auipc,
    Jal,
    ShiftR(u32),    // 0=SLL, 1=SRL, 2=SRA
    ShiftI(u32),    // 0=SLLI, 1=SRLI, 2=SRAI
    Slt(u32),       // 1=SLT(signed), 0=SLTU(unsigned)
    Slti(u32),      // 1=SLTI(signed), 0=SLTIU(unsigned)
    BranchEq(u32),  // 1=BEQ, 0=BNE
    BranchCmp(u32), // 1=signed (BLT/BGE), 0=unsigned (BLTU/BGEU)
    Jalr,
    Sw,
    Sh,
    Sb,
    LoadSub { load_width: u32, is_signed: u32 },
    Mul(u32), // 0=MUL, 1=MULH, 2=MULHU, 3=MULHSU
    Div(u32), // 0=DIV, 1=DIVU, 2=REM, 3=REMU
    Lw,
    Keccak,
}

// Re-exports from device_cache module for external callers (e2e.rs, structs.rs).
pub use super::cache::{
    SharedDeviceBufferSet, assert_caches_released_before_prove, flush_shared_ec_buffers,
    invalidate_shard_meta_cache, invalidate_shard_steps_cache, take_shared_device_buffers,
};
use super::{
    cache::{
        ensure_shard_metadata_cached, read_shared_addr_count, read_shared_addr_range,
        upload_shard_steps_cached, with_cached_gpu_ctx, with_cached_shard_meta,
        with_cached_shard_steps,
    },
    utils::d2h::{
        CompactEcBuf, LkResult, RamBuf, WitResult, gpu_collect_shard_records, gpu_compact_ec_d2h,
        gpu_lk_counters_to_multiplicity, gpu_witness_to_rmm, gpu_witness_to_rmm_d2h,
    },
};

thread_local! {
    /// Thread-local flag to force CPU path (used by debug comparison code).
    static FORCE_CPU_PATH: Cell<bool> = const { Cell::new(false) };
}

/// Force the current thread to use CPU path for all GPU witgen calls.
/// Used by debug comparison code in e2e.rs to run a CPU-only reference.
pub fn set_force_cpu_path(force: bool) {
    FORCE_CPU_PATH.with(|f| f.set(force));
}

pub(crate) fn is_force_cpu_path() -> bool {
    FORCE_CPU_PATH.with(|f| f.get())
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

    if !is_gpu_witgen_enabled() || is_force_cpu_path() {
        return Ok(None);
    }

    if !I::GPU_LK_SHARDRAM {
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
    let (gpu_witness, gpu_lk_counters, gpu_ram_slots, gpu_compact_ec, gpu_compact_addr) =
        info_span!("gpu_kernel").in_scope(|| {
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

    // Step 2: Collect lk and shardram
    // Priority: GPU shard records > CPU shard records > full CPU lk and shardram
    //
    // Keccak never enters this function (it has `gpu_assign_keccak_inner`).
    // Guard defensively in case the enum value is ever passed here by mistake.
    let is_standard_kind = !matches!(kind, GpuWitgenKind::Keccak);

    let lk_multiplicity = if gpu_lk_counters.is_some() && is_standard_kind {
        let lk_multiplicity = info_span!("gpu_lk_d2h")
            .in_scope(|| gpu_lk_counters_to_multiplicity(gpu_lk_counters.unwrap()))?;

        if gpu_compact_ec.is_none() && gpu_compact_addr.is_none() && is_standard_kind {
            // Shared buffer path: EC records + addr_accessed accumulated on device
            // in shared buffers across all kernel invocations. Skip per-kernel D2H.
            // Data will be consumed in batch by assign_shared_circuit.
        } else if gpu_compact_ec.is_some() && is_standard_kind {
            // GPU EC path: compact records already have EC points computed on device.
            // D2H only the active records (much smaller than full N*3 slot buffer).
            info_span!("gpu_ec_shard").in_scope(|| {
                let compact = gpu_compact_ec.unwrap();
                let compact_records =
                    info_span!("compact_d2h").in_scope(|| gpu_compact_ec_d2h(&compact))?;

                // D2H ram_slots lazily (only for debug or fallback).
                // Avoid the 68 MB D2H in the common case.
                let ram_slots_d2h = || -> Result<Vec<GpuRamRecordSlot>, ZKVMError> {
                    if let Some(ref ram_buf) = gpu_ram_slots {
                        let sv: Vec<u32> = ram_buf.to_vec().map_err(|e| {
                            ZKVMError::InvalidWitness(format!("ram_slots D2H failed: {e}").into())
                        })?;
                        Ok(unsafe {
                            let ptr = sv.as_ptr() as *const GpuRamRecordSlot;
                            let len = sv.len() * 4 / std::mem::size_of::<GpuRamRecordSlot>();
                            std::slice::from_raw_parts(ptr, len).to_vec()
                        })
                    } else {
                        Ok(vec![])
                    }
                };

                // D2H compact addr_accessed (GPU-side compaction via atomicAdd).
                // Much smaller than full ram_slots D2H (4 bytes/addr vs 48 bytes/slot).
                info_span!("compact_addr_d2h").in_scope(|| -> Result<(), ZKVMError> {
                    if let Some(ref ca) = gpu_compact_addr {
                        let count_vec: Vec<u32> = ca.count_buf.to_vec().map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("compact_addr_count D2H failed: {e}").into(),
                            )
                        })?;
                        let n = count_vec[0] as usize;
                        if n > 0 {
                            let addrs: Vec<u32> = ca.buffer.to_vec_n(n).map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("compact_addr D2H failed: {e}").into(),
                                )
                            })?;
                            let mut forked = shard_ctx.get_forked();
                            let thread_ctx = &mut forked[0];
                            for &addr in &addrs {
                                thread_ctx.push_addr_accessed(WordAddr(addr));
                            }
                        }
                    } else {
                        // Fallback: D2H full ram_slots for addr_accessed
                        let slots = ram_slots_d2h()?;
                        let mut forked = shard_ctx.get_forked();
                        let thread_ctx = &mut forked[0];
                        for slot in &slots {
                            if slot.flags & (1 << 4) != 0 {
                                thread_ctx.push_addr_accessed(WordAddr(slot.addr));
                            }
                        }
                    }
                    Ok(())
                })?;

                // Debug: compare GPU shard_ctx vs CPU shard_ctx independently
                if crate::instructions::gpu::config::is_debug_compare_enabled() {
                    let slots = ram_slots_d2h()?;
                    debug_compare_shard_ec::<E, I>(
                        &compact_records,
                        &slots,
                        config,
                        shard_ctx,
                        shard_steps,
                        step_indices,
                        kind,
                    );
                }

                // Accumulate compact shard records for assign_shared_circuit
                let raw_bytes = unsafe {
                    std::slice::from_raw_parts(
                        compact_records.as_ptr() as *const u8,
                        compact_records.len() * std::mem::size_of::<GpuShardRamRecord>(),
                    )
                };
                super::cache::append_compact_shard_records(raw_bytes);

                Ok::<(), ZKVMError>(())
            })?;
        } else if gpu_ram_slots.is_some() && is_standard_kind {
            // GPU shard records path (no EC): D2H + lightweight CPU scan
            info_span!("gpu_shard_records").in_scope(|| {
                let ram_buf = gpu_ram_slots.unwrap();
                let slot_bytes: Vec<u32> = ram_buf.to_vec().map_err(|e| {
                    ZKVMError::InvalidWitness(format!("ram_slots D2H failed: {e}").into())
                })?;
                let slots: &[GpuRamRecordSlot] = unsafe {
                    std::slice::from_raw_parts(
                        slot_bytes.as_ptr() as *const GpuRamRecordSlot,
                        slot_bytes.len() * 4 / std::mem::size_of::<GpuRamRecordSlot>(),
                    )
                };
                let mut forked = shard_ctx.get_forked();
                let thread_ctx = &mut forked[0];
                gpu_collect_shard_records(thread_ctx, slots);
                Ok::<(), ZKVMError>(())
            })?;
        } else {
            // CPU: collect shard records only (send/addr_accessed).
            info_span!("cpu_shard_records").in_scope(|| {
                let _ = cpu_collect_shardram::<E, I>(config, shard_ctx, shard_steps, step_indices)?;
                Ok::<(), ZKVMError>(())
            })?;
        }
        lk_multiplicity
    } else {
        // GPU LK counters missing or unverified — fall back to full CPU lk and shardram
        info_span!("cpu_lk_shardram").in_scope(|| {
            cpu_collect_lk_and_shardram::<E, I>(config, shard_ctx, shard_steps, step_indices)
        })?
    };
    debug_compare_final_lk::<E, I>(
        config,
        shard_ctx,
        num_witin,
        num_structural_witin,
        shard_steps,
        step_indices,
        kind,
        &lk_multiplicity,
    )?;
    debug_compare_shardram::<E, I>(config, shard_ctx, shard_steps, step_indices, kind)?;

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

    // Step 4: Keep witness on device in normal mode; D2H only for debug comparison.
    let mut raw_witin = if crate::instructions::gpu::config::is_debug_compare_enabled()
        || !should_keep_witness_device_backing()
    {
        info_span!("transpose_d2h", rows = total_instances, cols = num_witin).in_scope(|| {
            gpu_witness_to_rmm_d2h::<E>(
                hal,
                gpu_witness,
                total_instances,
                num_witin,
                I::padding_strategy(),
            )
        })?
    } else {
        gpu_witness_to_rmm::<E>(
            gpu_witness,
            total_instances,
            num_witin,
            I::padding_strategy(),
        )
    };
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

// Type aliases and D2H conversion functions live in super::utils::d2h.

/// Compute fetch counter parameters from step data.
pub(crate) fn compute_fetch_params(
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
) -> Result<
    (
        WitResult,
        Option<LkResult>,
        Option<RamBuf>,
        Option<CompactEcBuf>,
        Option<CompactEcBuf>,
    ),
    ZKVMError,
> {
    // Upload shard_steps to GPU once (cached across ADD/LW calls within same shard).
    let shard_id = shard_ctx.shard_id;
    info_span!("upload_shard_steps")
        .in_scope(|| upload_shard_steps_cached(hal, shard_steps, shard_id))?;

    // Convert step_indices from usize to u32 for GPU.
    let indices_u32: Vec<u32> = info_span!("indices_u32", n = step_indices.len())
        .in_scope(|| step_indices.iter().map(|&i| i as u32).collect());
    let shard_offset = shard_ctx.current_shard_offset_cycle();

    // Helper to split GpuWitgenFullResult into (witness, Some(lk_counters), ram_slots, compact_ec, compact_addr)
    macro_rules! split_full {
        ($result:expr) => {{
            let full = $result?;
            Ok((
                full.witness,
                Some(full.lk_counters),
                full.ram_slots,
                full.compact_ec,
                full.compact_addr,
            ))
        }};
    }

    // Compute fetch params for all GPU kinds (LK counters are merged into all kernels)
    let (fetch_base_pc, fetch_num_slots) = compute_fetch_params(shard_steps, step_indices);

    // Ensure shard metadata is cached for GPU shard records (shared across all kernel kinds)
    info_span!("ensure_shard_meta")
        .in_scope(|| ensure_shard_metadata_cached(hal, shard_ctx, shard_steps.len()))?;

    match kind {
        GpuWitgenKind::Add => {
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::add::extract_add_column_map(arith_config, num_witin));
            info_span!("hal_witgen_add").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
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
                            })
                    )
                })
            })
        }
        GpuWitgenKind::Sub => {
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sub::extract_sub_column_map(arith_config, num_witin));
            info_span!("hal_witgen_sub").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_sub(
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
                                    format!("GPU witgen_sub failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }
        GpuWitgenKind::LogicR(logic_kind) => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic::logic_circuit::LogicConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::logic_r::extract_logic_r_column_map(logic_config, num_witin)
            });
            info_span!("hal_witgen_logic_r").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_logic_r(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                logic_kind,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_logic_r failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::LogicI(logic_kind) => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::logic_i::extract_logic_i_column_map(logic_config, num_witin)
            });
            info_span!("hal_witgen_logic_i").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_logic_i(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                logic_kind,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_logic_i failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Addi => {
            let addi_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith_imm::arith_imm_circuit_v2::InstructionConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::addi::extract_addi_column_map(addi_config, num_witin));
            info_span!("hal_witgen_addi").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_addi(
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
                                    format!("GPU witgen_addi failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Lui => {
            let lui_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::lui::LuiConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::lui::extract_lui_column_map(lui_config, num_witin));
            info_span!("hal_witgen_lui").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_lui(
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
                                    format!("GPU witgen_lui failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Auipc => {
            let auipc_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::auipc::AuipcConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::auipc::extract_auipc_column_map(auipc_config, num_witin)
            });
            info_span!("hal_witgen_auipc").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_auipc(
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
                                    format!("GPU witgen_auipc failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Jal => {
            let jal_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::jump::jal_v2::JalConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::jal::extract_jal_column_map(jal_config, num_witin));
            info_span!("hal_witgen_jal").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_jal(
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
                                    format!("GPU witgen_jal failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::ShiftR(shift_kind) => {
            let shift_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::shift::shift_circuit_v2::ShiftRTypeConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::shift_r::extract_shift_r_column_map(shift_config, num_witin)
            });
            info_span!("hal_witgen_shift_r").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_shift_r(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                shift_kind,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_shift_r failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::ShiftI(shift_kind) => {
            let shift_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::shift::shift_circuit_v2::ShiftImmConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::shift_i::extract_shift_i_column_map(shift_config, num_witin)
            });
            info_span!("hal_witgen_shift_i").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_shift_i(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                shift_kind,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_shift_i failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Slt(is_signed) => {
            let slt_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::slt::slt_circuit_v2::SetLessThanConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::slt::extract_slt_column_map(slt_config, num_witin));
            info_span!("hal_witgen_slt").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_slt(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                is_signed,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_slt failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Slti(is_signed) => {
            let slti_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::slti::extract_slti_column_map(slti_config, num_witin));
            info_span!("hal_witgen_slti").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_slti(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                is_signed,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_slti failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::BranchEq(is_beq) => {
            let branch_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::branch_eq::extract_branch_eq_column_map(branch_config, num_witin)
            });
            info_span!("hal_witgen_branch_eq").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_branch_eq(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                is_beq,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_branch_eq failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::BranchCmp(is_signed) => {
            let branch_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::branch_cmp::extract_branch_cmp_column_map(branch_config, num_witin)
            });
            info_span!("hal_witgen_branch_cmp").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_branch_cmp(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                is_signed,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_branch_cmp failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Jalr => {
            let jalr_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::jump::jalr_v2::JalrConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::jalr::extract_jalr_column_map(jalr_config, num_witin));
            info_span!("hal_witgen_jalr").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_jalr(
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
                                    format!("GPU witgen_jalr failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Sw => {
            let sw_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 2>)
            };
            let mem_max_bits = sw_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sw::extract_sw_column_map(sw_config, num_witin));
            info_span!("hal_witgen_sw").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_sw(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                mem_max_bits,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_sw failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Sh => {
            let sh_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 1>)
            };
            let mem_max_bits = sh_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sh::extract_sh_column_map(sh_config, num_witin));
            info_span!("hal_witgen_sh").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_sh(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                mem_max_bits,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_sh failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Sb => {
            let sb_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 0>)
            };
            let mem_max_bits = sb_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sb::extract_sb_column_map(sb_config, num_witin));
            info_span!("hal_witgen_sb").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_sb(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                mem_max_bits,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_sb failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::LoadSub {
            load_width,
            is_signed,
        } => {
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load_v2::LoadConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::load_sub::extract_load_sub_column_map(load_config, num_witin)
            });
            let mem_max_bits = load_config.memory_addr.max_bits as u32;
            info_span!("hal_witgen_load_sub").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
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
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_load_sub failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Mul(mul_kind) => {
            let mul_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::mulh::mulh_circuit_v2::MulhConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::mul::extract_mul_column_map(mul_config, num_witin));
            info_span!("hal_witgen_mul").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_mul(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                mul_kind,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_mul failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }

        GpuWitgenKind::Div(div_kind) => {
            let div_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::div::div_circuit_v2::DivRemConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::div::extract_div_column_map(div_config, num_witin));
            info_span!("hal_witgen_div").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_div(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                div_kind,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_div failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }
        GpuWitgenKind::Lw => {
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
                .in_scope(|| super::chips::lw::extract_lw_column_map(load_config, num_witin));
            info_span!("hal_witgen_lw").in_scope(|| {
                with_cached_gpu_ctx(|gpu_records, shard_bufs| {
                    split_full!(
                        hal.witgen
                            .witgen_lw(
                                &col_map,
                                gpu_records,
                                &indices_u32,
                                shard_offset,
                                mem_max_bits,
                                fetch_base_pc,
                                fetch_num_slots,
                                None,
                                Some(shard_bufs),
                            )
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU witgen_lw failed: {e}").into(),
                                )
                            })
                    )
                })
            })
        }
        GpuWitgenKind::Keccak => {
            unreachable!("keccak uses gpu_assign_keccak_instances, not try_gpu_assign_instances")
        }
    }
}
