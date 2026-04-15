use ceno_emul::{StepIndex, StepRecord};
use ceno_gpu::common::witgen::types::{GpuKeccakInstance, GpuKeccakWriteOp, KeccakColumnMap};
use ff_ext::ExtensionField;
use std::sync::Arc;

use crate::instructions::riscv::ecall::keccak::EcallKeccakConfig;

use ceno_emul::SyscallWitness;

use ceno_emul::WordAddr;
use ceno_gpu::{
    Buffer, CudaHal,
    bb31::CudaHalBB31,
    common::{transpose::matrix_transpose, witgen::types::GpuShardRamRecord},
};
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use p3::field::FieldAlgebra;
use tracing::info_span;
use witness::{DeviceMatrixLayout, InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    instructions::gpu::{
        cache::{
            ensure_shard_metadata_cached, read_shared_addr_count, read_shared_addr_range,
            with_cached_shard_meta,
        },
        config::{
            is_debug_compare_enabled, is_gpu_witgen_enabled, is_kind_disabled,
            should_keep_witness_device_backing,
        },
        dispatch::{GpuWitgenKind, compute_fetch_params, is_force_cpu_path},
        utils::{
            d2h::{gpu_compact_ec_d2h, gpu_lk_counters_to_multiplicity},
            debug_compare::debug_compare_keccak,
        },
    },
    tables::RMMCollections,
    witness::LkMultiplicity,
};

/// Extract column map from a constructed EcallKeccakConfig.
///
/// VM state columns are listed individually. Keccak math columns use
/// a single base offset since they're allocated contiguously via transmute.
pub fn extract_keccak_column_map<E: ExtensionField>(
    config: &EcallKeccakConfig<E>,
    num_witin: usize,
) -> KeccakColumnMap {
    // StateInOut
    let pc = config.vm_state.pc.id as u32;
    let ts = config.vm_state.ts.id as u32;

    // OpFixedRS<reg_ecall, read> - ecall_id
    let ecall_prev_ts = config.ecall_id.prev_ts.id as u32;
    let ecall_lt_diff = {
        let diffs = &config.ecall_id.lt_cfg.0.diff;
        assert_eq!(
            diffs.len(),
            2,
            "Expected 2 AssertLt diff limbs for ecall_id"
        );
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // MemAddr - state_ptr address limbs
    let addr_limbs = {
        let limbs = config
            .state_ptr
            .1
            .addr
            .wits_in()
            .expect("MemAddr should have WitIn limbs");
        assert_eq!(limbs.len(), 2, "Expected 2 addr limbs");
        [limbs[0].id as u32, limbs[1].id as u32]
    };

    // OpFixedRS<reg_arg0, write> - state_ptr register write
    let sptr_prev_ts = config.state_ptr.0.prev_ts.id as u32;
    let sptr_prev_val = {
        let limbs = config
            .state_ptr
            .0
            .prev_value
            .as_ref()
            .expect("state_ptr should have prev_value")
            .wits_in()
            .expect("prev_value should have WitIn limbs");
        assert_eq!(limbs.len(), 2, "Expected 2 prev_value limbs");
        [limbs[0].id as u32, limbs[1].id as u32]
    };
    let sptr_lt_diff = {
        let diffs = &config.state_ptr.0.lt_cfg.0.diff;
        assert_eq!(
            diffs.len(),
            2,
            "Expected 2 AssertLt diff limbs for state_ptr"
        );
        [diffs[0].id as u32, diffs[1].id as u32]
    };

    // WriteMEM x50: prev_ts + lt_diff[2] each
    let mut mem_prev_ts = [0u32; 50];
    let mut mem_lt_diff_0 = [0u32; 50];
    let mut mem_lt_diff_1 = [0u32; 50];
    for (i, writer) in config.mem_rw.iter().enumerate() {
        mem_prev_ts[i] = writer.prev_ts.id as u32;
        let diffs = &writer.lt_cfg.0.diff;
        assert_eq!(
            diffs.len(),
            2,
            "Expected 2 AssertLt diff limbs for mem_rw[{}]",
            i
        );
        mem_lt_diff_0[i] = diffs[0].id as u32;
        mem_lt_diff_1[i] = diffs[1].id as u32;
    }

    // Keccak math columns base offset (contiguous block)
    let keccak_base_col = config.layout.layer_exprs.wits.input8[0].id as u32;

    // Verify contiguity of keccak math columns
    #[cfg(debug_assertions)]
    {
        let base = keccak_base_col as usize;
        let expected_size =
            std::mem::size_of::<crate::precompiles::lookup_keccakf::KeccakWitCols<u8>>();
        // Check that the last keccak column is at base + expected_size - 1
        let last_rc = config.layout.layer_exprs.wits.rc.last().unwrap();
        assert_eq!(
            last_rc.id as usize,
            base + expected_size - 1,
            "Keccak math columns not contiguous: last rc id {} != expected {}",
            last_rc.id,
            base + expected_size - 1
        );
    }

    KeccakColumnMap {
        pc,
        ts,
        ecall_prev_ts,
        ecall_lt_diff,
        addr_limbs,
        sptr_prev_ts,
        sptr_prev_val,
        sptr_lt_diff,
        mem_prev_ts,
        mem_lt_diff_0,
        mem_lt_diff_1,
        keccak_base_col,
        num_cols: num_witin as u32,
    }
}

/// Pack step records + syscall witnesses into flat GPU-transferable instances.
pub fn pack_keccak_instances(
    steps: &[StepRecord],
    step_indices: &[StepIndex],
    syscall_witnesses: &Arc<Vec<SyscallWitness>>,
) -> Vec<GpuKeccakInstance> {
    step_indices
        .iter()
        .map(|&idx| {
            let step = &steps[idx];
            let sw = step
                .syscall(syscall_witnesses)
                .expect("keccak step must have syscall witness");

            // Register op (state_ptr)
            let reg_op = &sw.reg_ops[0];
            let gpu_reg_op = GpuKeccakWriteOp {
                addr: reg_op.addr.0,
                value_before: reg_op.value.before,
                value_after: reg_op.value.after,
                _pad: 0,
                previous_cycle: reg_op.previous_cycle,
            };

            // Memory ops (50 read-writes)
            let mut mem_ops = [GpuKeccakWriteOp::default(); 50];
            for (i, op) in sw.mem_ops.iter().enumerate() {
                mem_ops[i] = GpuKeccakWriteOp {
                    addr: op.addr.0,
                    value_before: op.value.before,
                    value_after: op.value.after,
                    _pad: 0,
                    previous_cycle: op.previous_cycle,
                };
            }

            GpuKeccakInstance {
                pc: step.pc().before.0,
                _pad0: 0,
                cycle: step.cycle(),
                ecall_prev_cycle: step.rs1().unwrap().previous_cycle,
                reg_op: gpu_reg_op,
                mem_ops,
            }
        })
        .collect()
}

/// GPU dispatch entry point for keccak ecall witness generation.
///
/// Unlike `try_gpu_assign_instances`, keccak has a rotation-aware matrix layout
/// (each logical instance spans 32 physical rows) and requires building
/// structural witness on CPU with selector indices from the cyclic group.
#[cfg(feature = "gpu")]
pub fn gpu_assign_keccak_instances<E: ExtensionField>(
    config: &crate::instructions::riscv::ecall::keccak::EcallKeccakConfig<E>,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> Result<Option<(RMMCollections<E::BaseField>, Multiplicity<u64>)>, ZKVMError> {
    use crate::precompiles::KECCAK_ROUNDS_CEIL_LOG2;
    use gkr_iop::gpu::get_cuda_hal;

    // Guard: disabled or force-CPU
    if !is_gpu_witgen_enabled() || is_force_cpu_path() {
        return Ok(None);
    }
    // Check if keccak is disabled via CENO_GPU_DISABLE_WITGEN_KINDS=keccak
    if is_kind_disabled(GpuWitgenKind::Keccak) {
        return Ok(None);
    }

    // GPU only supports BabyBear field
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField>()
    {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(hal) => hal,
        Err(_) => return Ok(None),
    };

    // Empty step_indices: return empty matrices
    if step_indices.is_empty() {
        let rotation = KECCAK_ROUNDS_CEIL_LOG2;
        let raw_witin = RowMajorMatrix::<E::BaseField>::new_by_rotation(
            0,
            rotation,
            num_witin,
            InstancePaddingStrategy::Default,
        );
        let raw_structural = RowMajorMatrix::<E::BaseField>::new_by_rotation(
            0,
            rotation,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let lk = LkMultiplicity::default();
        return Ok(Some((
            [raw_witin, raw_structural],
            lk.into_finalize_result(),
        )));
    }

    let num_instances = step_indices.len();
    tracing::debug!("[GPU witgen] keccak with {} instances", num_instances);

    info_span!("gpu_witgen_keccak", n = num_instances).in_scope(|| {
        gpu_assign_keccak_inner::<E>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            steps,
            step_indices,
            &hal,
        )
        .map(Some)
    })
}

/// Keccak-specific GPU witness generation, separate from `gpu_assign_instances_inner` because:
///   1. Rotation: each instance spans 32 rows (not 1), requiring `new_by_rotation`
///   2. Structural witness: 3 selectors (sel_first/sel_last/sel_all) vs the standard 1
///   3. Input packing: needs `packed_instances` with `syscall_witnesses`
///
/// The LK/shardram collection logic (Steps 6-7) is identical to the standard path;
/// it is duplicated here rather than shared.
#[cfg(feature = "gpu")]
fn gpu_assign_keccak_inner<E: ExtensionField>(
    config: &crate::instructions::riscv::ecall::keccak::EcallKeccakConfig<E>,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    step_indices: &[StepIndex],
    hal: &CudaHalBB31,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use crate::precompiles::KECCAK_ROUNDS_CEIL_LOG2;

    let num_instances = step_indices.len();
    let num_padded_instances = num_instances.next_power_of_two().max(2);
    let num_padded_rows = num_padded_instances * 32; // 2^5 = 32 rows per instance
    let rotation = KECCAK_ROUNDS_CEIL_LOG2; // = 5

    // Step 1: Extract column map
    let col_map = info_span!("col_map").in_scope(|| extract_keccak_column_map(config, num_witin));

    // Step 2: Pack instances
    let packed_instances = info_span!("pack_instances")
        .in_scope(|| pack_keccak_instances(steps, step_indices, &shard_ctx.syscall_witnesses));

    // Step 3: Compute fetch params
    let (fetch_base_pc, fetch_num_slots) = compute_fetch_params(steps, step_indices);

    // Step 4: Ensure shard metadata cached
    info_span!("ensure_shard_meta")
        .in_scope(|| ensure_shard_metadata_cached(hal, shard_ctx, steps.len()))?;

    // Snapshot shared addr count before kernel (for debug comparison)
    let addr_count_before = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        read_shared_addr_count()
    } else {
        0
    };

    // Step 5: Launch GPU kernel
    let gpu_result = info_span!("gpu_kernel").in_scope(|| {
        with_cached_shard_meta(|shard_bufs| {
            hal.witgen
                .witgen_keccak(
                    &col_map,
                    &packed_instances,
                    num_padded_rows,
                    shard_ctx.current_shard_offset_cycle(),
                    fetch_base_pc,
                    fetch_num_slots,
                    None,
                    Some(shard_bufs),
                )
                .map_err(|e| {
                    ZKVMError::InvalidWitness(format!("GPU witgen_keccak failed: {e}").into())
                })
        })
    })?;

    // D2H keccak's addr entries from shared buffer (delta since before kernel)
    let gpu_keccak_addrs = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        let addr_count_after = read_shared_addr_count();
        if addr_count_after > addr_count_before {
            read_shared_addr_range(addr_count_before, addr_count_after)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Step 6: Collect LK multiplicity
    let lk_multiplicity = info_span!("gpu_lk_d2h")
        .in_scope(|| gpu_lk_counters_to_multiplicity(gpu_result.lk_counters))?;

    // Debug LK comparison is done in the unit test instead.

    // Step 7: Handle compact EC records (shared buffer path)
    if gpu_result.compact_ec.is_none() && gpu_result.compact_addr.is_none() {
        // Shared buffer path: EC records + addr_accessed accumulated on device
        // in shared buffers across all kernel invocations. Skip per-kernel D2H.
    } else if let Some(compact) = gpu_result.compact_ec {
        info_span!("gpu_ec_shard").in_scope(|| {
            let compact_records =
                info_span!("compact_d2h").in_scope(|| gpu_compact_ec_d2h(&compact))?;

            // D2H compact addr_accessed
            info_span!("compact_addr_d2h").in_scope(|| -> Result<(), ZKVMError> {
                if let Some(ref ca) = gpu_result.compact_addr {
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
                }
                Ok(())
            })?;

            // Accumulate compact shard records for assign_shared_circuit
            let raw_bytes = unsafe {
                std::slice::from_raw_parts(
                    compact_records.as_ptr() as *const u8,
                    compact_records.len() * std::mem::size_of::<GpuShardRamRecord>(),
                )
            };
            crate::instructions::gpu::cache::append_compact_shard_records(raw_bytes);

            Ok::<(), ZKVMError>(())
        })?;
    }

    // Step 8: Keep witness on device only when cache policy keeps device backing.
    // In debug mode or cache-none mode, do transpose + D2H.
    let raw_witin = if crate::instructions::gpu::config::is_debug_compare_enabled()
        || !should_keep_witness_device_backing()
    {
        info_span!("transpose_d2h", rows = num_padded_rows, cols = num_witin).in_scope(|| {
            let mut rmm_buffer = hal
                .alloc_elems_on_device(num_padded_rows * num_witin, false, None)
                .map_err(|e| {
                    ZKVMError::InvalidWitness(format!("GPU alloc for transpose failed: {e}").into())
                })?;
            matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
                &hal.inner,
                &mut rmm_buffer,
                &gpu_result.witness.device_buffer,
                num_padded_rows,
                num_witin,
            )
            .map_err(|e| ZKVMError::InvalidWitness(format!("GPU transpose failed: {e}").into()))?;

            let gpu_data: Vec<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField> =
                rmm_buffer.to_vec().map_err(|e| {
                    ZKVMError::InvalidWitness(format!("GPU D2H copy failed: {e}").into())
                })?;

            // Safety: BabyBear is the only supported GPU field, and E::BaseField must match
            let data: Vec<E::BaseField> = unsafe {
                let mut data = std::mem::ManuallyDrop::new(gpu_data);
                Vec::from_raw_parts(
                    data.as_mut_ptr() as *mut E::BaseField,
                    data.len(),
                    data.capacity(),
                )
            };

            let mut rmm = RowMajorMatrix::<E::BaseField>::new_by_rotation(
                num_instances,
                rotation,
                num_witin,
                InstancePaddingStrategy::Default,
            );
            std::ops::DerefMut::deref_mut(&mut rmm).values[..data.len()].copy_from_slice(&data);
            Ok::<_, ZKVMError>(rmm)
        })?
    } else {
        let mut rmm = RowMajorMatrix::<E::BaseField>::new_by_rotation(
            num_instances,
            rotation,
            num_witin,
            InstancePaddingStrategy::Default,
        );
        rmm.set_device_backing(
            gpu_result.witness.device_buffer,
            DeviceMatrixLayout::ColMajor,
        );
        rmm
    };

    // Step 9: Build structural witness on CPU with selector indices
    let raw_structural = info_span!("structural_witness").in_scope(|| {
        let mut raw_structural = RowMajorMatrix::<E::BaseField>::new_by_rotation(
            num_instances,
            rotation,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        // Get selector column IDs from config
        let sel_first = config
            .layout
            .selector_type_layout
            .sel_first
            .as_ref()
            .expect("sel_first must be Some");
        let sel_last = config
            .layout
            .selector_type_layout
            .sel_last
            .as_ref()
            .expect("sel_last must be Some");

        let sel_first_id = sel_first.selector_expr().id();
        let sel_last_id = sel_last.selector_expr().id();
        let sel_all_id = config
            .layout
            .selector_type_layout
            .sel_all
            .selector_expr()
            .id();

        let sel_first_indices = sel_first.sparse_indices();
        let sel_last_indices = sel_last.sparse_indices();
        let sel_all_indices = config.layout.selector_type_layout.sel_all.sparse_indices();

        // Only set selectors for real instances, not padding ones.
        for instance_chunk in raw_structural.iter_mut().take(num_instances) {
            // instance_chunk is a &mut [F] of size 32 * num_structural_witin
            for &idx in sel_first_indices {
                instance_chunk[idx * num_structural_witin + sel_first_id] = E::BaseField::ONE;
            }
            for &idx in sel_last_indices {
                instance_chunk[idx * num_structural_witin + sel_last_id] = E::BaseField::ONE;
            }
            for &idx in sel_all_indices {
                instance_chunk[idx * num_structural_witin + sel_all_id] = E::BaseField::ONE;
            }
        }
        raw_structural.padding_by_strategy();

        raw_structural
    });

    // Debug comparisons (activated by env vars)
    debug_compare_keccak::<E>(
        config,
        shard_ctx,
        num_witin,
        num_structural_witin,
        steps,
        step_indices,
        &lk_multiplicity,
        &raw_witin,
        &gpu_keccak_addrs,
    )?;

    Ok(([raw_witin, raw_structural], lk_multiplicity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::ecall::keccak::KeccakInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_keccak_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            KeccakInstruction::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();

        let col_map = extract_keccak_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        // All column IDs should be within range
        // Note: keccak_base_col and num_cols are metadata, not column indices
        let metadata_indices = [flat.len() - 1, flat.len() - 2]; // num_cols, keccak_base_col
        for (i, &col) in flat.iter().enumerate() {
            if metadata_indices.contains(&i) {
                continue;
            }
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (index {}) out of range: {} >= {}",
                i,
                col,
                col,
                col_map.num_cols
            );
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_witgen_keccak_correctness() {
        use crate::e2e::ShardContext;

        let mut cs = ConstraintSystem::<E>::new(|| "test_keccak_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            KeccakInstruction::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        // Get test data from emulator
        let (step, _program, syscall_witnesses) = ceno_emul::test_utils::keccak_step();
        let steps = vec![step];
        let step_indices: Vec<usize> = vec![0];

        // --- CPU path (force CPU via thread-local flag) ---
        use crate::instructions::gpu::dispatch::set_force_cpu_path;
        set_force_cpu_path(true);
        let mut shard_ctx = ShardContext::default();
        shard_ctx.syscall_witnesses = std::sync::Arc::new(syscall_witnesses.clone());
        let (cpu_rmms, _cpu_lkm) = KeccakInstruction::<E>::assign_instances(
            &config,
            &mut shard_ctx,
            num_witin,
            num_structural_witin,
            &steps,
            &step_indices,
        )
        .unwrap();
        set_force_cpu_path(false);
        let cpu_witness = &cpu_rmms[0];
        let cpu_structural = &cpu_rmms[1];

        // --- GPU path (full pipeline via gpu_assign_keccak_instances) ---
        use super::gpu_assign_keccak_instances;
        let mut shard_ctx_gpu = ShardContext::default();
        shard_ctx_gpu.syscall_witnesses = std::sync::Arc::new(syscall_witnesses);
        let (gpu_rmms, gpu_lk) = gpu_assign_keccak_instances::<E>(
            &config,
            &mut shard_ctx_gpu,
            num_witin,
            num_structural_witin,
            &steps,
            &step_indices,
        )
        .unwrap()
        .expect("GPU path should not return None");
        let gpu_witness = &gpu_rmms[0];
        let gpu_structural = &gpu_rmms[1];

        // --- Compare witness (raw_witin) ---
        let gpu_data = gpu_witness.values();
        let cpu_data = cpu_witness.values();
        assert_eq!(gpu_data.len(), cpu_data.len(), "witness size mismatch");

        let mut mismatches = 0;
        for (i, (g, c)) in gpu_data.iter().zip(cpu_data.iter()).enumerate() {
            if g != c {
                if mismatches < 20 {
                    let row = i / num_witin;
                    let col = i % num_witin;
                    eprintln!(
                        "Witness mismatch row={}, col={}: GPU={:?}, CPU={:?}",
                        row, col, g, c
                    );
                }
                mismatches += 1;
            }
        }
        eprintln!(
            "Keccak witness: {} mismatches out of {} cells",
            mismatches,
            gpu_data.len()
        );

        // --- Compare structural witness ---
        let gpu_struct_data = gpu_structural.values();
        let cpu_struct_data = cpu_structural.values();
        assert_eq!(
            gpu_struct_data.len(),
            cpu_struct_data.len(),
            "structural witness size mismatch"
        );

        let mut struct_mismatches = 0;
        for (i, (g, c)) in gpu_struct_data
            .iter()
            .zip(cpu_struct_data.iter())
            .enumerate()
        {
            if g != c {
                if struct_mismatches < 20 {
                    let row = i / num_structural_witin;
                    let col = i % num_structural_witin;
                    eprintln!(
                        "Structural mismatch row={}, col={}: GPU={:?}, CPU={:?}",
                        row, col, g, c
                    );
                }
                struct_mismatches += 1;
            }
        }
        eprintln!(
            "Keccak structural: {} mismatches out of {} cells",
            struct_mismatches,
            gpu_struct_data.len()
        );

        // --- Compare LK multiplicity ---
        let mut lk_mismatches = 0;
        for (table_idx, (gpu_map, cpu_map)) in gpu_lk.0.iter().zip(_cpu_lkm.0.iter()).enumerate() {
            for (&k, &gpu_v) in gpu_map.iter() {
                let cpu_v = cpu_map.get(&k).copied().unwrap_or(0);
                if gpu_v != cpu_v {
                    if lk_mismatches < 30 {
                        eprintln!(
                            "LK mismatch table={}, key={:#x}: GPU={}, CPU={}",
                            table_idx, k, gpu_v, cpu_v,
                        );
                    }
                    lk_mismatches += 1;
                }
            }
            for (&k, &cpu_v) in cpu_map.iter() {
                if !gpu_map.contains_key(&k) {
                    if lk_mismatches < 30 {
                        eprintln!(
                            "LK mismatch table={}, key={:#x}: GPU=missing, CPU={}",
                            table_idx, k, cpu_v,
                        );
                    }
                    lk_mismatches += 1;
                }
            }
        }
        eprintln!("Keccak LK: {} mismatches", lk_mismatches);

        assert_eq!(mismatches, 0, "GPU vs CPU witness mismatch");
        assert_eq!(
            struct_mismatches, 0,
            "GPU vs CPU structural witness mismatch"
        );
        assert_eq!(lk_mismatches, 0, "GPU vs CPU LK multiplicity mismatch");
    }
}
