use ceno_emul::{StepIndex, StepRecord};
use ceno_gpu::common::witgen::types::{GpuKeccakInstance, GpuKeccakWriteOp, KeccakColumnMap};
use ff_ext::ExtensionField;
use std::sync::Arc;

use crate::instructions::riscv::ecall::keccak::KeccakCoreConfig;

use ceno_emul::SyscallWitness;

use ceno_emul::WordAddr;
use ceno_gpu::{
    Buffer, CudaHal,
    bb31::CudaHalBB31,
    common::{transpose::matrix_transpose, witgen::types::GpuShardRamRecord},
};
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use p3::field::PrimeCharacteristicRing as FieldAlgebra;
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
        config::is_kind_disabled,
        dispatch::{GpuWitgenKind, compute_fetch_params, is_force_cpu_path},
        utils::{
            d2h::{gpu_compact_ec_d2h, gpu_lk_counters_to_multiplicity},
            debug_compare::debug_compare_keccak,
        },
    },
    tables::RMMCollections,
    witness::LkMultiplicity,
};

/// Extract column map from a constructed KeccakCoreConfig.
pub fn extract_keccak_column_map<E: ExtensionField>(
    config: &KeccakCoreConfig<E>,
    num_witin: usize,
) -> KeccakColumnMap {
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
        cycle: config.layout.cycle.id as u32,
        state_ptr: config.layout.state_ptr.id as u32,
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
pub fn gpu_assign_keccak_instances<E: ExtensionField>(
    config: &crate::instructions::riscv::ecall::keccak::KeccakCoreConfig<E>,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> Result<Option<(RMMCollections<E::BaseField>, Multiplicity<u64>)>, ZKVMError> {
    use crate::precompiles::KECCAK_ROUNDS_CEIL_LOG2;
    use gkr_iop::gpu::get_cuda_hal;

    // Guard: disabled or force-CPU
    if is_force_cpu_path() {
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
        let _nvtx = nvtx::range!("ceno.witness.keccak instances={}", num_instances);
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

fn gpu_assign_keccak_inner<E: ExtensionField>(
    config: &crate::instructions::riscv::ecall::keccak::KeccakCoreConfig<E>,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    step_indices: &[StepIndex],
    hal: &CudaHalBB31,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    use crate::precompiles::KECCAK_ROUNDS_CEIL_LOG2;

    let num_instances = step_indices.len();
    let num_rows = num_instances * 32; // 2^5 = 32 rows per instance
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
        .in_scope(|| ensure_shard_metadata_cached(hal, shard_ctx, steps))?;

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
                    num_rows,
                    shard_ctx.current_shard_offset_cycle(),
                    fetch_base_pc,
                    fetch_num_slots,
                    false,
                    None,
                    Some(shard_bufs),
                )
                .map_err(|e| {
                    ZKVMError::InvalidWitness(format!("GPU witgen_keccak failed: {e}").into())
                })
        })
    })?;
    // Keep all post-kernel ownership transfers, optional D2H, structural
    // construction, debug checks, and buffer destruction under one direct
    // child so the parent has complete accounting even when a CUDA allocator
    // defers work until a Rust owner is dropped.
    let _result_assembly_span = info_span!("keccak_result_assembly").entered();

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
    let lk_multiplicity = if gpu_result.shard_lk_accumulated {
        Multiplicity::default()
    } else {
        info_span!("gpu_lk_d2h")
            .in_scope(|| gpu_lk_counters_to_multiplicity(gpu_result.lk_counters))?
    };

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
    let raw_witin = if crate::instructions::gpu::config::is_debug_compare_enabled() {
        let produced_rows = gpu_result.witness.num_rows;
        info_span!("transpose_d2h", rows = produced_rows, cols = num_witin).in_scope(|| {
            let gpu_data: Vec<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField> =
                match gpu_result.witness.layout {
                    DeviceMatrixLayout::RowMajor => {
                        gpu_result.witness.device_buffer.to_vec().map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU D2H copy failed: {e}").into())
                        })?
                    }
                    DeviceMatrixLayout::ColMajor => {
                        let mut rmm_buffer = hal
                            .alloc_elems_on_device(produced_rows * num_witin, false, None)
                            .map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("GPU alloc for transpose failed: {e}").into(),
                                )
                            })?;
                        matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
                            &hal.inner,
                            &mut rmm_buffer,
                            &gpu_result.witness.device_buffer,
                            produced_rows,
                            num_witin,
                        )
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU transpose failed: {e}").into())
                        })?;
                        rmm_buffer.to_vec().map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU D2H copy failed: {e}").into())
                        })?
                    }
                };

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
        RowMajorMatrix::<E::BaseField>::new_by_rotation_device_backing(
            num_instances,
            rotation,
            num_witin,
            InstancePaddingStrategy::Default,
            gpu_result.witness.device_buffer,
            gpu_result.witness.layout,
        )
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
    fn test_gpu_witgen_keccak_correctness() {
        use crate::{
            e2e::ShardContext,
            instructions::gpu::{
                cache::release_all_shard_gpu_caches, dispatch::set_force_cpu_path,
            },
        };

        assert!(
            crate::instructions::gpu::config::is_debug_compare_enabled(),
            "set CENO_GPU_DEBUG_COMPARE_WITGEN=1 to materialize the GPU oracle"
        );

        let mut cs = ConstraintSystem::<E>::new(|| "test_keccak_gpu");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            KeccakInstruction::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();
        let num_witin = cb.cs.num_witin as usize;
        let num_structural_witin = cb.cs.num_structural_witin as usize;

        // Exercise both sides of a warp, power-of-two padding, and the shard-0
        // workload size. Each case uses fresh shard caches so shared counters
        // and compact records cannot leak across oracle comparisons.
        let (step, _program, syscall_witnesses) = ceno_emul::test_utils::keccak_step();
        for num_instances in [1, 31, 32, 33, 64, 4096] {
            release_all_shard_gpu_caches();
            {
                let steps = vec![step; num_instances];
                let step_indices: Vec<usize> = (0..num_instances).collect();

                set_force_cpu_path(true);
                let mut shard_ctx = ShardContext::default();
                shard_ctx.syscall_witnesses = std::sync::Arc::new(syscall_witnesses.clone());
                let (cpu_rmms, cpu_lk) = KeccakInstruction::<E>::assign_instances(
                    &config,
                    &mut shard_ctx,
                    num_witin,
                    num_structural_witin,
                    &steps,
                    &step_indices,
                )
                .unwrap();
                set_force_cpu_path(false);

                let mut shard_ctx_gpu = ShardContext::default();
                shard_ctx_gpu.syscall_witnesses = std::sync::Arc::new(syscall_witnesses.clone());
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

                let gpu_data = gpu_rmms[0].values();
                let cpu_data = cpu_rmms[0].values();
                assert_eq!(gpu_data.len(), cpu_data.len(), "witness size mismatch");
                let col_map = extract_keccak_column_map(&config, num_witin);
                let kbase = col_map.keccak_base_col as usize;
                let mut mismatch_groups = std::collections::BTreeMap::new();
                let mut first_mismatches = Vec::new();
                let mismatches = gpu_data
                    .iter()
                    .zip(cpu_data)
                    .enumerate()
                    .filter(|(index, (gpu, cpu))| {
                        if gpu == cpu {
                            return false;
                        }
                        let row = index / num_witin;
                        let col = index % num_witin;
                        let offset = col.checked_sub(kbase);
                        let stage = match offset {
                            Some(0..=199) => "input8",
                            Some(200..=359) => "c_aux",
                            Some(360..=399) => "c_temp",
                            Some(400..=439) => "c_rot",
                            Some(440..=479) => "d",
                            Some(480..=679) => "theta",
                            Some(680..=871) => "rho_witness",
                            Some(872..=1071) => "rhopi",
                            Some(1072..=1271) => "nonlinear",
                            Some(1272..=1279) => "chi00",
                            Some(1280..=1479) => "iota",
                            Some(1480..=1487) => "round_constant",
                            Some(_) => "keccak_other",
                            None => "metadata",
                        };
                        *mismatch_groups.entry((stage, row)).or_insert(0usize) += 1;
                        if first_mismatches.len() < 32 {
                            first_mismatches.push((row, col, offset, *gpu, *cpu));
                        }
                        true
                    })
                    .count();

                if num_instances == 1 && mismatches != 0 {
                    eprintln!("Keccak first mismatches: {first_mismatches:?}");
                    eprintln!("Keccak mismatch groups (stage,row): {mismatch_groups:?}");
                }

                let gpu_structural = gpu_rmms[1].values();
                let cpu_structural = cpu_rmms[1].values();
                assert_eq!(
                    gpu_structural.len(),
                    cpu_structural.len(),
                    "structural witness size mismatch"
                );
                let structural_mismatches = gpu_structural
                    .iter()
                    .zip(cpu_structural)
                    .filter(|(gpu, cpu)| gpu != cpu)
                    .count();

                let mut lk_mismatches = 0;
                for (gpu_map, cpu_map) in gpu_lk.0.iter().zip(cpu_lk.0.iter()) {
                    for (&key, &gpu_value) in gpu_map {
                        lk_mismatches +=
                            usize::from(cpu_map.get(&key).copied().unwrap_or(0) != gpu_value);
                    }
                    for key in cpu_map.keys() {
                        lk_mismatches += usize::from(!gpu_map.contains_key(key));
                    }
                }

                eprintln!(
                    "Keccak instances={num_instances}: witness={mismatches}/{} structural={structural_mismatches}/{} lk={lk_mismatches}",
                    gpu_data.len(),
                    gpu_structural.len(),
                );
                assert_eq!(mismatches, 0, "GPU vs CPU witness mismatch");
                assert_eq!(
                    structural_mismatches, 0,
                    "GPU vs CPU structural witness mismatch"
                );
                assert_eq!(lk_mismatches, 0, "GPU vs CPU LK multiplicity mismatch");
            }
            release_all_shard_gpu_caches();
        }
    }
}
