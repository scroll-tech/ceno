/// GPU witness generation dispatcher for the proving pipeline.
///
/// This module provides `try_gpu_assign_instances` which:
/// 1. Runs the GPU kernel to fill the witness matrix (fast)
/// 2. Runs a CPU loop to collect side effects (shard_ctx.send, lk_multiplicity)
/// 3. Returns the GPU-generated witness + CPU-collected side effects
use ceno_emul::{StepIndex, StepRecord};
use ceno_gpu::{Buffer, CudaHal, CudaSlice, bb31::CudaHalBB31};
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use multilinear_extensions::util::max_usable_threads;
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use std::cell::RefCell;
use tracing::info_span;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    e2e::ShardContext, error::ZKVMError, instructions::Instruction, tables::RMMCollections,
    witness::LkMultiplicity,
};

#[derive(Debug, Clone, Copy)]
pub enum GpuWitgenKind {
    Add,
    Sub,
    LogicR,
    #[cfg(feature = "u16limb_circuit")]
    LogicI,
    #[cfg(feature = "u16limb_circuit")]
    Addi,
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

    // Step 1: GPU fills witness matrix
    let gpu_witness = info_span!("gpu_kernel").in_scope(|| {
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

    // Step 2: CPU collects side effects (shard_ctx.send, lk_multiplicity)
    let lk_multiplicity = info_span!("cpu_side_effects").in_scope(|| {
        collect_side_effects::<E, I>(config, shard_ctx, num_witin, shard_steps, step_indices)
    })?;

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

    // Step 4: Convert GPU witness to RowMajorMatrix
    let mut raw_witin = info_span!("d2h_copy").in_scope(|| {
        gpu_witness_to_rmm::<E>(
            gpu_witness,
            total_instances,
            num_witin,
            I::padding_strategy(),
        )
    })?;
    raw_witin.padding_by_strategy();

    Ok((
        [raw_witin, raw_structural],
        lk_multiplicity.into_finalize_result(),
    ))
}

/// GPU kernel dispatch based on instruction kind.
fn gpu_fill_witness<E: ExtensionField, I: Instruction<E>>(
    hal: &CudaHalBB31,
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<
    ceno_gpu::common::witgen_types::GpuWitnessResult<
        ceno_gpu::common::BufferImpl<'static, <ff_ext::BabyBearExt4 as ExtensionField>::BaseField>,
    >,
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

    match kind {
        GpuWitgenKind::Add => {
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::add::extract_add_column_map(arith_config, num_witin));
            info_span!("hal_witgen_add").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    hal.witgen_add(&col_map, gpu_records, &indices_u32, shard_offset, None)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_add failed: {e}").into())
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
                    hal.witgen_sub(&col_map, gpu_records, &indices_u32, shard_offset, None)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_sub failed: {e}").into())
                        })
                })
            })
        }
        GpuWitgenKind::LogicR => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic::logic_circuit::LogicConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::logic_r::extract_logic_r_column_map(logic_config, num_witin));
            info_span!("hal_witgen_logic_r").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    hal.witgen_logic_r(&col_map, gpu_records, &indices_u32, shard_offset, None)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_logic_r failed: {e}").into(),
                            )
                        })
                })
            })
        }
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LogicI => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::logic_i::extract_logic_i_column_map(logic_config, num_witin));
            info_span!("hal_witgen_logic_i").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    hal.witgen_logic_i(&col_map, gpu_records, &indices_u32, shard_offset, None)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_logic_i failed: {e}").into(),
                            )
                        })
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
                    hal.witgen_addi(&col_map, gpu_records, &indices_u32, shard_offset, None)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("GPU witgen_addi failed: {e}").into(),
                            )
                        })
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
            let col_map = info_span!("col_map")
                .in_scope(|| super::lw::extract_lw_column_map(load_config, num_witin));
            info_span!("hal_witgen_lw").in_scope(|| {
                with_cached_shard_steps(|gpu_records| {
                    hal.witgen_lw(&col_map, gpu_records, &indices_u32, shard_offset, None)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(format!("GPU witgen_lw failed: {e}").into())
                        })
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
    num_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> Result<LkMultiplicity, ZKVMError> {
    let nthreads = max_usable_threads();
    let total = step_indices.len();
    let batch_size = if total > 256 {
        total.div_ceil(nthreads)
    } else {
        total
    }
    .max(1);

    let lk_multiplicity = LkMultiplicity::default();
    let shard_ctx_vec = shard_ctx.get_forked();

    step_indices
        .par_chunks(batch_size)
        .zip(shard_ctx_vec)
        .flat_map(|(indices, mut shard_ctx)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            let mut scratch = vec![E::BaseField::ZERO; num_witin];
            indices
                .iter()
                .copied()
                .map(|step_idx| {
                    scratch.fill(E::BaseField::ZERO);
                    I::assign_instance(
                        config,
                        &mut shard_ctx,
                        &mut scratch,
                        &mut lk_multiplicity,
                        &shard_steps[step_idx],
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Result<(), ZKVMError>>()?;

    Ok(lk_multiplicity)
}

/// Convert GPU device buffer to RowMajorMatrix via D2H copy.
fn gpu_witness_to_rmm<E: ExtensionField>(
    gpu_result: ceno_gpu::common::witgen_types::GpuWitnessResult<
        ceno_gpu::common::BufferImpl<'static, <ff_ext::BabyBearExt4 as ExtensionField>::BaseField>,
    >,
    num_rows: usize,
    num_cols: usize,
    padding: InstancePaddingStrategy,
) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
    let gpu_data: Vec<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField> = gpu_result
        .device_buffer
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
