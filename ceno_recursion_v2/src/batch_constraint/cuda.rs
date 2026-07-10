use openvm_cuda_backend::{GpuBackend, base::DeviceMatrix};
use openvm_cuda_common::{
    d_buffer::DeviceBuffer,
    error::CudaError,
    memory_manager::MemTracker,
    stream::{GpuDeviceCtx, cudaStream_t},
};
use openvm_stark_backend::prover::AirProvingContext;
use openvm_stark_sdk::config::baby_bear_poseidon2::F;
use p3_field::BasedVectorSpace;

use crate::{
    cuda::{
        to_device_or_nullptr,
        types::{MainEvalData, MainFrontloadTermData, MainTowerPointEqData},
    },
    main::{
        eval_absorb::MainEvalAbsorbCols, frontload::MainFrontloadTermCols,
        tower_point::MainTowerPointEqCols,
    },
    system::{MainEvalRecord, MainFrontloadTermRecord, MainTowerPointEqRecord},
    tracegen::ModuleChip,
};

unsafe extern "C" {
    fn _main_eval_absorb_tracegen(
        d_trace: *mut F,
        height: usize,
        d_records: *const MainEvalData,
        num_records: usize,
        stream: cudaStream_t,
    ) -> i32;

    fn _main_tower_point_eq_tracegen(
        d_trace: *mut F,
        height: usize,
        d_records: *const MainTowerPointEqData,
        num_records: usize,
        stream: cudaStream_t,
    ) -> i32;

    fn _main_frontload_term_tracegen(
        d_trace: *mut F,
        height: usize,
        d_records: *const MainFrontloadTermData,
        num_records: usize,
        stream: cudaStream_t,
    ) -> i32;
}

unsafe fn main_eval_absorb_tracegen(
    d_trace: &DeviceBuffer<F>,
    height: usize,
    d_records: &DeviceBuffer<MainEvalData>,
    num_records: usize,
    stream: cudaStream_t,
) -> Result<(), CudaError> {
    unsafe {
        CudaError::from_result(_main_eval_absorb_tracegen(
            d_trace.as_mut_ptr(),
            height,
            d_records.as_ptr(),
            num_records,
            stream,
        ))
    }
}

unsafe fn main_tower_point_eq_tracegen(
    d_trace: &DeviceBuffer<F>,
    height: usize,
    d_records: &DeviceBuffer<MainTowerPointEqData>,
    num_records: usize,
    stream: cudaStream_t,
) -> Result<(), CudaError> {
    unsafe {
        CudaError::from_result(_main_tower_point_eq_tracegen(
            d_trace.as_mut_ptr(),
            height,
            d_records.as_ptr(),
            num_records,
            stream,
        ))
    }
}

unsafe fn main_frontload_term_tracegen(
    d_trace: &DeviceBuffer<F>,
    height: usize,
    d_records: &DeviceBuffer<MainFrontloadTermData>,
    num_records: usize,
    stream: cudaStream_t,
) -> Result<(), CudaError> {
    unsafe {
        CudaError::from_result(_main_frontload_term_tracegen(
            d_trace.as_mut_ptr(),
            height,
            d_records.as_ptr(),
            num_records,
            stream,
        ))
    }
}

pub struct MainEvalAbsorbGpuTraceGenerator;

impl ModuleChip<GpuBackend> for MainEvalAbsorbGpuTraceGenerator {
    type Ctx<'a> = &'a [MainEvalRecord];

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_proving_ctx(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<AirProvingContext<GpuBackend>> {
        let mem = MemTracker::start("tracegen.main_eval_absorb");
        let num_valid_rows = records.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };
        let width = MainEvalAbsorbCols::<F>::width();
        let device_ctx = GpuDeviceCtx::for_current_device().ok()?;
        let trace = DeviceMatrix::with_capacity_on(height, width, &device_ctx);

        let records = records
            .iter()
            .map(|record| MainEvalData {
                proof_idx: record.proof_idx,
                idx: record.idx,
                eval_idx: record.eval_idx,
                tidx: record.tidx,
                value: record
                    .value
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                lookup_count: record.lookup_count,
            })
            .collect::<Vec<_>>();
        let d_records = to_device_or_nullptr(&records).ok()?;
        unsafe {
            main_eval_absorb_tracegen(
                trace.buffer(),
                height,
                &d_records,
                records.len(),
                device_ctx.stream.as_raw(),
            )
            .ok()?;
        }
        device_ctx.stream.synchronize().ok()?;
        mem.emit_metrics();
        Some(AirProvingContext::simple_no_pis(trace))
    }
}

pub struct MainFrontloadTermGpuTraceGenerator;

impl ModuleChip<GpuBackend> for MainFrontloadTermGpuTraceGenerator {
    type Ctx<'a> = &'a [MainFrontloadTermRecord];

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_proving_ctx(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<AirProvingContext<GpuBackend>> {
        let mem = MemTracker::start("tracegen.main_frontload_term");
        let num_valid_rows = records.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };
        let width = MainFrontloadTermCols::<F>::width();
        let device_ctx = GpuDeviceCtx::for_current_device().ok()?;
        let trace = DeviceMatrix::with_capacity_on(height, width, &device_ctx);

        let pack_start = std::time::Instant::now();
        let records = records
            .iter()
            .map(|record| MainFrontloadTermData {
                proof_idx: record.proof_idx,
                idx: record.idx,
                row_idx: record.row_idx,
                node_idx: record.node_idx,
                eval_idx: record.eval_idx,
                has_eval_factor: record.has_eval_factor,
                instance_idx: record.instance_idx,
                challenge_idx: record.challenge_idx,
                global_round_idx: record.global_round_idx,
                has_global_factor: record.has_global_factor,
                is_wit: record.is_wit,
                is_const: record.is_const,
                is_instance: record.is_instance,
                is_challenge: record.is_challenge,
                is_add: record.is_add,
                is_sub: record.is_sub,
                is_neg: record.is_neg,
                is_mul: record.is_mul,
                is_fold: record.is_fold,
                is_tail: record.is_tail,
                constraint_idx: record.constraint_idx,
                alpha: record
                    .alpha
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                arg0: record
                    .arg0
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                arg1: record
                    .arg1
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                value: record
                    .value
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                chip_acc_in: record
                    .chip_acc_in
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                chip_acc_out: record
                    .chip_acc_out
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                is_last_chip_step: record.is_last_chip_step,
            })
            .collect::<Vec<_>>();
        tracing::info!(
            elapsed_ms = pack_start.elapsed().as_secs_f64() * 1000.0,
            record_count = records.len(),
            height,
            width,
            cells = height * width,
            "main_frontload_term.pack_records"
        );
        let h2d_start = std::time::Instant::now();
        let d_records = to_device_or_nullptr(&records).ok()?;
        tracing::info!(
            elapsed_ms = h2d_start.elapsed().as_secs_f64() * 1000.0,
            record_count = records.len(),
            height,
            width,
            cells = height * width,
            "main_frontload_term.h2d_records"
        );
        let kernel_start = std::time::Instant::now();
        unsafe {
            if let Err(err) = main_frontload_term_tracegen(
                trace.buffer(),
                height,
                &d_records,
                records.len(),
                device_ctx.stream.as_raw(),
            ) {
                tracing::warn!(?err, "main_frontload_term_tracegen failed");
                return None;
            }
        }
        if let Err(err) = device_ctx.stream.synchronize() {
            tracing::warn!(?err, "main_frontload_term_tracegen synchronize failed");
            return None;
        }
        tracing::info!(
            elapsed_ms = kernel_start.elapsed().as_secs_f64() * 1000.0,
            record_count = records.len(),
            height,
            width,
            cells = height * width,
            "main_frontload_term.kernel_launch_sync"
        );
        mem.emit_metrics();
        Some(AirProvingContext::simple_no_pis(trace))
    }
}

pub struct MainTowerPointEqGpuTraceGenerator;

impl ModuleChip<GpuBackend> for MainTowerPointEqGpuTraceGenerator {
    type Ctx<'a> = &'a [MainTowerPointEqRecord];

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_proving_ctx(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<AirProvingContext<GpuBackend>> {
        let mem = MemTracker::start("tracegen.main_tower_point_eq");
        let num_valid_rows = records.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };
        let width = MainTowerPointEqCols::<F>::width();
        let device_ctx = GpuDeviceCtx::for_current_device().ok()?;
        let trace = DeviceMatrix::with_capacity_on(height, width, &device_ctx);

        let records = records
            .iter()
            .map(|record| MainTowerPointEqData {
                proof_idx: record.proof_idx,
                idx: record.idx,
                round_idx: record.round_idx,
                global_value: record
                    .global_value
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                tower_value: record
                    .tower_value
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                eq_in: record
                    .eq_in
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
                eq_out: record
                    .eq_out
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap(),
            })
            .collect::<Vec<_>>();
        let d_records = to_device_or_nullptr(&records).ok()?;
        unsafe {
            main_tower_point_eq_tracegen(
                trace.buffer(),
                height,
                &d_records,
                records.len(),
                device_ctx.stream.as_raw(),
            )
            .ok()?;
        }
        device_ctx.stream.synchronize().ok()?;
        mem.emit_metrics();
        Some(AirProvingContext::simple_no_pis(trace))
    }
}
