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
    cuda::{to_device_or_nullptr, types::MainEvalData},
    main::eval_absorb::MainEvalAbsorbCols,
    system::MainEvalRecord,
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
