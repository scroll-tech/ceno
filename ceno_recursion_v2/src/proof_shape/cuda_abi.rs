#![allow(clippy::missing_safety_doc)]

use openvm_cuda_backend::prelude::{Digest, F};
use openvm_cuda_common::{d_buffer::DeviceBuffer, error::CudaError};

use crate::cuda::types::{AirData, PublicValueData, TraceHeight, TraceMetadata};

#[repr(C)]
pub(crate) struct ProofShapePerProof {
    pub num_present: usize,
    pub n_max: usize,
    pub n_logup: usize,
    pub final_cidx: usize,
    pub final_total_interactions: usize,
    pub main_commit: Digest,
}

#[repr(C)]
pub(crate) struct ProofShapeTracegenInputs {
    pub num_airs: usize,
    pub l_skip: usize,
    pub max_interaction_count: u32,
    pub max_cached: usize,
    pub min_cached_idx: usize,
    pub pre_hash: Digest,
    pub range_checker_8_ptr: *mut u32,
    pub range_checker_5_ptr: *mut u32,
    pub pow_checker_ptr: *mut u32,
}

unsafe extern "C" {
    fn _proof_shape_tracegen(
        d_trace: *mut F,
        height: usize,
        d_air_data: *const AirData,
        d_per_row_tidx: *const *const usize,
        d_sorted_trace_heights: *const *const TraceHeight,
        d_sorted_trace_metadata: *const *const TraceMetadata,
        d_cached_commits: *const *const Digest,
        d_per_proof: *const ProofShapePerProof,
        num_proofs: usize,
        inputs: *const ProofShapeTracegenInputs,
    ) -> i32;
    fn _public_values_recursion_tracegen(
        d_trace: *mut F,
        height: usize,
        d_pvs_data: *const *const PublicValueData,
        d_pvs_tidx: *const *const usize,
        num_proofs: usize,
        num_pvs: usize,
    ) -> i32;
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn proof_shape_tracegen(
    d_trace: &DeviceBuffer<F>,
    height: usize,
    d_air_data: &DeviceBuffer<AirData>,
    d_per_row_tidx: Vec<*const usize>,
    d_sorted_trace_heights: Vec<*const TraceHeight>,
    d_sorted_trace_metadata: Vec<*const TraceMetadata>,
    d_cached_commits: Vec<*const Digest>,
    d_per_proof: &DeviceBuffer<ProofShapePerProof>,
    num_proofs: usize,
    inputs: &ProofShapeTracegenInputs,
) -> Result<(), CudaError> {
    unsafe {
        CudaError::from_result(_proof_shape_tracegen(
            d_trace.as_mut_ptr(),
            height,
            d_air_data.as_ptr(),
            d_per_row_tidx.as_ptr(),
            d_sorted_trace_heights.as_ptr(),
            d_sorted_trace_metadata.as_ptr(),
            d_cached_commits.as_ptr(),
            d_per_proof.as_ptr(),
            num_proofs,
            inputs as *const ProofShapeTracegenInputs,
        ))
    }
}

pub unsafe fn public_values_tracegen(
    d_trace: &DeviceBuffer<F>,
    height: usize,
    d_pvs_data: Vec<*const PublicValueData>,
    d_pvs_tidx: Vec<*const usize>,
    num_proofs: usize,
    num_pvs: usize,
) -> Result<(), CudaError> {
    unsafe {
        CudaError::from_result(_public_values_recursion_tracegen(
            d_trace.as_mut_ptr(),
            height,
            d_pvs_data.as_ptr(),
            d_pvs_tidx.as_ptr(),
            num_proofs,
            num_pvs,
        ))
    }
}
