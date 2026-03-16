use openvm_cuda_common::{copy::MemCopyH2D, d_buffer::DeviceBuffer, error::MemCopyError};
use recursion_circuit::system::GlobalTraceGenCtx;

pub mod preflight;
pub mod proof;
pub mod types;
pub mod vk;

pub use preflight::PreflightGpu;
pub use proof::ProofGpu;
pub use vk::VerifyingKeyGpu;

pub struct GlobalCtxGpu;

impl GlobalTraceGenCtx for GlobalCtxGpu {
    type ChildVerifyingKey = VerifyingKeyGpu;
    type MultiProof = [ProofGpu];
    type PreflightRecords = [PreflightGpu];
}

pub fn to_device_or_nullptr<T>(h2d: &[T]) -> Result<DeviceBuffer<T>, MemCopyError>
where
    [T]: MemCopyH2D<T>,
{
    if h2d.is_empty() {
        Ok(DeviceBuffer::new())
    } else {
        h2d.to_device()
    }
}
