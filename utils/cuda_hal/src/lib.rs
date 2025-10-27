// Placeholder crate: This crate acts as a stub to avoid fetching the private repository
// during dependency resolution when the `gpu` feature is not enabled.

// When the `gpu` feature is enabled, the workspace patch should be replaced with
// the real implementation from the private repository.

#[cfg(feature = "gpu")]
compile_error!(
    "GPU feature is enabled but using placeholder crate! \
     Please replace the workspace patch with the real ceno-gpu implementation \
     or build without the gpu feature."
);

// Minimal stub exports to satisfy basic compilation when gpu feature is disabled
pub mod bb31 {
    pub struct CudaHalBB31;

    impl CudaHalBB31 {
        pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            Err("GPU placeholder: real implementation required".into())
        }
    }

    pub fn convert_ceno_to_gpu_basefold_commitment<T>(_hal: &CudaHalBB31, _commitment: &T) -> T {
        panic!("GPU placeholder: real implementation required")
    }

    pub mod buffer {
        pub struct BufferImpl<T>(std::marker::PhantomData<T>);
    }
}

pub struct BasefoldCommitmentWithWitness<T, B>(std::marker::PhantomData<(T, B)>);
