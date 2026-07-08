#[cfg(feature = "cuda")]
use {
    openvm_cuda_builder::{CudaBuilder, cuda_available},
    std::{env, process::Command},
};

fn main() {
    #[cfg(feature = "cuda")]
    {
        if !cuda_available() {
            println!(
                "cargo:warning=CUDA toolkit is not available; skipping ceno_recursion_v2 CUDA kernels"
            );
            return;
        }

        if env::var_os("CUDA_ARCH").is_none()
            && Command::new("nvidia-smi")
                .args(["--query-gpu=compute_cap", "--format=csv,noheader"])
                .output()
                .map(|output| !output.status.success() || output.stdout.is_empty())
                .unwrap_or(true)
        {
            println!(
                "cargo:warning=nvidia-smi did not report a CUDA device; defaulting CUDA_ARCH=80 for kernel compilation"
            );
            // The build script is single-threaded here; this only controls CudaBuilder arch detection.
            unsafe { env::set_var("CUDA_ARCH", "80") };
        }

        let common = CudaBuilder::new()
            .include_from_dep("DEP_CUDA_COMMON_INCLUDE")
            .include("cuda/include")
            .flag("-Xcompiler=-Wno-maybe-uninitialized");

        common.emit_link_directives();

        common
            .clone()
            .library_name("cuda-ceno-recursion-v2")
            .files_from_glob("cuda/src/**/*.cu")
            .build();
    }
}
