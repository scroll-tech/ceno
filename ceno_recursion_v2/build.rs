#[cfg(feature = "cuda")]
use {
    openvm_cuda_builder::{CudaBuilder, cuda_available},
    std::{
        env, fs,
        path::{Path, PathBuf},
        process::Command,
    },
};

#[cfg(feature = "cuda")]
fn poseidon2_air_cuda_include() -> Option<PathBuf> {
    fn valid(path: PathBuf) -> Option<PathBuf> {
        path.join("poseidon2-air/tracegen.cuh")
            .exists()
            .then_some(path)
    }

    if let Some(path) = env::var_os("OPENVM_POSEIDON2_AIR_CUDA_INCLUDE").map(PathBuf::from) {
        if let Some(path) = valid(path) {
            return Some(path);
        }
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")?);
    for ancestor in manifest_dir.ancestors() {
        if let Some(path) =
            valid(ancestor.join("openvm/crates/circuits/poseidon2-air/cuda/include"))
        {
            return Some(path);
        }
    }

    let mut cargo_homes = Vec::new();
    if let Some(path) = env::var_os("CARGO_HOME").map(PathBuf::from) {
        cargo_homes.push(path);
    }
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        cargo_homes.push(home.join(".cargo"));
        cargo_homes.push(home.join("data/.cargo"));
    }

    for cargo_home in cargo_homes {
        if let Some(path) = find_poseidon2_air_include_in_cargo_home(&cargo_home) {
            return Some(path);
        }
    }

    None
}

#[cfg(feature = "cuda")]
fn find_poseidon2_air_include_in_cargo_home(cargo_home: &Path) -> Option<PathBuf> {
    let checkouts = cargo_home.join("git/checkouts");
    for repo in fs::read_dir(checkouts).ok()?.flatten() {
        let repo_path = repo.path();
        let name = repo.file_name();
        if !name.to_string_lossy().starts_with("openvm-") {
            continue;
        }
        for checkout in fs::read_dir(repo_path).ok()?.flatten() {
            let candidate = checkout
                .path()
                .join("crates/circuits/poseidon2-air/cuda/include");
            if candidate.join("poseidon2-air/tracegen.cuh").exists() {
                return Some(candidate);
            }
        }
    }
    None
}

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
        let common = if let Some(path) = poseidon2_air_cuda_include() {
            println!("cargo:rerun-if-env-changed=OPENVM_POSEIDON2_AIR_CUDA_INCLUDE");
            common.include(path)
        } else {
            println!(
                "cargo:warning=OpenVM poseidon2-air CUDA headers were not found; set OPENVM_POSEIDON2_AIR_CUDA_INCLUDE"
            );
            common
        };

        common.emit_link_directives();

        common
            .clone()
            .library_name("cuda-ceno-recursion-v2")
            .files_from_glob("cuda/src/**/*.cu")
            .build();
    }
}
