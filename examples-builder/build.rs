use glob::glob;
use std::{
    fs::{File, read_dir, remove_file},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

fn rerun_all_but_target(dir: &Path) {
    for entry in read_dir(dir).unwrap().filter_map(Result::ok) {
        if "target" == entry.file_name() {
            continue;
        }
        println!("cargo:rerun-if-changed={}", entry.path().to_string_lossy());
    }
}

fn build_elfs() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("vars.rs");
    let _ = remove_file(&dest_path);
    let mut dest = File::create(&dest_path).expect("failed to create vars.rs");

    let is_release = std::env::var("PROFILE").unwrap() == "release";
    let guest_target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|path| path.join("ceno-guest-examples"))
        .unwrap_or_else(|| PathBuf::from("target"));
    let guest_target_str = guest_target.to_string_lossy().into_owned();
    let mut args = vec!["build", "--examples", "--target-dir", &guest_target_str];
    let llama_tiny = std::env::var_os("CARGO_FEATURE_LLAMA_TINY").is_some();
    let production_heads_1 = std::env::var_os("CARGO_FEATURE_PRODUCTION_HEADS_1").is_some();
    let production_heads_2 = std::env::var_os("CARGO_FEATURE_PRODUCTION_HEADS_2").is_some();
    let production_heads_4 = std::env::var_os("CARGO_FEATURE_PRODUCTION_HEADS_4").is_some();
    let production_heads_8 = std::env::var_os("CARGO_FEATURE_PRODUCTION_HEADS_8").is_some();
    let resident_block_1 = std::env::var_os("CARGO_FEATURE_RESIDENT_BLOCK_1").is_some();
    let resident_block_2 = std::env::var_os("CARGO_FEATURE_RESIDENT_BLOCK_2").is_some();
    let resident_block_4 = std::env::var_os("CARGO_FEATURE_RESIDENT_BLOCK_4").is_some();
    let resident_segments_2 = std::env::var_os("CARGO_FEATURE_RESIDENT_SEGMENTS_2").is_some();
    assert!(
        usize::from(resident_block_1)
            + usize::from(resident_block_2)
            + usize::from(resident_block_4)
            <= 1,
        "resident block multiplier features are mutually exclusive"
    );
    if llama_tiny {
        args.extend(["--features", "llama-tiny"]);
    }
    assert!(
        usize::from(production_heads_1)
            + usize::from(production_heads_2)
            + usize::from(production_heads_4)
            + usize::from(production_heads_8)
            <= 1,
        "production head-count features are mutually exclusive"
    );
    if production_heads_1 {
        args.extend(["--features", "production-heads-1"]);
    }
    if production_heads_2 {
        args.extend(["--features", "production-heads-2"]);
    }
    if production_heads_4 {
        args.extend(["--features", "production-heads-4"]);
    }
    if production_heads_8 {
        args.extend(["--features", "production-heads-8"]);
    }
    if resident_block_1 {
        args.extend(["--features", "resident-block-1"]);
    }
    if resident_block_2 {
        args.extend(["--features", "resident-block-2"]);
    }
    if resident_block_4 {
        args.extend(["--features", "resident-block-4"]);
    }
    if resident_segments_2 {
        args.extend(["--features", "resident-segments-2"]);
    }
    if is_release {
        args.insert(1, "--release"); // insert --release after "build"
    }

    let output = Command::new("cargo")
        .args(args)
        .current_dir("../examples")
        .env_clear()
        .envs(std::env::vars().filter(|x| !x.0.starts_with("CARGO_")))
        .output()
        .expect("cargo command failed to run");

    if !output.status.success() {
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        panic!("cargo build of examples failed.");
    }

    for example in glob("../examples/examples/*.rs")
        .unwrap()
        .map(Result::unwrap)
    {
        println!("cargo:rerun-if-changed={}", example.display());
        let example = example.file_stem().unwrap().to_str().unwrap();
        // `vars.rs` embeds every guest ELF.  The plain `cargo build --examples`
        // above overwrites them without the AOT basic-block map, while Cargo
        // Ceno currently accepts one example at a time.
        let mut ceno_args = vec!["ceno", "build", "--example", example];
        if llama_tiny {
            ceno_args.extend(["--features", "llama-tiny"]);
        }
        if production_heads_1 {
            ceno_args.extend(["--features", "production-heads-1"]);
        }
        if production_heads_2 {
            ceno_args.extend(["--features", "production-heads-2"]);
        }
        if production_heads_4 {
            ceno_args.extend(["--features", "production-heads-4"]);
        }
        if production_heads_8 {
            ceno_args.extend(["--features", "production-heads-8"]);
        }
        if resident_block_1 {
            ceno_args.extend(["--features", "resident-block-1"]);
        }
        if resident_block_2 {
            ceno_args.extend(["--features", "resident-block-2"]);
        }
        if resident_block_4 {
            ceno_args.extend(["--features", "resident-block-4"]);
        }
        if resident_segments_2 {
            ceno_args.extend(["--features", "resident-segments-2"]);
        }
        if is_release {
            ceno_args.push("--release");
        }
        let output = Command::new("cargo")
            .args(ceno_args)
            .current_dir("../examples")
            .env_clear()
            .envs(std::env::vars().filter(|x| !x.0.starts_with("CARGO_")))
            .env("CARGO_TARGET_DIR", &guest_target)
            .output()
            .expect("cargo ceno build failed to run");
        if !output.status.success() {
            io::stdout().write_all(&output.stdout).unwrap();
            io::stderr().write_all(&output.stderr).unwrap();
            panic!("cargo ceno build of embedded example {example} failed.");
        }
        writeln!(
            dest,
            r#"#[allow(non_upper_case_globals)]
            pub const {example}: &[u8] =
                include_bytes!(r"{}/riscv32im-ceno-zkvm-elf/{}/examples/{example}");"#,
            guest_target.display(),
            std::env::var("PROFILE").unwrap()
        )
        .expect("failed to write vars.rs");
    }
    rerun_all_but_target(Path::new("../examples"));
    rerun_all_but_target(Path::new("../ceno_rt"));
    rerun_all_but_target(Path::new("../guest_libs"));
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // The TensorBus guest ABI lives below `ceno_rt/src`; the shallow directory
    // scan above does not notice this file on every Cargo implementation.
    println!("cargo:rerun-if-changed=../ceno_rt/src/tensor.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_LLAMA_TINY");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PRODUCTION_HEADS_1");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PRODUCTION_HEADS_2");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_RESIDENT_BLOCK_1");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_RESIDENT_BLOCK_2");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_RESIDENT_BLOCK_4");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_RESIDENT_SEGMENTS_2");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    build_elfs();
}
