use glob::glob;
use std::{
    fs::{File, read_dir, remove_file},
    io::{self, Write},
    path::Path,
    process::Command,
};

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

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
    let mut args = vec!["build", "--features", "profiling", "--examples", "--target-dir", "target"];
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
        let example = example.file_stem().unwrap().to_str().unwrap();
        writeln!(
            dest,
            r#"#[allow(non_upper_case_globals)]
            pub const {example}: &[u8] =
                include_bytes!(r"{CARGO_MANIFEST_DIR}/../examples/target/riscv32im-ceno-zkvm-elf/{}/examples/{example}");"#,
        std::env::var("PROFILE").unwrap()).expect("failed to write vars.rs");
    }
    rerun_all_but_target(Path::new("../examples"));
    rerun_all_but_target(Path::new("../ceno_rt"));
    rerun_all_but_target(Path::new("../guest_libs"));
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");
    build_elfs();
}
