use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    process::Command,
};

/// Add each example to this list.
///
/// Contact Matthias, if your examples get complicated enough to need their own crates, instead of just being one file.
const EXAMPLES: &[&str] = &[
    "ceno_rt_alloc",
    "ceno_rt_io",
    "ceno_rt_mem",
    "ceno_rt_mini",
    "ceno_rt_panic",
    "hints",
    "sorting",
    "median",
];
const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn build_elfs() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("vars.rs");
    let mut dest = File::create(dest_path).expect("failed to create vars.rs");

    // TODO(Matthias): skip building the elfs if we are in clippy or check mode.
    // See git history for an attempt to do this.
    let output = Command::new("cargo")
        .args(["build", "--release", "--examples"])
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
    for example in EXAMPLES {
        writeln!(
            dest,
            r#"#[allow(non_upper_case_globals)]
            pub const {example}: &[u8] =
                include_bytes!(r"{CARGO_MANIFEST_DIR}/../examples/target/riscv32im-unknown-none-elf/release/examples/{example}");"#
        ).expect("failed to write vars.rs");
    }
    println!("cargo:rerun-if-changed=../examples/");
    println!("cargo:rerun-if-changed=../ceno_rt/");
    let elfs_path = "../examples/target/riscv32im-unknown-none-elf/release/examples/";
    println!("cargo:rerun-if-changed={elfs_path}");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    build_elfs();
}
