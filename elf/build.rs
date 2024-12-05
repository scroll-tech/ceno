use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    process::Command,
};

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn build_elfs() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("vars.rs");
    let mut dest = File::create(dest_path).expect("failed to create vars.rs");

    // TODO(Matthias): skip building the elfs if we are in clippy or check mode.
    // See git history for an attempt to do this.
    let output = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir("../guest")
        .env_clear()
        .envs(std::env::vars().filter(|x| !x.0.starts_with("CARGO_")))
        .output()
        .expect("cargo command failed to run");
    if !output.status.success() {
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        panic!("cargo build of examples failed.");
    }
    writeln!(
        dest,
        r#"#[allow(non_upper_case_globals)]
        pub const elf: &[u8] =
            include_bytes!(r"{CARGO_MANIFEST_DIR}/../guest/target/riscv32im-unknown-none-elf/release/guest");"#
    ).expect("failed to write vars.rs");
    let input_path = "../guest/";
    let elfs_path = "../guest/target/riscv32im-unknown-none-elf/release/";

    println!("cargo:rerun-if-changed={input_path}");
    println!("cargo:rerun-if-changed={elfs_path}");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    build_elfs();
}
