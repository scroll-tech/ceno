//! Build ceno program
//!
//! Reference cargo.toml file:
//! ```toml
//! [unstable]
//! build-std = [
//!   "alloc",
//!   "core",
//!   "compiler_builtins",
//!   "std",
//!   "panic_abort",
//!   "proc_macro",
//! ]
//! build-std-features = [
//!   "compiler-builtins-mem",
//!   "panic_immediate_abort",
//!   "default",
//! ]
//!
//! [profile.dev]
//! panic = "abort"
//!
//! [build]
//! rustflags = [
//!   "-C",
//!   "link-arg=-Tmemory.x",
//!   "-C",
//!   "link-arg=-Tceno_link.x",
//!   "-Zlocation-detail=none",
//!   "-C",
//!   "passes=lower-atomic",
//! ]
//! target = "../ceno_rt/riscv32im-ceno-zkvm-elf.json"
//! ```

use std::env::current_dir;
use clap::Parser;
use std::process::{Command, Stdio};
use anyhow::{bail, Context};
use crate::utils::{print_cmdline, release_target_json, search_cargo_manifest_path};

const BASE_RUST_FLAGS: &[&str] = &[
    "-C",
    "panic=abort",
    "-C",
    "link-arg=-Tmemory.x",
    "-C",
    "link-arg=-Tceno_link.x",
    "-Zlocation-detail=none",
    "-C",
    "passes=lower-atomic",
];

const BASE_CARGO_ARGS: &[&str] = &[
    "-Z",
    "build-std=alloc,core,compiler_builtins,std,panic_abort,proc_macro",
    "-Z",
    "build-std-features=compiler-builtins-mem,panic_immediate_abort,default"
];

#[derive(Parser)]
#[command(name = "build", about = "Compile an Ceno program")]
pub struct BuildCmd {
    // #[clap(flatten)]
    // build_args: BuildArgs,
}

impl BuildCmd {
    pub fn run(&self) -> anyhow::Result<()> {
        // TODO: allow user to provide the manifest path
        let current_dir = current_dir().context("failed to get current directory")?;
        let manifest_path = search_cargo_manifest_path(&current_dir)
            .context("io error when search for Cargo.toml")?
            .context(format!("could not found `Cargo.toml` in `{}` or any parent directory", current_dir.display()))?;
        // TODO: allow user to override the target definition json
        let (_guard, target_json_path) = release_target_json().context("failed to release target definition")?;

        let rust_flags = BASE_RUST_FLAGS.join(" ");

        let mut command = Command::new("cargo");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .env("RUSTFLAGS", rust_flags)
            .arg("build")
            .args(BASE_CARGO_ARGS)
            .arg("--manifest-path")
            .arg(&manifest_path)
            .arg("--target")
            .arg(&target_json_path);
        print_cmdline(&command);
        let status = command.status()?;
        if !status.success() {
            match status.code() {
                Some(code) => bail!("cargo exited with status code: {code}"),
                None => bail!("cargo terminated by signal")
            }
        }
        Ok(())
    }
}
