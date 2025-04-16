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

use crate::{commands::common_args::*, utils::*};
use anyhow::bail;
use clap::Parser;
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(name = "build", about = "Compile an Ceno program")]
pub struct BuildCmd {
    #[clap(flatten, next_help_heading = "Options")]
    pub cargo_options: CargoOptions,
    #[clap(flatten, next_help_heading = "Package Selection")]
    pub package_selection: PackageSelection,
    #[clap(flatten, next_help_heading = "Target Selection")]
    pub target_selection: TargetSelection,
    #[clap(flatten, next_help_heading = "Feature Selection")]
    pub feature_selection: FeatureSelection,
    #[clap(flatten, next_help_heading = "Compilation Options")]
    pub compilation_options: CompilationOptions,
    #[clap(flatten, next_help_heading = "Manifest Options")]
    pub manifest_options: ManifestOptions,
}

impl BuildCmd {
    pub fn run(self, toolchain: Option<String>) -> anyhow::Result<()> {
        self.cargo_options.set_global();

        let mut command = Command::new("cargo");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .env("RUSTFLAGS", get_rust_flags());

        if let Some(toolchain) = toolchain {
            command.arg(format!("+{}", toolchain));
        }
        command.arg("build");

        self.cargo_options.apply_to(&mut command);
        self.package_selection.apply_to(&mut command);
        self.target_selection.apply_to(&mut command);
        self.feature_selection.apply_to(&mut command);
        let _guard = self.compilation_options.apply_to(&mut command)?;
        self.manifest_options.apply_to(&mut command)?;
        apply_cargo_build_std_args(&mut command);
        print_cmdline(&command);

        let status = command.status()?;
        if !status.success() {
            match status.code() {
                Some(code) => bail!("cargo exited with status code: {code}"),
                None => bail!("cargo terminated by signal"),
            }
        }
        Ok(())
    }
}
