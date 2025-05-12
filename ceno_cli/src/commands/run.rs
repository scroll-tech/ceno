use crate::{
    commands::{BuildCmd, common_args::*},
    utils::*,
};
use clap::Parser;
use std::env::current_dir;

#[derive(Parser)]
#[command(name = "keygen", about = "Generate vk for a Cargo Ceno program")]
pub struct KeygenCmd {
    #[clap(flatten)]
    inner: CmdInner,
}

#[derive(Parser)]
#[command(name = "run", about = "Run a Cargo Ceno program")]
pub struct RunCmd {
    #[clap(flatten)]
    inner: CmdInner,
}

#[derive(Parser)]
#[command(name = "prove", about = "Run and Prove a Cargo Ceno program")]
pub struct ProveCmd {
    #[clap(flatten)]
    inner: CmdInner,
}

#[derive(Parser)]
#[command(name = "run", about = "Run a Cargo Ceno program")]
struct CmdInner {
    #[clap(flatten, next_help_heading = "Ceno Options")]
    ceno_options: CenoOptions,
    #[clap(flatten, next_help_heading = "Cargo Options")]
    cargo_options: CargoOptions,
    #[clap(flatten, next_help_heading = "Package Selection")]
    package_selection: PackageSelection,
    #[clap(flatten, next_help_heading = "Target Selection")]
    target_selection: TargetSelection,
    #[clap(flatten, next_help_heading = "Feature Selection")]
    feature_selection: FeatureSelection,
    #[clap(flatten, next_help_heading = "Compilation Options")]
    compilation_options: CompilationOptions,
    #[clap(flatten, next_help_heading = "Manifest Options")]
    manifest_options: ManifestOptions,
}

enum RunKind {
    Prove,
    Keygen,
    Run,
}

impl KeygenCmd {
    pub fn run(self, toolchain: Option<String>) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        self.inner.run(toolchain, RunKind::Keygen)?;
        print_cargo_message(
            "Finished",
            format_args!("keygen in {:.2}s", start.elapsed().as_secs_f32()),
        );
        Ok(())
    }
}

impl RunCmd {
    pub fn run(self, toolchain: Option<String>) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        self.inner.run(toolchain, RunKind::Run)?;
        print_cargo_message(
            "Finished",
            format_args!("running elf in {:.2}s", start.elapsed().as_secs_f32()),
        );
        Ok(())
    }
}

impl ProveCmd {
    pub fn run(self, toolchain: Option<String>) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        self.inner.run(toolchain, RunKind::Prove)?;
        print_cargo_message(
            "Finished",
            format_args!(
                "running elf and proving in {:.2}s",
                start.elapsed().as_secs_f32()
            ),
        );
        Ok(())
    }
}

impl CmdInner {
    fn run(mut self, toolchain: Option<String>, kind: RunKind) -> anyhow::Result<()> {
        let manifest_path = match self.manifest_options.manifest_path.clone() {
            Some(path) => path,
            None => search_cargo_manifest_path(current_dir()?)?,
        };
        let target_selection = self
            .target_selection
            .canonicalize(manifest_path, &self.package_selection)?;

        // XXX: custom handling: set release mode from compilation_options
        self.ceno_options.release = self.compilation_options.release;

        let build = BuildCmd {
            cargo_options: self.cargo_options.clone(),
            package_selection: self.package_selection.clone(),
            target_selection: target_selection.clone(),
            feature_selection: self.feature_selection.clone(),
            compilation_options: self.compilation_options.clone(),
            manifest_options: self.manifest_options.clone(),
        };
        build.run(toolchain.clone())?;

        let target_elf = target_selection.get_target_path(&self.compilation_options);
        assert!(target_elf.exists(), "{}", target_elf.display());

        match kind {
            RunKind::Keygen => {
                self.ceno_options.keygen(target_elf)?;
            }
            RunKind::Run => {
                self.ceno_options.run(target_elf)?;
            }
            RunKind::Prove => {
                self.ceno_options.prove(target_elf)?;
            }
        }

        Ok(())
    }
}
