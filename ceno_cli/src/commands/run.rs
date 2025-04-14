use crate::{
    commands::{BuildCmd, common_args::*},
    utils::*,
};
use anyhow::{Context, bail};
use cargo_metadata::{MetadataCommand, TargetKind};
use clap::{Args, Parser};
use std::env::current_dir;
use std::path::Path;
use crate::commands::helpers::*;

#[derive(Parser)]
#[command(name = "run", about = "Run an Ceno program")]
pub struct RunCmd {
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

impl RunCmd {
    pub fn run(self, toolchain: Option<String>) -> anyhow::Result<()> {
        // let manifest_path = match self.manifest_options.manifest_path.clone() {
        //     Some(path) => path,
        //     None => search_cargo_manifest_path(current_dir()?)?,
        // };
        //
        // let metadata = MetadataCommand::new()
        //     .manifest_path(manifest_path)
        //     .no_deps()
        //     .exec()?;
        // let target_selection = if !self.target_selection.is_set() {
        //     let mut packages = vec![];
        //     if let Some(package) = self.package_selection.package.as_ref() {
        //         packages.push(
        //             metadata
        //                 .packages
        //                 .iter()
        //                 .find(|p| p.name == *package)
        //                 .context(format!("package `{package}` not found",))?,
        //         );
        //     } else {
        //         packages.extend(metadata.packages.iter());
        //     }
        //
        //     let mut binary_targets = vec![];
        //     for package in packages {
        //         if let Some(default_run) = package.default_run.as_ref() {
        //             binary_targets.push((true, default_run));
        //             continue;
        //         }
        //         binary_targets.extend(package.targets.iter().filter_map(|target| {
        //             let is_bin = target
        //                 .kind
        //                 .iter()
        //                 .any(|kind| matches!(kind, TargetKind::Bin));
        //             let is_example = target
        //                 .kind
        //                 .iter()
        //                 .any(|kind| matches!(kind, TargetKind::Example));
        //
        //             if is_example {
        //                 Some((true, &target.name))
        //             } else if is_bin {
        //                 Some((false, &target.name))
        //             } else {
        //                 None
        //             }
        //         }));
        //     }
        //
        //     if binary_targets.len() > 1 {
        //         bail!("multiple binaries found, please specify one with `--bin` or `--example`")
        //     }
        //
        //     let (is_example, name) = binary_targets.pop().unwrap();
        //     if is_example {
        //         TargetSelection {
        //             bin: None,
        //             example: Some(name.to_string()),
        //         }
        //     } else {
        //         TargetSelection {
        //             bin: Some(name.to_string()),
        //             example: None,
        //         }
        //     }
        // } else {
        //     self.target_selection
        // };
        //
        // let build = BuildCmd {
        //     cargo_options: self.cargo_options.clone(),
        //     package_selection: self.package_selection.clone(),
        //     target_selection: target_selection.clone(),
        //     feature_selection: self.feature_selection.clone(),
        //     compilation_options: self.compilation_options.clone(),
        //     manifest_options: self.manifest_options.clone(),
        // };
        // build.run(toolchain.clone())?;
        //
        // let target_elf = target_selection.get_target_path(&self.compilation_options);
        // assert!(target_elf.exists());
        let target_elf = Path::new("/Users/hhq/workspace/ceno/examples/target/riscv32im-ceno-zkvm-elf/release/examples/ceno_rt_io");

        let (zkvm_proof, vk) = run_elf(&self.ceno_options, &target_elf)?;

        Ok(())
    }
}
