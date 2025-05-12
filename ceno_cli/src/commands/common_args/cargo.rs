use crate::utils::{RUSTC_TARGET, release_target_json};
use anyhow::{Context, bail};
use cargo_metadata::{MetadataCommand, TargetKind};
use clap::Args;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

/// Options:
///       --message-format <FMT>     Error format
///   -v, --verbose...               Use verbose output (-vv very verbose/build.rs output)
///   -q, --quiet                    Do not print cargo log messages
///       --color <WHEN>             Coloring: auto, always, never
///       --config <KEY=VALUE|PATH>  Override a configuration value
///   -Z <FLAG>                      Unstable (nightly-only) flags to Cargo, see 'cargo -Z help' for details
#[derive(Clone, Args)]
pub struct CargoOptions {
    /// Error format
    #[arg(long)]
    pub message_format: Option<String>,
    /// Use verbose output (-vv very verbose/build.rs output)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Do not print cargo log messages
    #[arg(short, long)]
    pub quiet: bool,
    /// Coloring: auto, always, never
    #[arg(long)]
    pub color: Option<String>,
    /// Override a configuration value
    #[arg(long)]
    pub config: Option<Vec<String>>,
    /// Unstable (nightly-only) flags to Cargo, see 'cargo -Z help' for details
    #[arg(short = 'Z', action = clap::ArgAction::Append)]
    pub unstable_flags: Option<Vec<String>>,
}

/// Package Selection:
///   --package [<SPEC>]  Package with the target to run
#[derive(Clone, Args)]
pub struct PackageSelection {
    /// Package with the target to run
    #[arg(long)]
    pub package: Option<String>,
}

/// Target Selection:
///       --bin [<NAME>]      Name of the bin target to run
///       --example [<NAME>]  Name of the example target to run
#[derive(Clone, Args)]
pub struct TargetSelection {
    /// Name of the bin target to run
    #[arg(long, conflicts_with = "example")]
    pub bin: Option<String>,
    /// Name of the example target to run
    #[arg(long, conflicts_with = "bin")]
    pub example: Option<String>,
}

/// Feature Selection:
///   -F, --features <FEATURES>  Space or comma separated list of features to activate
///       --all-features         Activate all available features
///       --no-default-features  Do not activate the `default` feature
#[derive(Clone, Args)]
pub struct FeatureSelection {
    /// Space or comma separated list of features to activate
    #[arg(short = 'F', long)]
    pub features: Option<Vec<String>>,
    /// Activate all available features
    #[arg(long)]
    pub all_features: bool,
    /// Do not activate the `default` feature
    #[arg(long)]
    pub no_default_features: bool,
}

/// Compilation Options:
///   -j, --jobs <N>                Number of parallel jobs, defaults to # of CPUs.
///       --keep-going              Do not abort the build as soon as there is an error
///   -r, --release                 Build artifacts in release mode, with optimizations
///       --profile <PROFILE-NAME>  Build artifacts with the specified profile
///       --target [<TRIPLE>]       Build for the target triple
///       --target-dir <DIRECTORY>  Directory for all generated artifacts
#[derive(Clone, Args)]
pub struct CompilationOptions {
    /// Number of parallel jobs, defaults to # of CPUs.
    #[arg(short, long)]
    pub jobs: Option<u32>,
    /// Do not abort the build as soon as there is an error
    #[arg(long)]
    pub keep_going: bool,
    /// Build artifacts in release mode, with optimizations
    #[arg(short, long)]
    pub release: bool,
    /// Build artifacts with the specified profile
    #[arg(long)]
    pub profile: Option<String>,
    /// Build for the target triple
    #[arg(long)]
    pub target: Option<String>,
    /// Directory for all generated artifacts
    #[arg(long)]
    pub target_dir: Option<PathBuf>,
}

/// Manifest Options:
///       --manifest-path <PATH>  Path to Cargo.toml
///       --lockfile-path <PATH>  Path to Cargo.lock (unstable)
///       --ignore-rust-version   Ignore `rust-version` specification in packages
///       --locked                Assert that `Cargo.lock` will remain unchanged
///       --offline               Run without accessing the network
///       --frozen                Equivalent to specifying both --locked and --offline
#[derive(Clone, Args)]
pub struct ManifestOptions {
    /// Path to Cargo.toml
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,
    /// Path to Cargo.lock (unstable)
    #[arg(long)]
    pub lockfile_path: Option<String>,
    /// Ignore `rust-version` specification in packages
    #[arg(long)]
    pub ignore_rust_version: bool,
    /// Assert that `Cargo.lock` will remain unchanged
    #[arg(long)]
    pub locked: bool,
    /// Run without accessing the network
    #[arg(long)]
    pub offline: bool,
    /// Equivalent to specifying both --locked and --offline
    #[arg(long)]
    pub frozen: bool,
}

impl CargoOptions {
    /// Set the global options based on the command line arguments.
    pub fn set_global(&self) {
        crate::utils::QUITE
            .set(self.quiet)
            .expect("failed to set quiet flag, this is a bug");
        if let Some(color) = self.color.as_ref() {
            if color == "always" {
                console::set_colors_enabled(true);
            } else if color == "never" {
                console::set_colors_enabled(false);
            }
        }
    }

    /// Apply the args to the cargo command.
    pub fn apply_to(&self, command: &mut Command) {
        if let Some(message_format) = self.message_format.as_ref() {
            command.arg("--message-format").arg(message_format);
        }
        if self.verbose > 0 {
            command.arg(format!("-{}", "v".repeat(self.verbose as usize)));
        }
        if self.quiet {
            command.arg("--quiet");
        }
        if let Some(color) = self.color.as_ref() {
            command.arg("--color").arg(color);
        }
        if let Some(config) = self.config.as_ref() {
            for item in config {
                command.arg("--config").arg(item);
            }
        }
        if let Some(unstable_flags) = self.unstable_flags.as_ref() {
            for flag in unstable_flags {
                command.arg("-Z").arg(flag);
            }
        }
    }
}

impl PackageSelection {
    /// Apply the args to the cargo command.
    pub fn apply_to(&self, command: &mut Command) {
        if let Some(package) = self.package.as_ref() {
            command.arg("--package").arg(package);
        }
    }
}

impl TargetSelection {
    /// Check if any target is set.
    pub fn is_set(&self) -> bool {
        self.bin.is_some() || self.example.is_some()
    }

    /// Apply the args to the cargo command.
    pub fn apply_to(&self, command: &mut Command) {
        if let Some(bin) = self.bin.as_ref() {
            command.arg("--bin").arg(bin);
        } else if let Some(example) = self.example.as_ref() {
            command.arg("--example").arg(example);
        }
    }

    /// Get the target path for a target.
    ///
    /// # Panics
    ///
    /// Panics if neither `bin` nor `example` is set.
    pub fn get_target_path(&self, compilation_options: &CompilationOptions) -> PathBuf {
        let prefix = compilation_options
            .target_dir
            .as_deref()
            .unwrap_or_else(|| Path::new("target"))
            .join(RUSTC_TARGET)
            .join(compilation_options.get_profile());
        if let Some(bin) = self.bin.as_ref() {
            prefix.join(bin)
        } else if let Some(example) = self.example.as_ref() {
            prefix.join("examples").join(example)
        } else {
            panic!("target need to be set");
        }
    }

    pub fn canonicalize<P: Into<PathBuf>>(
        self,
        manifest_path: P,
        package_selection: &PackageSelection,
    ) -> anyhow::Result<TargetSelection> {
        if self.is_set() {
            return Ok(self);
        }

        let metadata = MetadataCommand::new()
            .manifest_path(manifest_path)
            .no_deps()
            .exec()?;
        let mut packages = vec![];
        if let Some(package) = package_selection.package.as_ref() {
            packages.push(
                metadata
                    .packages
                    .iter()
                    .find(|p| p.name == *package)
                    .context(format!("package `{package}` not found",))?,
            );
        } else {
            packages.extend(metadata.packages.iter());
        }

        let mut binary_targets = vec![];
        for package in packages {
            if let Some(default_run) = package.default_run.as_ref() {
                binary_targets.push((true, default_run));
                continue;
            }
            binary_targets.extend(package.targets.iter().filter_map(|target| {
                let is_bin = target
                    .kind
                    .iter()
                    .any(|kind| matches!(kind, TargetKind::Bin));
                let is_example = target
                    .kind
                    .iter()
                    .any(|kind| matches!(kind, TargetKind::Example));

                if is_example {
                    Some((true, &target.name))
                } else if is_bin {
                    Some((false, &target.name))
                } else {
                    None
                }
            }));
        }

        if binary_targets.len() > 1 {
            bail!("multiple binaries found, please specify one with `--bin` or `--example`")
        }

        let (is_example, name) = binary_targets.pop().unwrap();

        Ok(if is_example {
            TargetSelection {
                bin: None,
                example: Some(name.to_string()),
            }
        } else {
            TargetSelection {
                bin: Some(name.to_string()),
                example: None,
            }
        })
    }
}

impl FeatureSelection {
    /// Apply the args to the cargo command.
    pub fn apply_to(&self, command: &mut Command) {
        if let Some(features) = self.features.as_ref() {
            command.arg("--features").arg(features.join(","));
        }
        if self.all_features {
            command.arg("--all-features");
        }
        if self.no_default_features {
            command.arg("--no-default-features");
        }
    }
}

impl CompilationOptions {
    /// Get the target profile
    pub fn get_profile(&self) -> &str {
        if self.release {
            "release"
        } else {
            self.profile.as_deref().unwrap_or("debug")
        }
    }

    /// Apply the args to the cargo command.
    pub fn apply_to(&self, command: &mut Command) -> anyhow::Result<Option<TempDir>> {
        if let Some(jobs) = self.jobs {
            command.arg("--jobs").arg(jobs.to_string());
        }
        if self.keep_going {
            command.arg("--keep-going");
        }
        if self.release {
            command.arg("--release");
        }
        if let Some(profile) = self.profile.as_ref() {
            command.arg("--profile").arg(profile);
        }
        if let Some(target) = self.target.as_ref() {
            command.arg("--target").arg(target);
        } else {
            let (guard, target_json_path) =
                release_target_json().context("failed to release target definition")?;
            command.arg("--target").arg(&target_json_path);
            return Ok(Some(guard));
        }

        Ok(None)
    }
}

impl ManifestOptions {
    /// Apply the args to the cargo command.
    pub fn apply_to(&self, command: &mut Command) -> anyhow::Result<()> {
        if let Some(manifest_path) = self.manifest_path.as_ref() {
            command.arg("--manifest-path").arg(manifest_path);
        }
        if let Some(lockfile_path) = self.lockfile_path.as_ref() {
            command.arg("--lockfile").arg(lockfile_path);
        }
        if self.ignore_rust_version {
            command.arg("--ignore-rust-version");
        }
        if self.locked {
            command.arg("--locked");
        }
        if self.offline {
            command.arg("--offline");
        }
        if self.frozen {
            command.arg("--frozen");
        }

        Ok(())
    }
}
