use crate::utils::release_target_json;
use anyhow::Context;
use clap::Parser;
use std::{path::PathBuf, process::Command};
use tempfile::TempDir;

/// Options:
///       --message-format <FMT>     Error format
///   -v, --verbose...               Use verbose output (-vv very verbose/build.rs output)
///   -q, --quiet                    Do not print cargo log messages
///       --color <WHEN>             Coloring: auto, always, never
///       --config <KEY=VALUE|PATH>  Override a configuration value
///   -Z <FLAG>                      Unstable (nightly-only) flags to Cargo, see 'cargo -Z help' for details
#[derive(Clone, Parser)]
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

/// Feature Selection:
///   -F, --features <FEATURES>  Space or comma separated list of features to activate
///       --all-features         Activate all available features
///       --no-default-features  Do not activate the `default` feature
#[derive(Clone, Parser)]
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
#[derive(Clone, Parser)]
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
#[derive(Clone, Parser)]
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
    pub fn set_global(&self) {
        crate::utils::QUITE.set(self.quiet).expect("failed to set quiet flag, this is a bug");
        if let Some(color) = self.color.as_ref() {
            if color == "always" {
                console::set_colors_enabled(true);
            } else if color == "never" {
                console::set_colors_enabled(false);
            }
        }
    }

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

impl FeatureSelection {
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
