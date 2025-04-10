use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use crate::commands::*;
use crate::utils::print_error;

mod commands;
mod utils;

pub const CENO_VERSION: &str = env!("CENO_VERSION");

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    #[command(name = "ceno")]
    Ceno(VmCli),
}

#[derive(Args)]
#[command(
    author,
    about,
    long_about = None,
    args_conflicts_with_subcommands = true,
    version = CENO_VERSION
)]
pub struct VmCli {
    #[clap(subcommand)]
    pub command: VmCliCommands,
}

#[derive(Subcommand)]
pub enum VmCliCommands {
    // Bench(BenchCmd),
    Build(BuildCmd),
    // Keygen(KeygenCmd),
    // Prove(ProveCmd),
    // Run(RunCmd),
    // Setup(EvmProvingSetupCmd),
    // Verify(VerifyCmd),
}

fn main() {
    let Cargo::Ceno(args) = Cargo::parse();
    let command = args.command;
    let result = match command {
        // VmCliCommands::Bench(cmd) => cmd.run(),
        VmCliCommands::Build(cmd) => cmd.run().context("could not build ceno program due to previous error"),
        // VmCliCommands::Run(cmd) => cmd.run(),
        // VmCliCommands::Keygen(cmd) => cmd.run(),
        // VmCliCommands::Prove(cmd) => cmd.run(),
        // VmCliCommands::Setup(cmd) => cmd.run().await,
        // VmCliCommands::Verify(cmd) => cmd.run(),
    };
    if let Err(e) = result {
        print_error(e);
        std::process::exit(1);
    }
}
