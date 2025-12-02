use crate::{commands::*, utils::*};
use anyhow::Context;
#[cfg(all(feature = "jemalloc", unix, not(test)))]
use ceno_zkvm::print_allocated_bytes;
use clap::{Args, Parser, Subcommand};

mod commands;
mod sdk;
mod utils;

// Use jemalloc as global allocator for performance
#[cfg(all(feature = "jemalloc", unix, not(test)))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const CENO_VERSION: &str = env!("CENO_VERSION");

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
enum Cargo {
    #[command(name = "ceno")]
    Ceno(VmCli),
}

#[derive(Args)]
#[command(
    author,
    about,
    long_about = None,
    version = CENO_VERSION
)]
struct VmCli {
    toolchain: Option<String>,
    #[clap(subcommand)]
    command: VmCliCommands,
}

#[derive(Subcommand)]
pub enum VmCliCommands {
    // Bench(BenchCmd),
    Build(BuildCmd),
    Keygen(KeygenCmd),
    Prove(ProveCmd),
    Run(RunCmd),
    RawKeygen(RawKeygenCmd),
    RawProve(RawProveCmd),
    RawRun(RawRunCmd),
    // Setup(EvmProvingSetupCmd),
    Verify(VerifyCmd),

    Info(InfoCmd),
}

fn main() {
    let Cargo::Ceno(args) = Cargo::parse();
    let mut toolchain = args.toolchain;
    if let Some(toolchain) = toolchain.as_mut() {
        if !toolchain.starts_with("+") {
            print_error(anyhow::anyhow!("invalid toolchain selector: {toolchain}"));
            std::process::exit(1);
        }
        *toolchain = toolchain.strip_prefix("+").unwrap().to_string();
    }

    let command = args.command;
    let result = match command {
        // VmCliCommands::Bench(cmd) => cmd.run(),
        VmCliCommands::Build(cmd) => cmd
            .run(toolchain)
            .context("could not build ceno program due to previous error"),
        VmCliCommands::Prove(cmd) => cmd
            .run(toolchain)
            .context("could not run and prove ceno program due to previous error"),
        VmCliCommands::Run(cmd) => cmd
            .run(toolchain)
            .context("could not run ceno program due to previous error"),
        VmCliCommands::Keygen(cmd) => cmd
            .run(toolchain)
            .context("could not run ceno program due to previous error"),
        VmCliCommands::RawKeygen(cmd) => cmd
            .run()
            .context("could not generate vk for given elf due to previous error"),
        VmCliCommands::RawProve(cmd) => cmd
            .run()
            .context("could not run and prove given elf due to previous error"),
        VmCliCommands::RawRun(cmd) => cmd
            .run()
            .context("could not run given elf due to previous error"),
        // VmCliCommands::Setup(cmd) => cmd.run().await,
        VmCliCommands::Verify(cmd) => cmd.run(),
        VmCliCommands::Info(cmd) => cmd.run(),
    };
    if let Err(e) = result {
        print_error(e);
        std::process::exit(1);
    }
    #[cfg(all(feature = "jemalloc", unix, not(test)))]
    {
        print_allocated_bytes();
    }
}
