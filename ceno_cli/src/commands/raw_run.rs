use crate::commands::common_args::*;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "keygen", about = "Generate vk for an elf file")]
pub struct RawKeygenCmd {
    /// Path to the Ceno elf file
    elf: PathBuf,
    #[clap(flatten, next_help_heading = "Ceno Options")]
    ceno_options: CenoOptions,
}

impl RawKeygenCmd {
    pub fn run(self) -> anyhow::Result<()> {
        self.ceno_options.try_setup_logger();
        self.ceno_options.keygen(self.elf)
    }
}

#[derive(Parser)]
#[command(name = "run", about = "Run an elf file")]
pub struct RawRunCmd {
    /// Path to the Ceno elf file
    elf: PathBuf,
    #[clap(flatten, next_help_heading = "Ceno Options")]
    ceno_options: CenoOptions,
}

impl RawRunCmd {
    pub fn run(self) -> anyhow::Result<()> {
        self.ceno_options.try_setup_logger();
        self.ceno_options.run(self.elf)
    }
}

#[derive(Parser)]
#[command(name = "run", about = "Run and prove an elf file")]
pub struct RawProveCmd {
    /// Path to the Ceno elf file
    elf: PathBuf,
    #[clap(flatten, next_help_heading = "Ceno Options")]
    ceno_options: CenoOptions,
}

impl RawProveCmd {
    pub fn run(self) -> anyhow::Result<()> {
        self.ceno_options.try_setup_logger();
        self.ceno_options.prove(self.elf)
    }
}
