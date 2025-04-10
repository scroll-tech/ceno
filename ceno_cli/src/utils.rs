use std::backtrace::BacktraceStatus;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use console::style;
use tempfile::{TempDir};

/// Search for a `Cargo.toml` file in the given path and its parent directories.
pub fn search_cargo_manifest_path<P: AsRef<Path>>(path: P) -> io::Result<Option<PathBuf>> {
    let mut path = path.as_ref().to_path_buf();
    loop {
        let cargo_manifest = path.join("Cargo.toml");
        if cargo_manifest.try_exists()? {
            return Ok(Some(cargo_manifest.canonicalize()?))
        }
        if !path.pop() {
            break;
        }
    }
    Ok(None)
}


/// Release the target definition json into a temp file.
pub fn release_target_json() -> io::Result<(TempDir, PathBuf)> {
    const TARGET_DEFINITION: &[u8] = include_bytes!("../../ceno_rt/riscv32im-ceno-zkvm-elf.json");
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("riscv32im-ceno-zkvm-elf.json");
    let mut target_json_file = File::create(&path)?;
    target_json_file.write_all(TARGET_DEFINITION)?;
    Ok((temp_dir, path))
}

// pub fn cargo_like_eprintln<S: AsRef<str>>(
//     status: S,
//     msg: &str,
// ){
//     eprint!("{:<12}", style(status).green().bold())
// }

pub fn print_cmdline(cmd: &Command) {
    eprint!("{:>12} ", style("Running").green().bold());
    eprint!("{}", cmd.get_program().to_string_lossy());
    for arg in cmd.get_args() {
        eprint!(" {}", arg.to_string_lossy());
    }
    eprintln!();
}

pub fn print_error(e: anyhow::Error) {
    for e in e.chain().rev() {
        eprintln!("{}{} {}", style("error").red().bold(), style(":").white().bold(), e.to_string());
    }
    let bt = e.backtrace();
    if bt.status() == BacktraceStatus::Captured {
        eprintln!("error backtrace:");
        eprintln!("{bt}");
    }
}
