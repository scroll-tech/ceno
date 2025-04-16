use anyhow::bail;
use console::style;
use std::{
    backtrace::BacktraceStatus,
    fmt,
    fs::File,
    io,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};
use tempfile::TempDir;

/// Controls whether we should print the progress of the command.
pub static QUITE: OnceLock<bool> = OnceLock::new();

/// The rustc target triple name for ceno.
pub const RUSTC_TARGET: &str = "riscv32im-ceno-zkvm-elf";

/// Search for a `Cargo.toml` file in the given path and its parent directories.
pub fn search_cargo_manifest_path<P: AsRef<Path>>(path: P) -> anyhow::Result<PathBuf> {
    let path = path.as_ref();
    let mut path_buf = path.to_path_buf();
    loop {
        let cargo_manifest = path_buf.join("Cargo.toml");
        if cargo_manifest.try_exists()? {
            return Ok(cargo_manifest.canonicalize()?);
        }
        if !path_buf.pop() {
            break;
        }
    }
    bail!(
        "could not find `Cargo.toml` in `{}` or any parent directory",
        path.display()
    )
}

/// Get `RUSTFLAGS` env (if any) and append the base flags.
pub fn get_rust_flags() -> String {
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

    let mut rust_flags = std::env::var("RUSTFLAGS").unwrap_or_else(|_| String::new());
    if !rust_flags.is_empty() {
        rust_flags.push(' ');
    }
    rust_flags.push_str(&BASE_RUST_FLAGS.join(" "));
    rust_flags
}

/// Apply the build-std args to the cargo command.
pub fn apply_cargo_build_std_args(command: &mut Command) {
    const BASE_CARGO_ARGS: &[&str] = &[
        "-Z",
        "build-std=alloc,core,compiler_builtins,std,panic_abort,proc_macro",
        "-Z",
        "build-std-features=compiler-builtins-mem,panic_immediate_abort,default",
    ];
    command.args(BASE_CARGO_ARGS);
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

/// Print the entire command line to stderr.
pub fn print_cmdline(command: &Command) {
    if *QUITE.get_or_init(|| false) {
        return;
    }
    eprint!("{:>12} ", style("Running").green().bold());
    eprint!("{}", command.get_program().to_string_lossy());
    for arg in command.get_args() {
        eprint!(" {}", arg.to_string_lossy());
    }
    eprintln!();
}

/// Print the error message and backtrace (if any).
pub fn print_error(e: anyhow::Error) {
    for e in e.chain().rev() {
        eprintln!(
            "{}{} {}",
            style("error").red().bold(),
            style(":").white().bold(),
            e
        );
    }
    let bt = e.backtrace();
    if bt.status() == BacktraceStatus::Captured {
        eprintln!("error backtrace:");
        eprintln!("{bt}");
    }
}

/// Print cargo style message to stderr
pub fn print_cargo_message(status: &str, msg: fmt::Arguments) {
    if *QUITE.get_or_init(|| false) {
        return;
    }
    eprint!("{:>12} ", style(status).green().bold());
    eprintln!("{}", msg);
}

/// Parse the binary size from a string.
pub fn parse_size(s: &str) -> Result<u32, parse_size::Error> {
    parse_size::Config::new()
        .with_binary()
        .parse_size(s)
        .map(|size| size as u32)
}
