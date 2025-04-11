use console::style;
use std::{backtrace::BacktraceStatus, fs::File, io, io::Write, path::PathBuf, process::Command};
use std::sync::OnceLock;
use tempfile::TempDir;

pub static QUITE: OnceLock<bool> = OnceLock::new();

// /// Search for a `Cargo.toml` file in the given path and its parent directories.
// pub fn search_cargo_manifest_path<P: AsRef<Path>>(path: P) -> io::Result<Option<PathBuf>> {
//     let mut path = path.as_ref().to_path_buf();
//     loop {
//         let cargo_manifest = path.join("Cargo.toml");
//         if cargo_manifest.try_exists()? {
//             return Ok(Some(cargo_manifest.canonicalize()?))
//         }
//         if !path.pop() {
//             break;
//         }
//     }
//     Ok(None)
// }

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

pub fn print_error(e: anyhow::Error) {
    for e in e.chain().rev() {
        eprintln!(
            "{}{} {}",
            style("error").red().bold(),
            style(":").white().bold(),
            e.to_string()
        );
    }
    let bt = e.backtrace();
    if bt.status() == BacktraceStatus::Captured {
        eprintln!("error backtrace:");
        eprintln!("{bt}");
    }
}
