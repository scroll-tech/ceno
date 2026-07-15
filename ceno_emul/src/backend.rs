use anyhow::{Result, bail};

/// Selects the implementation used for top-level emulator preflight execution.
///
/// With `aot-x86_64` enabled on Linux x86_64, AOT is the default because the
/// preflight path does not need exact `FullTracer` step records. Other builds
/// default to the interpreter. `CENO_EMULATOR_BACKEND` remains an explicit
/// override for benchmarks, debugging, and parity checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EmulatorBackend {
    /// Original instruction-by-instruction Rust interpreter.
    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        default
    )]
    Interp,
    /// Native x86_64 code generated from statically reachable RISC-V blocks,
    /// with fallback to the interpreter for unsupported or unsafe cases.
    #[cfg_attr(
        all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"),
        default
    )]
    Aot,
}

impl EmulatorBackend {
    pub fn from_env() -> Result<Self> {
        match std::env::var("CENO_EMULATOR_BACKEND") {
            Ok(value) if value.eq_ignore_ascii_case("interp") => Ok(Self::Interp),
            Ok(value) if value.eq_ignore_ascii_case("aot") => Ok(Self::Aot),
            Ok(value) => {
                bail!("unsupported CENO_EMULATOR_BACKEND={value:?}; expected \"interp\" or \"aot\"")
            }
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(err) => bail!("could not read CENO_EMULATOR_BACKEND: {err}"),
        }
    }
}
