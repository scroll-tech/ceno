use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EmulatorBackend {
    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        default
    )]
    Interp,
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
