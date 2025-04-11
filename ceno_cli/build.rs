use std::{env, fmt::Write};
use vergen_git2::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = BuildBuilder::default().build_timestamp(true).build()?;
    let git2 = Git2Builder::default().sha(true).dirty(true).build()?;
    let rustc = RustcBuilder::default()
        .channel(true)
        .commit_date(true)
        .build()?;

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&git2)?
        .add_instructions(&rustc)?
        .emit_and_set()?;

    let mut ceno_version = String::from(env!("CARGO_PKG_VERSION"));
    write!(ceno_version, " ({}", env::var("VERGEN_GIT_SHA")?)?;
    if env::var("VERGEN_GIT_DIRTY")? == "true" {
        write!(ceno_version, "-dirty")?;
    }
    writeln!(
        ceno_version,
        " rustc-{}-{} {})",
        env::var("VERGEN_RUSTC_CHANNEL")?,
        env::var("VERGEN_RUSTC_COMMIT_DATE")?,
        env::var("VERGEN_BUILD_TIMESTAMP")?
    )?;
    println!("cargo:rustc-env=CENO_VERSION={}", ceno_version);
    Ok(())
}
