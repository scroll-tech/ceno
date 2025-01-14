use std::io::Write;

use ceno_host::CenoStdin;
use clap::{Parser, command};

// TODO(Matthias): consider unifying this with the version in ceno_zkvm.
// But it's so small, it's not urgent.
fn parse_size(s: &str) -> Result<u32, parse_size::Error> {
    parse_size::Config::new()
        .with_binary()
        .parse_size(s)
        .map(|size| size as u32)
}

/// Prepare hints for the quadratic sorting benchmark
///
/// Output on stdout in rkyv format, suitable for giving as a hints file to `e2e`.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Size of example, try eg 1k, 1M, 1G, or 1_023, or 17
    #[arg(long, value_parser = parse_size)]
    size: u32,
}

fn main() {
    std::io::stdout()
        .write_all(&Vec::<u8>::from(
            &*CenoStdin::default()
                .write(&Args::parse().size)
                .expect("writing hint failed"),
        ))
        .expect("writing hint to stdout failed");
}
