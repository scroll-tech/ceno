//! Direct registry-setup measurement.  This deliberately constructs no guest
//! execution or proof; it is the large-circuit setup gate's reproducible
//! symbolic-setup measurement harness.

use ceno_zkvm::{e2e::construct_configs, structs::ProgramParams};
use ff_ext::BabyBearExt4;
use rayon::ThreadPoolBuilder;
use std::{env, fs, time::Instant};
use tiny_keccak::{Hasher, Keccak};

fn requested_threads() -> usize {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--threads" {
            return args
                .next()
                .expect("--threads requires a value")
                .parse()
                .expect("--threads must be a positive integer");
        }
    }
    1
}

fn peak_rss_kib() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}

fn fingerprint(config: &ceno_zkvm::e2e::ConstraintSystemConfig<BabyBearExt4>) -> [u8; 32] {
    let mut hash = Keccak::v256();
    for (name, cs) in config.zkvm_cs.get_css() {
        hash.update(name.as_bytes());
        let artifact = bincode::serialize(cs).expect("registry circuit must serialize");
        hash.update(&artifact);
    }
    let mut output = [0; 32];
    hash.finalize(&mut output);
    output
}

fn main() {
    let threads = requested_threads();
    assert!(threads > 0, "--threads must be positive");
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        // Symbolic construction has deeply nested expression trees; use the
        // same generous stack budget for sequential and Rayon measurements.
        .stack_size(64 * 1024 * 1024)
        .build()
        .expect("failed to create setup Rayon pool");
    let start = Instant::now();
    // Keep construction, fingerprinting, and destruction on the enlarged
    // Rayon stack.  Production symbolic trees can overflow the main thread
    // while recursively dropping after a successful construction.
    let (circuits, fingerprint) = pool.install(|| {
        gkr_iop::setup_profile::reset();
        let config = construct_configs::<BabyBearExt4>(ProgramParams::default());
        let fingerprint = fingerprint(&config);
        (config.zkvm_cs.get_css().len(), fingerprint)
    });
    let elapsed = start.elapsed();
    let static_layer_build_ms = gkr_iop::setup_profile::static_layer_build_ns() / 1_000_000;
    let selector_monomialize_ms = gkr_iop::setup_profile::selector_monomialize_ns() / 1_000_000;
    let main_monomialize_ms = gkr_iop::setup_profile::main_monomialize_ns() / 1_000_000;
    let main_extract_ms = gkr_iop::setup_profile::main_monomial_extract_ns() / 1_000_000;
    let main_finalize_ms = gkr_iop::setup_profile::main_monomial_finalize_ns() / 1_000_000;
    let profile = if cfg!(feature = "llama-tiny") {
        "llama-tiny"
    } else {
        "production-width"
    };
    println!(
        "profile={profile} threads={threads} circuits={} setup_ms={} static_layer_build_ms={} selector_monomialize_ms={} main_monomialize_ms={} main_extract_ms={} main_finalize_ms={} peak_rss_kib={} fingerprint={}",
        circuits,
        elapsed.as_millis(),
        static_layer_build_ms,
        selector_monomialize_ms,
        main_monomialize_ms,
        main_extract_ms,
        main_finalize_ms,
        peak_rss_kib().unwrap_or_default(),
        hex(&fingerprint),
    );
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
