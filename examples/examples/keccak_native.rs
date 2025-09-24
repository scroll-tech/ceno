//! Compute the Keccak-256 using alloy-primitives with native-keccak hook.

extern crate ceno_rt;

use alloy_primitives::keccak256;

const MESSAGE: &[u8] = b"Hello, world!";

fn main() {
    let output = keccak256(MESSAGE);
    log_digest(&output);
}

#[cfg(debug_assertions)]
fn log_digest(digest: &[u8; 32]) {
    use ceno_rt::info_out;
    info_out().write_frame(digest);
}

#[cfg(not(debug_assertions))]
fn log_digest(_state: &[u8; 32]) {}
