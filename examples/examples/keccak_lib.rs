//! Compute the Keccak(SHA-3) over a message and log the state.

extern crate ceno_rt;

use ceno_keccak::{Hasher, Keccak};

const MESSAGE: &[u8] = b"Hello, world!";

fn main() {
    let mut hasher = Keccak::v256();
    hasher.update(MESSAGE);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    log_digest(&output);
}

#[cfg(debug_assertions)]
fn log_digest(digest: &[u8; 32]) {
    use ceno_rt::info_out;
    info_out().write_frame(digest);
}

#[cfg(not(debug_assertions))]
fn log_digest(_state: &[u8; 32]) {}
