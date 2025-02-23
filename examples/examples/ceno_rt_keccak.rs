//! Compute the Keccak permutation using a syscall.
//!
//! Iterate multiple times and log the state after each iteration.

extern crate ceno_rt;
use ceno_rt::{info_out, syscalls::syscall_keccak_permute};
use core::slice;

const ITERATIONS: usize = 3;

fn main() {
    let mut state = [0_u64; 25];

    for _ in 0..ITERATIONS {
        syscall_keccak_permute(&mut state);
        log_state(&state);
    }
}

fn log_state(state: &[u64; 25]) {
    let out = unsafe {
        slice::from_raw_parts(state.as_ptr() as *const u8, state.len() * size_of::<u64>())
    };
    info_out().write_frame(out);
}
