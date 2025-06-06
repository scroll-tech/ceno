//! Compute the Keccak permutation using a syscall.
//!
//! Iterate multiple times and log the state after each iteration.

extern crate ceno_rt;
use ceno_rt::syscalls::syscall_keccak_permute;

const ITERATIONS: usize = 4;

fn main() {
    let mut state = [0_u64; 25];

    for _ in 0..ITERATIONS {
        syscall_keccak_permute(&mut state);
        log_state(&state);
    }
}

#[cfg(debug_assertions)]
fn log_state(state: &[u64; 25]) {
    use ceno_rt::info_out;
    info_out().write_frame(unsafe {
        core::slice::from_raw_parts(state.as_ptr() as *const u8, state.len() * size_of::<u64>())
    });
}

#[cfg(not(debug_assertions))]
fn log_state(_state: &[u64; 25]) {}
