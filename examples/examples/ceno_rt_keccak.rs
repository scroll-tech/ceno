//! Compute the Keccak permutation using a syscall.
//!
//! Iterate multiple times and log the state after each iteration.

extern crate ceno_rt;
use ceno_rt::syscalls::syscall_keccak_permute;

const ITERATIONS: usize = 3;

fn main() {
    let mut state = [0_u64; 25];

    for _ in 0..ITERATIONS {
        syscall_keccak_permute(&mut state);
        log_state(&state);
    }
}

#[cfg(debug_assertions)]
fn log_state(state: &[u64; 25]) {
    use ceno_rt::debug_println;
    use core::fmt::Write;
    for (i, word) in state.iter().enumerate() {
        debug_println!("state[{:02}] = 0x{:016X}", i, word);
    }
}

#[cfg(not(debug_assertions))]
fn log_state(_state: &[u64; 25]) {}
