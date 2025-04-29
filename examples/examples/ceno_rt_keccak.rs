//! Compute the Keccak permutation using a syscall.
//!
//! Iterate multiple times and log the state after each iteration.

extern crate ceno_rt;
use ceno_rt::{debug_println, syscalls::syscall_keccak_permute};
use core::fmt::Write;

const ITERATIONS: usize = 3;

fn main() {
    let mut state = [0_u64; 25];

    for _ in 0..ITERATIONS {
        syscall_keccak_permute(&mut state);
        log_state(&state);
    }
}

fn log_state(state: &[u64; 25]) {
    for (i, word) in state.iter().enumerate() {
        debug_println!("state[{:02}] = 0x{:016X}", i, word);
    }
}
