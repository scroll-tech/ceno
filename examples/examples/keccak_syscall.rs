//! Compute the Keccak permutation using a syscall.
//!
//! Iterate multiple times and log the state after each iteration.

extern crate ceno_rt;
use ceno_serde::from_slice;
use ceno_syscall::syscall_keccak_permute;

const DEFAULT_ITERATIONS: usize = 100;

fn main() {
    let iterations = iteration_hint();
    let mut state = [0_u64; 25];

    for i in 0..iterations {
        syscall_keccak_permute(&mut state);
        if i == 0 {
            log_state(&state);
        }
    }
}

fn iteration_hint() -> usize {
    let hint = ceno_rt::read_slice();
    if hint.is_empty() {
        return DEFAULT_ITERATIONS;
    }

    let iterations: u32 = from_slice(hint).expect("keccak_syscall iteration hint must be a u32");
    match iterations {
        0 => DEFAULT_ITERATIONS,
        iterations => iterations as usize,
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
