//! Compute the Keccak permutation using a syscall.
//!
//! Iterate multiple times and log the state after each iteration.

#![no_main]
#![no_std]
extern crate ceno_rt;
use ceno_rt::{info_out, syscall_keccak_permute};
use core::{ptr::read_volatile, slice};

const ITERATIONS: usize = 3;

ceno_rt::entry!(main);
fn main() {
    let mut state = [0_u64; 25];

    for _ in 0..ITERATIONS {
        syscall_keccak_permute(&mut state);
        log_state(&state);
    }
}

fn log_state(state: &[u64; 25]) {
    let out = unsafe {
        slice::from_raw_parts_mut(state.as_ptr() as *mut u8, state.len() * size_of::<u64>())
    };
    info_out().write_frame(out);
}
