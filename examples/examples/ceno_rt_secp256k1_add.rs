//! Compute the Keccak permutation using a syscall.
//!
//! Iterate multiple times and log the state after each iteration.

extern crate ceno_rt;
use ceno_rt::syscalls::secp256k1_add;

// Example from https://docs.rs/secp/latest/secp/#arithmetic-1
const P: &str = "02b435092055e2dc9a1474dac777302c172dde0a40323f0879bff48d002575b685";
const Q: &str = "0375663d8ea90563709204f1b1ff4822220cfb257ed5602609282314ba4e7d492c";
const P_PLUS_Q: &str = "02bc0b73e8233f4fbaa30bcfa540f76d517d385383dd8c9a13ba6dad097f8ea9db";

fn load_hex(hex: &str, arr: &mut [u8; 33]) {
    assert!(hex.len() == 66);
    for i in 0..33usize {
        arr[i] = u8::from_str_radix(&hex[2 * i..2 * (i + 1)], 16).unwrap();
    }
}

fn main() {
    let mut p = [0_u8; 33];
    let mut q = [0_u8; 33];
    let mut p_plus_q = [0_u8; 33];

    load_hex(P, &mut p);
    load_hex(Q, &mut q);
    load_hex(P_PLUS_Q, &mut p_plus_q);

    secp256k1_add(&mut p, &mut q);
    // assert_eq!(p, p_plus_q);
    // assert_eq!(1, 2);
}
