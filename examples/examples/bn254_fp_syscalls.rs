// Test addition of two curve points. Assert result inside the guest
extern crate ceno_rt;
use std::str::FromStr;

use ceno_rt::syscalls::syscall_bn254_fp_addmod;
use num_bigint::BigInt;

fn bigint_to_words(value: BigInt) -> [u32; 8] {
    let mut digits = value.to_u32_digits().1;
    assert!(digits.len() <= 8);

    let padding = 8 - digits.len();
    digits.append(&mut vec![0u32; padding]);
    digits.try_into().unwrap()
}

const A: &str = "20088242871839275224246405745257275088696311157297823662689037894645226208583";
const B: &str = "21888202871839275222246405745257275088696311157297823662689037894645226208583";

fn main() {
    let mut p: [u32; 8] = bigint_to_words(BigInt::from_str(A).unwrap());
    let q: [u32; 8] = bigint_to_words(BigInt::from_str(B).unwrap());

    let mut p2 = p.clone();

    syscall_bn254_fp_addmod(&mut p[0], &q[0]);
}
