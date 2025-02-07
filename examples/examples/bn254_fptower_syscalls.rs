// Test addition of two curve points. Assert result inside the guest
extern crate ceno_rt;

use ceno_rt::syscalls::{
    syscall_bn254_fp_addmod, syscall_bn254_fp_mulmod, syscall_bn254_fp2_addmod,
    syscall_bn254_fp2_mulmod,
};
use substrate_bn::{Fq, Fq2};

fn bytes_to_words(bytes: [u8; 32]) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * (i + 1)].try_into().unwrap()))
}

fn fq_to_words(val: Fq) -> [u32; 8] {
    let mut bytes = [0u8; 32];
    val.to_big_endian(&mut bytes).unwrap();
    bytes.reverse();
    bytes_to_words(bytes)
}

fn fq2_to_words(val: Fq2) -> [u32; 16] {
    [fq_to_words(val.real()), fq_to_words(val.imaginary())]
        .concat()
        .try_into()
        .unwrap()
}

fn main() {
    let mut a = Fq::one();
    let mut b = Fq::one();

    for i in 0..50 {
        let mut a_words = fq_to_words(a);
        let a_backup = a_words.clone();
        let b_words = fq_to_words(b);

        syscall_bn254_fp_addmod(&mut a_words[0], &b_words[0]);
        let sum_words = fq_to_words(a + b);
        assert_eq!(a_words, sum_words);

        a_words.copy_from_slice(&a_backup);

        syscall_bn254_fp_mulmod(&mut a_words[0], &b_words[0]);
        let prod_words = fq_to_words(a * b);
        assert_eq!(a_words, prod_words);

        a = Fq::from_str("29").unwrap() * a + Fq::from_str("133000").unwrap();
        b = Fq::from_str("471").unwrap() * b + Fq::from_str("3045").unwrap();
    }

    let a_twist = Fq2::new(a, b);
    let b_twist = Fq2::new(b, a);

    let mut a = Fq2::one();
    let mut b = Fq2::one();

    for i in 0..50 {
        let mut a_words = fq2_to_words(a);
        let a_backup = a_words.clone();
        let b_words = fq2_to_words(b);

        syscall_bn254_fp2_addmod(&mut a_words[0], &b_words[0]);
        let sum_words = fq2_to_words(a + b);
        assert_eq!(a_words, sum_words);

        a_words.copy_from_slice(&a_backup);

        syscall_bn254_fp2_mulmod(&mut a_words[0], &b_words[0]);
        let prod_words = fq2_to_words(a * b);
        assert_eq!(a_words, prod_words);

        a = a * a_twist;
        b = b * b_twist;
    }
}
