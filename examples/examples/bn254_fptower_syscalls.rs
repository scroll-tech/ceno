extern crate ceno_rt;
use ceno_rt::{
    info_out,
    syscalls::{
        syscall_bn254_fp_addmod, syscall_bn254_fp_mulmod, syscall_bn254_fp2_addmod,
        syscall_bn254_fp2_mulmod,
    },
};
use rand::{SeedableRng, rngs::StdRng};
use std::slice;
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
    let log_flag = true;

    let log_state = |state: &[u32]| {
        if log_flag {
            let out = unsafe {
                slice::from_raw_parts(state.as_ptr() as *const u8, std::mem::size_of_val(state))
            };
            info_out().write_frame(out);
        }
    };

    let mut a = Fq::one();
    let mut b = Fq::one();
    let seed = [0u8; 32];
    let mut rng = StdRng::from_seed(seed);
    const RUNS: usize = 10;

    for _ in 0..RUNS {
        let mut a_words = fq_to_words(a);

        let a_backup = a_words;
        let b_words = fq_to_words(b);

        log_state(&a_words);
        log_state(&b_words);
        syscall_bn254_fp_addmod(&mut a_words[0], &b_words[0]);
        let sum_words = fq_to_words(a + b);
        assert_eq!(a_words, sum_words);
        log_state(&a_words);

        a_words.copy_from_slice(&a_backup);

        log_state(&a_words);
        log_state(&b_words);
        syscall_bn254_fp_mulmod(&mut a_words[0], &b_words[0]);
        let prod_words = fq_to_words(a * b);
        assert_eq!(a_words, prod_words);
        log_state(&a_words);

        a = Fq::random(&mut rng);
        b = Fq::random(&mut rng);
    }

    let mut a = Fq2::one();
    let mut b = Fq2::one();

    for _ in 0..RUNS {
        let mut a_words = fq2_to_words(a);
        let a_backup = a_words;
        let b_words = fq2_to_words(b);

        log_state(&a_words);
        log_state(&b_words);
        syscall_bn254_fp2_addmod(&mut a_words[0], &b_words[0]);
        let sum_words = fq2_to_words(a + b);
        assert_eq!(a_words, sum_words);
        log_state(&a_words);

        a_words.copy_from_slice(&a_backup);

        log_state(&a_words);
        log_state(&b_words);
        syscall_bn254_fp2_mulmod(&mut a_words[0], &b_words[0]);
        let prod_words = fq2_to_words(a * b);
        assert_eq!(a_words, prod_words);
        log_state(&a_words);

        a = Fq2::new(Fq::random(&mut rng), Fq::random(&mut rng));
        b = Fq2::new(Fq::random(&mut rng), Fq::random(&mut rng));
    }
}
