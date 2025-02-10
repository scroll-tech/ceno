// Test addition of two curve points. Assert result inside the guest
extern crate ceno_rt;
use ceno_rt::{
    info_out,
    syscalls::{syscall_bn254_add, syscall_bn254_double},
};
use std::slice;

use substrate_bn::{AffineG1, Fr, G1, Group};
fn bytes_to_words(bytes: [u8; 64]) -> [u32; 16] {
    let mut bytes = bytes;
    // Reverse the order of bytes for each coordinate
    bytes[0..32].reverse();
    bytes[32..].reverse();
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * (i + 1)].try_into().unwrap()))
}

fn g1_to_words(elem: G1) -> [u32; 16] {
    let elem = AffineG1::from_jacobian(elem).unwrap();
    let mut x_bytes = [0u8; 32];
    elem.x().to_big_endian(&mut x_bytes).unwrap();
    let mut y_bytes = [0u8; 32];
    elem.y().to_big_endian(&mut y_bytes).unwrap();

    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&x_bytes);
    bytes[32..].copy_from_slice(&y_bytes);

    bytes_to_words(bytes)
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

    let a = G1::one() * Fr::from_str("237").unwrap();
    let b = G1::one() * Fr::from_str("450").unwrap();
    let mut a = g1_to_words(a);
    let b = g1_to_words(b);

    log_state(&a);
    log_state(&b);

    syscall_bn254_add(&mut a, &b);

    assert_eq!(a, [
        3533671058, 384027398, 1667527989, 405931240, 1244739547, 3008185164, 3438692308,
        533547881, 4111479971, 1966599592, 1118334819, 3045025257, 3188923637, 1210932908,
        947531184, 656119894
    ]);
    log_state(&a);

    let c = G1::one() * Fr::from_str("343").unwrap();
    let mut c = g1_to_words(c);
    log_state(&c);

    syscall_bn254_double(&mut c);
    log_state(&c);

    let one = g1_to_words(G1::one());
    log_state(&one);

    syscall_bn254_add(&mut c, &one);
    log_state(&c);

    // 2 * 343 + 1 == 237 + 450, one hopes
    assert_eq!(a, c);
}
