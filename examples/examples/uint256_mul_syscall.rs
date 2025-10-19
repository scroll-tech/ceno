extern crate ceno_rt;
use ceno_syscall::syscall_uint256_mul;

fn main() {
    let mut a_words: [u32; 8] = [
        0xF8EF7F4B, 0x16980341, 0x6044835, 0xD5CE47D3, 0xF33351FC, 0x74FCA157, 0xE35749FD,
        0x9418A94B,
    ];
    let b_and_modulus: [u32; 16] = [
        0xC8653C55, 0x9C14580B, 0xFFCFBEA7, 0xD04DA9F6, 0xF2F5282D, 0xA3DACD28, 0x51A162ED,
        0x0264BEB1, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF,
    ];

    syscall_uint256_mul(&mut a_words, &b_and_modulus);
    let expected: [u32; 8] = [
        0xF0D2F44F, 0xF0DC2116, 0x253AB7CD, 0x3089E8F6, 0x803BED8F, 0x969E7A64, 0x610CBFFF,
        0x80012A20,
    ];
    assert_eq!(a_words, expected);
}
