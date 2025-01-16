// Test addition of two curve points. Assert result inside the guest
extern crate ceno_rt;
use ceno_rt::syscalls::secp256k1_double;

// Byte repr. of points from https://docs.rs/secp/latest/secp/#arithmetic-1
const P: [u8; 65] = [
    4, 180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10, 64, 50,
    63, 8, 121, 191, 244, 141, 0, 37, 117, 182, 133, 190, 160, 239, 131, 180, 166, 242, 145, 107,
    249, 24, 168, 27, 69, 86, 58, 86, 159, 10, 210, 164, 20, 152, 148, 67, 37, 222, 234, 108, 57,
    84, 148,
];

const DOUBLE_P: [u8; 65] = [
    4, 111, 137, 182, 244, 228, 50, 13, 91, 93, 34, 231, 93, 191, 248, 105, 28, 226, 251, 23, 66,
    192, 188, 66, 140, 44, 218, 130, 239, 101, 255, 164, 76, 202, 170, 134, 48, 127, 46, 14, 9,
    192, 64, 102, 67, 163, 33, 48, 157, 140, 217, 10, 97, 231, 183, 28, 129, 177, 185, 253, 179,
    135, 182, 253, 203,
];

type DecompressedPoint = [u32; 16];

// interpret bytes for our internal interface [u32; 16]
fn from_bytes(bytes: [u8; 65]) -> DecompressedPoint {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[1..][4 * i..4 * (i + 1)].try_into().unwrap()))
}

fn main() {
    let mut p: DecompressedPoint = from_bytes(P);
    let double_p: DecompressedPoint = from_bytes(DOUBLE_P);

    secp256k1_double(&mut p);
    assert_eq!(p, double_p);
}
