// Test addition of two curve points. Assert result inside the guest
extern crate ceno_rt;
use ceno_rt::syscalls::syscall_secp256k1_add;

// Byte repr. of points from https://docs.rs/secp/latest/secp/#arithmetic-1
const P: [u8; 65] = [
    4, 180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10, 64, 50,
    63, 8, 121, 191, 244, 141, 0, 37, 117, 182, 133, 190, 160, 239, 131, 180, 166, 242, 145, 107,
    249, 24, 168, 27, 69, 86, 58, 86, 159, 10, 210, 164, 20, 152, 148, 67, 37, 222, 234, 108, 57,
    84, 148,
];
const Q: [u8; 65] = [
    4, 117, 102, 61, 142, 169, 5, 99, 112, 146, 4, 241, 177, 255, 72, 34, 34, 12, 251, 37, 126,
    213, 96, 38, 9, 40, 35, 20, 186, 78, 125, 73, 44, 215, 29, 243, 127, 197, 147, 216, 206, 110,
    116, 63, 96, 72, 143, 182, 205, 11, 234, 96, 127, 206, 19, 1, 103, 103, 219, 255, 25, 229, 210,
    4, 141,
];
const P_PLUS_Q: [u8; 65] = [
    4, 188, 11, 115, 232, 35, 63, 79, 186, 163, 11, 207, 165, 64, 247, 109, 81, 125, 56, 83, 131,
    221, 140, 154, 19, 186, 109, 173, 9, 127, 142, 169, 219, 108, 17, 216, 218, 125, 37, 30, 87,
    86, 194, 151, 20, 122, 64, 118, 123, 210, 29, 60, 209, 138, 131, 11, 247, 157, 212, 209, 123,
    162, 111, 197, 70,
];

type DecompressedPoint = [u32; 16];

/// `bytes` is expected to contain the uncompressed representation of
/// a curve point, as described in https://docs.rs/secp/latest/secp/struct.Point.html
///
/// The return value is an array of words compatible with the sp1 syscall for `add` and `double`
/// Notably, these words should encode the X and Y coordinates of the point
/// in "little endian" and not "big endian" as is the case of secp
fn bytes_to_words(bytes: [u8; 65]) -> [u32; 16] {
    // ignore the tag byte (specific to the secp repr.)
    let mut bytes: [u8; 64] = bytes[1..].try_into().unwrap();

    // Reverse the order of bytes for each coordinate
    bytes[0..32].reverse();
    bytes[32..].reverse();
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * (i + 1)].try_into().unwrap()))
}
fn main() {
    let mut p: DecompressedPoint = bytes_to_words(P);
    let mut q: DecompressedPoint = bytes_to_words(Q);
    let p_plus_q: DecompressedPoint = bytes_to_words(P_PLUS_Q);

    syscall_secp256k1_add(&mut p, &mut q);
    assert_eq!(p, p_plus_q);
}
