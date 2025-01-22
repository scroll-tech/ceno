// Test decompression of curve point. Assert result inside the guest
extern crate ceno_rt;
use ceno_rt::syscalls::syscall_secp256k1_decompress;

// Byte repr. of point P1 from https://docs.rs/secp/latest/secp/#arithmetic-1
const COMPRESSED: [u8; 33] = [
    2, 180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10, 64, 50,
    63, 8, 121, 191, 244, 141, 0, 37, 117, 182, 133,
];
const DECOMPRESSED: [u8; 64] = [
    180, 53, 9, 32, 85, 226, 220, 154, 20, 116, 218, 199, 119, 48, 44, 23, 45, 222, 10, 64, 50, 63,
    8, 121, 191, 244, 141, 0, 37, 117, 182, 133, 190, 160, 239, 131, 180, 166, 242, 145, 107, 249,
    24, 168, 27, 69, 86, 58, 86, 159, 10, 210, 164, 20, 152, 148, 67, 37, 222, 234, 108, 57, 84,
    148,
];

fn main() {
    let is_odd = match COMPRESSED[0] {
        2 => false,
        3 => true,
        _ => panic!("parity byte should be 2 or 3"),
    };

    // ignore parity byte, append 32 zero bytes for writing Y
    let mut compressed_with_space: [u8; 64] = [COMPRESSED[1..].to_vec(), vec![0; 32]]
        .concat()
        .try_into()
        .unwrap();

    syscall_secp256k1_decompress(&mut compressed_with_space, is_odd);
    assert_eq!(compressed_with_space, DECOMPRESSED);
}
