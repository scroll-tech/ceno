#[cfg(target_os = "zkvm")]
use core::arch::asm;

pub const KECCAK_PERMUTE: u32 = 0x00_01_01_09;

/// Based on https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/zkvm/entrypoint/src/syscalls/keccak_permute.rs
/// Executes the Keccak256 permutation on the given state.
///
/// ### Spec
///
/// - The caller must ensure that `state` is valid pointer to data that is aligned along a four
///   byte boundary.
#[allow(unused_variables)]
pub fn syscall_keccak_permute(state: &mut [u64; 25]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") KECCAK_PERMUTE,
            in("a0") state as *mut [u64; 25],
            in("a1") 0
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

pub const SECP256K1_ADD: u32 = 0x00_01_01_0A;
/// Based on https://github.com/succinctlabs/sp1/blob/dbe622aa4a6a33c88d76298c2a29a1d7ef7e90df/crates/zkvm/entrypoint/src/syscalls/secp256k1.rs
/// Adds two Secp256k1 points.
///
/// ### Spec
/// - The caller must ensure that `p` and `q` are valid pointers to data that is aligned along a four
///   byte boundary.
/// - Point representation: the first `8` words describe the X-coordinate, the last `8` describe the Y-coordinate. Each
///   coordinate is encoded as follows: its `32` bytes are ordered from lowest significance to highest and then stored into little endian words.
///   For example, the word `p[0]` contains the least significant `4` bytes of `X` and their significance is maintained w.r.t `p[0]`
/// - The caller must ensure that `p` and `q` are valid points on the `secp256k1` curve, and that `p` and `q` are not equal to each other.
/// - The result is stored in the first point.
#[allow(unused_variables)]
pub fn syscall_secp256k1_add(p: *mut [u32; 16], q: *mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") SECP256K1_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

pub const SECP256K1_DOUBLE: u32 = 0x00_00_01_0B;

/// Based on: https://github.com/succinctlabs/sp1/blob/dbe622aa4a6a33c88d76298c2a29a1d7ef7e90df/crates/zkvm/entrypoint/src/syscalls/secp256k1.rs
/// Double a Secp256k1 point.
///
/// ### Spec
/// - The caller must ensure that `p` is a valid pointer to data that is aligned along a four byte boundary.
/// - Point representation: the first `8` words describe the X-coordinate, the last `8` describe the Y-coordinate. Each
///   coordinate is encoded as follows: its `32` bytes are ordered from lowest significance to highest and then stored into little endian words.
///   For example, the word `p[0]` contains the least significant `4` bytes of `X` and their significance is maintained w.r.t `p[0]`
/// - The result is stored in p
#[allow(unused_variables)]
pub fn syscall_secp256k1_double(p: *mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") SECP256K1_DOUBLE,
            in("a0") p,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

pub const SECP256K1_DECOMPRESS: u32 = 0x00_00_01_0C;

/// Decompresses a compressed Secp256k1 point.
///
/// ### Spec
/// - The input array should be 64 bytes long, with the first 32 bytes containing the X coordinate in
///   big-endian format. Note that this byte ordering is different than the one implied in the spec
///   of the `add` and `double` operations
/// - The second half of the input will be overwritten with the Y coordinate of the
///   decompressed point in big-endian format using the point's parity (is_odd).
/// - The caller must ensure that `point` is valid pointer to data that is aligned along a four byte
///   boundary.
#[allow(unused_variables)]
pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool) {
    #[cfg(target_os = "zkvm")]
    {
        let p = point.as_mut_ptr();
        unsafe {
            asm!(
                "ecall",
                in("t0") SECP256K1_DECOMPRESS,
                in("a0") p,
                in("a1") is_odd as u8
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

pub const SHA_EXTEND: u32 = 0x00_30_01_05;
/// Based on: https://github.com/succinctlabs/sp1/blob/2aed8fea16a67a5b2983ffc471b2942c2f2512c8/crates/zkvm/entrypoint/src/syscalls/sha_extend.rs#L12
/// Executes the SHA256 extend operation on the given word array.
///
/// ### Safety
///
/// The caller must ensure that `w` is valid pointer to data that is aligned along a four byte
/// boundary.
#[allow(unused_variables)]
pub fn syscall_sha256_extend(w: *mut [u32; 64]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") SHA_EXTEND,
            in("a0") w,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
