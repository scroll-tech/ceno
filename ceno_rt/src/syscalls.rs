// Based on https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/zkvm/entrypoint/src/syscalls/keccak_permute.rs
#[cfg(target_os = "zkvm")]
use core::arch::asm;

pub const KECCAK_PERMUTE: u32 = 0x00_01_01_09;

/// Executes the Keccak256 permutation on the given state.
///
/// ### Safety
///
/// The caller must ensure that `state` is valid pointer to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
pub fn keccak_permute(state: &mut [u64; 25]) {
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

/// Adds two Secp256k1 points.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` and `q` are valid pointers to data that is aligned along a four
/// byte boundary. Additionally, the caller must ensure that `p` and `q` are valid points on the
/// secp256k1 curve, and that `p` and `q` are not equal to each other.
#[allow(unused_variables)]
pub fn secp256k1_add(p: *mut [u32; 16], q: *mut [u32; 16]) {
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
