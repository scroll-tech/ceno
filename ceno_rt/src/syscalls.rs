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
