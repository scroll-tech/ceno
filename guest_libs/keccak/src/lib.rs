//! Ceno Keccak zkVM Guest Library

#![no_std]
#![deny(missing_docs)]
extern crate alloc;

/// Re-export the `tiny_keccak` crate's `Hasher` trait.
pub use tiny_keccak::{self, Hasher};

mod vendor;
pub use vendor::keccak::Keccak;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "riscv32"))] {
        pub use tiny_keccak::keccakf;
    } else {
        pub use ceno_rt::syscalls::syscall_keccak_permute as keccakf;
    }
}

mod keccakf {
    use crate::{
        keccakf,
        vendor::{Buffer, Permutation},
    };

    pub struct KeccakF;

    impl Permutation for KeccakF {
        fn execute(buffer: &mut Buffer) {
            keccakf(buffer.words());
        }
    }
}

/// Native hook for keccak256 for use with `alloy-primitives` "native-keccak" feature.
///
/// # Safety
///
/// The VM accepts the preimage by pointer and length, and writes the
/// 32-byte hash.
/// - `bytes` must point to an input buffer at least `len` long.
/// - `output` must point to a buffer that is at least 32-bytes long.
///
/// [`keccak256`]: https://en.wikipedia.org/wiki/SHA-3
/// [`sha3`]: https://docs.rs/sha3/latest/sha3/
/// [`tiny_keccak`]: https://docs.rs/tiny-keccak/latest/tiny_keccak/
#[cfg(target_arch = "riscv32")]
#[inline(always)]
#[no_mangle]
pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    use crate::{Hasher, Keccak};

    unsafe {
        let input = core::slice::from_raw_parts(bytes, len);
        let out = core::slice::from_raw_parts_mut(output, 32);
        let mut hasher = Keccak::v256();
        hasher.update(input);
        hasher.finalize(out);
    }
}
