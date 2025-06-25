use rkyv::vec::ArchivedVec;
use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    let times = 10;
    let raw_preimage: &ArchivedVec<u32> = ceno_rt::read();
    let preimage: Vec<u8> = raw_preimage.iter().flat_map(|x| x.to_le_bytes()).collect();
    for i in 0..times {
        let digest = keccak256(&preimage)
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>();

        if i == 0 {
            log_digest(digest);
        }
        // TODO define serializable struct
        // ceno_rt::commit::<ArchivedVec<u32>, Vec<u32>>(&result);
    }
}

/// Simple interface to the [`keccak256`] hash function.
///
/// [`keccak256`]: https://en.wikipedia.org/wiki/SHA-3
pub fn keccak256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    output
}

#[cfg(debug_assertions)]
fn log_digest(digest: Vec<u32>) {
    use ceno_rt::debug_print;
    use core::fmt::Write;
    for d in digest {
        debug_print!("{:x}", d)
    }
}

#[cfg(not(debug_assertions))]
fn log_digest(_digest: Vec<u32>) {}
