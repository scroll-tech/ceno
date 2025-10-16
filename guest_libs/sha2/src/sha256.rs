use crate::consts::K32;
use ceno_syscall::syscall_sha256_extend;
use digest::{consts::U64, generic_array::GenericArray};

// Copied from <https://github.com/sp1-patches/RustCrypto-hashes/blob/bf1b2575ccc1bab0f0890f4c3064bcd1d8968a1f/sha2/src/sha256.rs#L42C1-L49C2>
#[inline(always)]
fn to_u32s(block: &[u8; 64]) -> [u32; 16] {
    core::array::from_fn(|i| {
        let chunk = block[4 * i..][..4].try_into().unwrap();
        u32::from_be_bytes(chunk)
    })
}

// Copied from <https://github.com/sp1-patches/RustCrypto-hashes/blob/bf1b2575ccc1bab0f0890f4c3064bcd1d8968a1f/sha2/src/sha256/soft_compact.rs>
fn compress_u32(state: &mut [u32; 8], block: [u32; 16]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    let mut w = [0; 64];
    w[..16].copy_from_slice(&block);

    // Replace extend with a syscall
    syscall_sha256_extend(&mut w);

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = s1
            .wrapping_add(ch)
            .wrapping_add(K32[i])
            .wrapping_add(w[i])
            .wrapping_add(h);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks.iter() {
        compress_u32(state, to_u32s(block));
    }
}

/// Raw SHA-256 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-256.
pub fn compress256(state: &mut [u32; 8], blocks: &[GenericArray<u8, U64>]) {
    // SAFETY: GenericArray<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    let p = blocks.as_ptr() as *const [u8; 64];
    let blocks = unsafe { core::slice::from_raw_parts(p, blocks.len()) };
    compress(state, blocks)
}
