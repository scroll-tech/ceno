// WARNING: VIBE-CODED!
extern crate ceno_rt;
use ceno_rt::syscalls::syscall_sha256_extend;
use rkyv::vec::ArchivedVec;

// SHA-256 constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Initial hash values
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// To test with hardcoded 10-byte input, run with:
// RUST_LOG=info cargo run --release --package ceno_zkvm --bin e2e -- --profiling=3 --platform=ceno --public-io=30689455,3643278932,1489987339,1626711444,3610619649,1925764735,581441152,321290698 examples/target/riscv32im-ceno-zkvm-elf/release/examples/sha256
fn main() {
    // Hardcoded 10 zero byte input
    let input: Vec<u8> = vec![0; 10];
    // Read input data from the host
    // ceno_rt::read();
    let input: &[u8] = input.as_ref();

    // Initialize hash state
    let mut h = H0;

    // Process input in 512-bit (64-byte) blocks
    for chunk in input.chunks(64) {
        // Prepare message block
        let mut w = [0u32; 64];

        // Copy input bytes into first 16 words
        for (i, byte) in chunk.iter().enumerate() {
            let word_idx = i / 4;
            let byte_idx = i % 4;
            w[word_idx] |= (*byte as u32) << ((3 - byte_idx) * 8);
        }

        // If this is the last block, add padding
        if chunk.len() < 64 {
            // Add 1 bit
            w[chunk.len() / 4] |= 0x80 << ((3 - (chunk.len() % 4)) * 8);

            // If there's not enough space for the length, we need another block
            if chunk.len() >= 56 {
                // Process this block
                process_block(&mut h, &w);
                // Create a new block with just padding
                w = [0u32; 64];
            }

            // Add message length in bits at the end
            let bit_len = (input.len() * 8) as u64;
            w[14] = (bit_len >> 32) as u32;
            w[15] = bit_len as u32;
        }

        // Process the block
        process_block(&mut h, &w);
    }

    // Output the final hash values one by one
    ceno_rt::commit::<ArchivedVec<u32>, SHA256Result>(&SHA256Result(h.to_vec()));
    // debug_print!("{:x}", h[0]);
}

#[derive(Debug, PartialEq)]
struct SHA256Result(Vec<u32>);
impl From<&ArchivedVec<u32>> for SHA256Result {
    fn from(value: &ArchivedVec<u32>) -> Self {
        SHA256Result(value.to_vec())
    }
}

fn process_block(h: &mut [u32; 8], w: &[u32; 64]) {
    // Expand message schedule
    let mut w_expanded = *w;
    syscall_sha256_extend(&mut w_expanded);

    // Initialize working variables
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_i = h[7];

    // Main loop
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h_i
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w_expanded[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h_i = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Add this chunk's hash to result
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_i);
}
