extern crate ceno_rt;

use ceno_sha2::{Digest, Sha256};

// Example run (private input: 10 zero bytes)
// RUST_LOG=info cargo run --release --package ceno_zkvm --bin e2e -- --profiling=3 --platform=ceno --public-io=30689455,3643278932,1489987339,1626711444,3610619649,1925764735,581441152,321290698 examples/target/riscv32im-ceno-zkvm-elf/release/examples/sha256 --hints=0,0,0,0,0,0,0,0,0,0
fn main() {
    // Read input data from the host
    let input: Vec<u8> = ceno_rt::read();

    let h = Sha256::digest(&input);
    let h: [u8; 32] = h.into();
    let h: [u32; 8] = core::array::from_fn(|i| {
        let chunk = &h[4 * i..][..4];
        u32::from_be_bytes(chunk.try_into().unwrap())
    });

    // Output the final hash values one by one
    ceno_rt::commit(&h);
    // debug_print!("{:x}", h[0]);
}
