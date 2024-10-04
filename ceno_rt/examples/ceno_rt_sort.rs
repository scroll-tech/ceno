#![no_main]
#![no_std]

#[allow(unused_imports)]
use ceno_rt;

use alloc::vec::Vec;
use core::hint::black_box;
use rand::{rngs::SmallRng, Rng, SeedableRng};

extern crate rand;

extern crate alloc;

#[allow(clippy::unit_arg)]
fn sort() {
    let mut rng = black_box(SmallRng::seed_from_u64(0xdead_beef_feed_cafe));
    let n = black_box(10_000);
    let mut v: Vec<u32> = (0..n).map(|_| black_box(rng.gen())).collect();
    black_box(v.sort());
}

#[no_mangle]
fn main() {
    sort();
}
