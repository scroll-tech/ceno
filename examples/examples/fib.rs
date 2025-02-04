extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use rkyv::Archived;

fn main() {
    let n = u32::from(ceno_rt::read::<Archived<u32>>());

    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    // Print any output you feel like, eg the first element of the sorted vector:
    println!("{}", a);
}
