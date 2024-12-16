extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use rkyv::vec::ArchivedVec;

fn main() {
    let input: &ArchivedVec<u32> = ceno_rt::read();
    let mut scratch: Vec<u32> = input.to_vec();
    scratch.sort();
    // Print any output you feel like, eg the first element of the sorted vector:
    println!("{}", scratch[0]);
}
