#![no_main]
#![no_std]

extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use rkyv::vec::ArchivedVec;

ceno_rt::entry!(main);
fn main() {
    let input: &ArchivedVec<u32> = ceno_rt::read();
    let mut scratch = input.to_vec();
    scratch.sort();
    // Print any output you feel like, eg the first element of the sorted vector:
    println!("{}", scratch[0]);
}
