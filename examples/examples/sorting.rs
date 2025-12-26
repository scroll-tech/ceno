extern crate ceno_rt;
use ceno_rt::debug_println;
#[cfg(debug_assertions)]
use core::fmt::Write;

fn main() {
    let mut scratch: Vec<u32> = ceno_rt::read();
    scratch.sort();
    // Print any output you feel like, eg the first element of the sorted vector:
    debug_println!("{}", scratch[0]);
}
