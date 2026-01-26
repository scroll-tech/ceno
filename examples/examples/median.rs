//! Find the median of a collection of numbers.
//!
//! Of course, we are asking our good friend, the host, for help, but we still need to verify the answer.
extern crate ceno_rt;
use ceno_rt::debug_println;
#[cfg(debug_assertions)]
use core::fmt::Write;

fn main() {
    let numbers: Vec<u32> = ceno_rt::read();
    let median_candidate: u32 = ceno_rt::read();
    let smaller = numbers.iter().filter(|x| **x < median_candidate).count();
    assert_eq!(smaller, numbers.len() / 2);
    debug_println!("{}", median_candidate);
}
