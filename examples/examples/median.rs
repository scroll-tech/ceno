//! Find the median of a collection of numbers.
//!
//! Of course, we are asking our good friend, the host, for help, but we still need to verify the answer.
extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use rkyv::{Archived, vec::ArchivedVec};

fn main() {
    let numbers: &ArchivedVec<u32> = ceno_rt::read();
    let median_candidate: &Archived<u32> = ceno_rt::read();
    let median_candidate = &&median_candidate.to_native();
    let smaller = numbers.iter().filter(move |x| x < median_candidate).count();
    assert_eq!(smaller, numbers.len() / 2);
    println!("{}", median_candidate);
}
