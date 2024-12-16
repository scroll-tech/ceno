extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use rkyv::vec::ArchivedVec;
use std::collections::HashSet;

/// Check that the input is a set of unique numbers.
fn main() {
    let input: &ArchivedVec<u32> = ceno_rt::read();
    let mut set = HashSet::new();
    for i in input.iter() {
        assert!(set.insert(i));
    }
    println!("The input is a set of unique numbers.");
}
