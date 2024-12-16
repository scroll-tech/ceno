//! Here's an example that really makes use of the standard library and couldn't be done without.
//!
//! I mean `HashSet` really lives only in the proper standard library, and not in `alloc` or `core`.
//! You could, of course, rerwite the example to use `alloc::collections::btree_set::BTreeSet`
//! instead of `HashSet`.

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
