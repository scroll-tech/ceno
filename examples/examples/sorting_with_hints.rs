extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use itertools::{Itertools, izip};
use rkyv::vec::ArchivedVec;

fn main() {
    // We take the input numbers from the hints for convenience.
    // But just pretend that in the real world, the input would be
    // committed to via public IO.
    let input: &ArchivedVec<u32> = ceno_rt::read();
    let answer: &ArchivedVec<u32> = ceno_rt::read();
    let places: &ArchivedVec<u32> = ceno_rt::read();

    // Check that the answer is sorted.
    for (prev, next) in answer.iter().tuple_windows() {
        assert!(prev <= next);
    }

    // Check that that `answer` is a permutation of the `input`,
    // with the help of `places`.
    let mut scratch: Vec<bool> = vec![true; input.len()];
    for (&place, answer) in izip!(places.iter(), answer.iter()) {
        assert!(std::mem::replace(&mut scratch[place as usize], false));
        assert_eq!(input[place as usize], *answer);
    }
    println!("All checks passed!");
}
