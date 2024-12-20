extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use rkyv::vec::ArchivedVec;

fn sort<T: Ord>(slice: &mut [T]) {
    let len = slice.len();
    for i in 0..len {
        for j in 0..len {
            if slice[j] > slice[i] {
                slice.swap(j, i);
            }
        }
    }
}

fn main() {
    let input: &ArchivedVec<u32> = ceno_rt::read();
    let mut scratch = input.to_vec();
    sort(&mut scratch);
    // Print any output you feel like, eg the first element of the sorted vector:
    println!("{}", scratch[0]);
}
