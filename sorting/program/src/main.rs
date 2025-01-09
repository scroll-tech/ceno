//! A simple program that takes a number `n` and counts the number of primes up to n
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use sorting_lib::PublicValuesStruct;

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();
    let n_: usize = n.try_into().unwrap();
    // Sort a sequence of n pseudo-random numbers
    let mut scratch: Vec<u32> = vec![1; n_];
    for i in 1..n_ {
        scratch[i] = ((scratch[i - 1]) * 17 + 19) & ((1 << 20) - 1);
    }
    scratch.sort();

    let median = scratch[n_ / 2];

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, median });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
