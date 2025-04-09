//! A simple program that takes a number `n` and counts the number of primes up to n
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn is_prime(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    let mut i = 2;
    while i * i <= n {
        if n % i == 0 {
            return false;
        }
        i += 1;
    }

    return true;
}

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();

    // Count (naively) the number of primes up to n inclusively
    let mut cnt_primes = 0;
    for i in 0..=n.into() {
        cnt_primes += is_prime(i) as u32;
    }

    if cnt_primes > 1000 * 1000 {
        panic!();
    }
}
