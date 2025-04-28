extern crate ceno_rt;
use rkyv::Archived;

fn is_prime(n: u32) -> bool {
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

    true
}

fn main() {
    let n: &Archived<u32> = ceno_rt::read();
    let mut cnt_primes = 0;

    for i in 0..=n.into() {
        cnt_primes += is_prime(i) as u32;
    }

    if cnt_primes > 1000 * 1000 {
        panic!();
    }

    ceno_rt::commit::<Archived<u32>, _>(&cnt_primes);
}
