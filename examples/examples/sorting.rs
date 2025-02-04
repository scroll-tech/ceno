extern crate ceno_rt;
use rand::Rng;
use rkyv::Archived;

fn main() {
    let n = u32::from(ceno_rt::read::<Archived<u32>>());

    // Provide some random numbers to sort.
    let mut rng = rand::thread_rng();
    let mut scratch: Vec<u32> = (0..n).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    scratch.sort();
}
