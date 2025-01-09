extern crate ceno_rt;
use rkyv::Archived;

fn main() {
    let n: &Archived<u32> = ceno_rt::read();
    let n: usize = (*n).try_into().unwrap();

    // Initialize with some pseudo-random array to avoid large input
    let mut scratch: Vec<u32> = vec![1; n];
    for i in 1..n {
        scratch[i] = ((scratch[i - 1]) * 17 + 19) & ((1 << 20) - 1);
    }
    scratch.sort();
}
