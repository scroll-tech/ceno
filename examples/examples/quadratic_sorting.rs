extern crate ceno_rt;

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
    let mut scratch: Vec<u32> = ceno_rt::read();
    sort(&mut scratch);
    // Print any output you feel like, eg the first element of the sorted vector:
    // println!("{}", scratch[0]);
}
