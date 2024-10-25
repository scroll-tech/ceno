use std::mem::MaybeUninit;

/// Decompose an integer into a binary vector in little endian.
pub fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(num_var);
    let mut i = input;
    for _ in 0..num_var {
        res.push(i & 1 == 1);
        i >>= 1;
    }
    res
}

// TODO avoid duplicate implementation with sumcheck package
/// log2 ceil of x
pub fn ceil_log2(x: usize) -> usize {
    assert!(x > 0, "ceil_log2: x must be positive");
    // Calculate the number of bits in usize
    let usize_bits = std::mem::size_of::<usize>() * 8;
    usize_bits - (x - 1).leading_zeros() as usize
}

pub fn create_uninit_vec<T: Sized>(len: usize) -> Vec<MaybeUninit<T>> {
    let mut vec: Vec<MaybeUninit<T>> = Vec::with_capacity(len);
    unsafe { vec.set_len(len) };
    vec
}

#[inline(always)]
pub fn largest_even_below(n: usize) -> usize {
    if n % 2 == 0 { n } else { n.saturating_sub(1) }
}

/// return max available thread aligned power of 2
pub fn aligned_max_usable_threads() -> usize {
    if cfg!(test) {
        1
    } else {
        let max_threads = rayon::current_num_threads();
        if !max_threads.is_power_of_two() {
            tracing::warn!("thread size {} is not power of 2", max_threads);
            if max_threads < 2 {
                1
            } else {
                1 << (usize::BITS - 1 - max_threads.leading_zeros()) // get prev power of 2
            }
        } else {
            max_threads
        }
    }
}
