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
pub fn ceil_log2<const PRINT_WITNESS: bool>(x: usize) -> usize {
    assert!(x > 0, "ceil_log2: x must be positive");
    // Calculate the number of bits in usize
    let usize_bits = std::mem::size_of::<usize>() * 8;
    let result = usize_bits - (x - 1).leading_zeros() as usize;
    // PRINT WITNESSES
    if PRINT_WITNESS {
        // bits of x in BIG ENDIAN order
        let mut bits = Vec::new();
        let mut x = if x == 1 { x } else { x - 1 };
        while x > 0 {
            bits.insert(0, x % 2);
            x /= 2;
        }
        // Convert the first entry to bit width
        print!("{}", bits.len());
        for b in &bits[1..] {
            print!(" {}", b);
        }
        println!();
    }
    result
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
