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

pub(crate) fn index_of<T: PartialEq>(slice: &[T], target: &T) -> Option<usize> {
    for (index, item) in slice.iter().enumerate() {
        if target == item {
            return Some(index);
        }
    }
    None
}
