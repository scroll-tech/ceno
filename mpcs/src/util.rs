pub mod arithmetic;
pub mod hash;
use std::collections::VecDeque;

use ff_ext::{ExtensionField, SmallField};
pub mod merkle_tree;
use p3::field::FieldAlgebra;

pub fn base_to_usize<E: ExtensionField>(x: &E::BaseField) -> usize {
    x.to_canonical_u64() as usize
}

pub fn u32_to_field<E: ExtensionField>(x: u32) -> E::BaseField {
    E::BaseField::from_canonical_u32(x)
}

/// splits a vector into multiple slices, where each slice length
/// is specified by the corresponding element in the `sizes` slice.
///
/// # arguments
///
/// * `input` - the input vector to be split.
/// * `sizes` - a slice of sizes indicating how to split the input vector.
///
/// # panics
///
/// panics if the sum of `sizes` does not equal the length of `input`.
///
/// # example
///
/// ```
/// let input = vec![10, 20, 30, 40, 50, 60];
/// let sizes = vec![2, 3, 1];
/// let result = split_by_sizes(input, &sizes);
///
/// assert_eq!(result.len(), 3);
/// assert_eq!(result[0], &[10, 20]);
/// assert_eq!(result[1], &[30, 40, 50]);
/// assert_eq!(result[2], &[60]);
/// ```
pub fn split_by_sizes<'a, T>(input: &'a [T], sizes: &[usize]) -> Vec<&'a [T]> {
    let total_size: usize = sizes.iter().sum();

    if total_size != input.len() {
        panic!(
            "total size of chunks ({}) doesn't match input length ({})",
            total_size,
            input.len()
        );
    }

    // `scan` keeps track of the current start index and produces each slice
    sizes
        .iter()
        .scan(0, |start, &size| {
            let end = *start + size;
            let slice = &input[*start..end];
            *start = end;
            Some(slice)
        })
        .collect()
}

/// removes and returns elements from the front of the deque
/// as long as they satisfy the given predicate.
///
/// # arguments
/// * `deque` - the mutable VecDeque to operate on.
/// * `pred` - a predicate function that takes a reference to an element
///   and returns `true` if the element should be removed.
///
/// # returns
/// a `Vec<T>` containing all the elements that were removed.
pub fn pop_front_while<T, F>(deque: &mut VecDeque<T>, mut pred: F) -> Vec<T>
where
    F: FnMut(&T) -> bool,
{
    let mut result = Vec::new();
    while let Some(front) = deque.front() {
        if pred(front) {
            result.push(deque.pop_front().unwrap());
        } else {
            break;
        }
    }
    result
}

#[inline(always)]
pub(crate) fn codeword_fold_with_challenge<E: ExtensionField>(
    codeword: &[E],
    challenge: E,
    coeff: E::BaseField,
    inv_2: E::BaseField,
) -> E {
    let (left, right) = (codeword[0], codeword[1]);
    // original (left, right) = (lo + hi*x, lo - hi*x), lo, hi are codeword, but after times x it's not codeword
    // recover left & right codeword via (lo, hi) = ((left + right) / 2, (left - right) / 2x)
    let (lo, hi) = ((left + right) * inv_2, (left - right) * coeff); // e.g. coeff = (2 * dit_butterfly)^(-1) in rs code
    // we do fold on (lo, hi) to get folded = (1-r) * lo + r * hi (with lo, hi are two codewords), as it match perfectly with raw message in lagrange domain fixed variable
    lo + challenge * (hi - lo)
}

#[cfg(any(test, feature = "benchmark"))]
pub mod test {
    use ff_ext::FromUniformBytes;
    use rand::{
        CryptoRng, RngCore, SeedableRng,
        rngs::{OsRng, StdRng},
    };
    use std::{array, iter, ops::Range};
    #[cfg(test)]
    use {
        crate::util::{base_to_usize, u32_to_field},
        p3::field::FieldAlgebra,
    };

    #[cfg(test)]
    type E = ff_ext::GoldilocksExt2;
    #[cfg(test)]
    type F = p3::goldilocks::Goldilocks;

    pub fn std_rng() -> impl RngCore + CryptoRng {
        StdRng::from_seed(Default::default())
    }

    pub fn seeded_std_rng() -> impl RngCore + CryptoRng {
        StdRng::seed_from_u64(OsRng.next_u64())
    }

    pub fn rand_idx(range: Range<usize>, mut rng: impl RngCore) -> usize {
        range.start + (rng.next_u64() as usize % (range.end - range.start))
    }

    pub fn rand_array<F: FromUniformBytes, const N: usize>(mut rng: impl RngCore) -> [F; N] {
        array::from_fn(|_| F::random(&mut rng))
    }

    pub fn rand_vec<F: FromUniformBytes>(n: usize, mut rng: impl RngCore) -> Vec<F> {
        iter::repeat_with(|| F::random(&mut rng)).take(n).collect()
    }

    #[test]
    pub fn test_field_transform() {
        assert_eq!(
            F::from_canonical_u64(2) * F::from_canonical_u64(3),
            F::from_canonical_u64(6)
        );
        assert_eq!(base_to_usize::<E>(&u32_to_field::<E>(1u32)), 1);
        assert_eq!(base_to_usize::<E>(&u32_to_field::<E>(10u32)), 10);
    }
}
