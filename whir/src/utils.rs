use crate::ntt::{transpose, transpose_bench_allocate};
use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;
use p3::field::Field;
use rayon::{iter::ParallelIterator, slice::ParallelSliceMut};
use std::collections::BTreeSet;

#[macro_export]
macro_rules! start_timer {
    ($exp: expr) => {
        ()
    };
}

#[macro_export]
macro_rules! end_timer {
    ($exp: expr) => {
        let _ = $exp;
    };
}

// checks whether the given number n is a power of two.
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1) == 0)
}

/// performs big-endian binary decomposition of `value` and returns the result.
///
/// `n_bits` must be at must usize::BITS. If it is strictly smaller, the most significant bits of `value` are ignored.
/// The returned vector v ends with the least significant bit of `value` and always has exactly `n_bits` many elements.
pub fn to_binary(value: usize, n_bits: usize) -> Vec<bool> {
    // Ensure that n is within the bounds of the input integer type
    assert!(n_bits <= usize::BITS as usize);
    let mut result = vec![false; n_bits];
    for i in 0..n_bits {
        result[n_bits - 1 - i] = (value & (1 << i)) != 0;
    }
    result
}

// TODO(Gotti): n_bits is a misnomer if base > 2. Should be n_limbs or sth.
// Also, should the behaviour for value >= base^n_bits be specified as part of the API or asserted not to happen?
// Currently, we compute the decomposition of value % (base^n_bits).

/// decomposes value into its big-endian base-ary decomposition, meaning we return a vector v, s.t.
///
/// value = v[0]*base^(n_bits-1) + v[1] * base^(n_bits-2) + ... + v[n_bits-1] * 1,
/// where each v[i] is in 0..base.
/// The returned vector always has length exactly n_bits (we pad with leading zeros);
pub fn base_decomposition(value: usize, base: u8, n_bits: usize) -> Vec<u8> {
    // Initialize the result vector with zeros of the specified length
    let mut result = vec![0u8; n_bits];

    // Create a mutable copy of the value for computation
    // Note: We could just make the local passed-by-value argument `value` mutable, but this is clearer.
    let mut value = value;

    // Compute the base decomposition
    for i in 0..n_bits {
        result[i] = (value % (base as usize)) as u8;
        value /= base as usize;
    }
    // TODO: Should we assert!(value == 0) here to check that the orginally passed `value` is < base^n_bits ?

    result
}

// Gotti: Consider renaming this function. The name sounds like it's a PRG.
// TODO (Gotti): Check that ordering is actually correct at point of use (everything else is big-endian).

/// expand_randomness outputs the vector [1, base, base^2, base^3, ...] of length len.
pub fn expand_randomness<F: Field>(base: F, len: usize) -> Vec<F> {
    let mut res = Vec::with_capacity(len);
    let mut acc = F::ONE;
    for _ in 0..len {
        res.push(acc);
        acc *= base;
    }

    res
}

/// Deduplicates AND orders a vector
pub fn dedup<T: Ord>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    Vec::from_iter(BTreeSet::from_iter(v))
}

// FIXME(Gotti): comment does not match what function does (due to mismatch between folding_factor and folding_factor_exp)
// Also, k should be defined: k = evals.len() / 2^{folding_factor}, I guess.

/// Takes the vector of evaluations (assume that evals[i] = f(omega^i))
/// and folds them into a vector of such that folded_evals[i] = [f(omega^(i + k * j)) for j in 0..folding_factor]
pub fn stack_evaluations<F: Field>(mut evals: Vec<F>, folding_factor: usize) -> Vec<F> {
    let folding_factor_exp = 1 << folding_factor;
    assert!(evals.len() % folding_factor_exp == 0);
    let size_of_new_domain = evals.len() / folding_factor_exp;

    // interpret evals as (folding_factor_exp x size_of_new_domain)-matrix and transpose in-place
    transpose(&mut evals, folding_factor_exp, size_of_new_domain);
    evals
}

pub fn stack_evaluations_bench_allocate<F: Field>(
    mut evals: Vec<F>,
    folding_factor: usize,
) -> Vec<F> {
    let folding_factor_exp = 1 << folding_factor;
    assert!(evals.len() % folding_factor_exp == 0);
    let size_of_new_domain = evals.len() / folding_factor_exp;

    // interpret evals as (folding_factor_exp x size_of_new_domain)-matrix and transpose in-place
    transpose_bench_allocate(&mut evals, folding_factor_exp, size_of_new_domain);
    evals
}

pub fn interpolate_field_type_over_boolean_hypercube<E: ExtensionField>(evals: &mut FieldType<E>) {
    match evals {
        FieldType::Ext(evals) => interpolate_over_boolean_hypercube(evals),
        FieldType::Base(evals) => interpolate_over_boolean_hypercube(evals),
        _ => unreachable!(),
    };
}

pub fn interpolate_over_boolean_hypercube<F: Field>(evals: &mut [F]) {
    // let timer = start_timer!(|| "interpolate_over_hypercube");
    // iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = p3::util::log2_strict_usize(evals.len());

    evals.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] -= chunk[0];
    });

    // This code implicitly assumes that coeffs has size at least 1 << n,
    // that means the size of evals should be a power of two
    for i in 2..n + 1 {
        let chunk_size = 1 << i;
        evals.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] -= chunk[j - half_chunk];
            }
        });
    }
    // end_timer!(timer);
}

pub fn evaluate_over_hypercube<F: Field>(coeffs: &mut [F]) {
    let n = p3::util::log2_strict_usize(coeffs.len());

    // This code implicitly assumes that coeffs has size at least 1 << n,
    // that means the size of evals should be a power of two
    for i in (2..n + 1).rev() {
        let chunk_size = 1 << i;
        coeffs.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] += chunk[j - half_chunk];
            }
        });
    }

    coeffs.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] += chunk[0];
    });
}

pub fn evaluate_as_univariate<E: ExtensionField>(evals: &[E], points: &[E]) -> Vec<E> {
    if evals.len() == 1 {
        // It's a constant function, so just return the constant value.
        return vec![evals[0]; points.len()];
    }
    let mut coeffs = evals.to_vec();
    interpolate_over_boolean_hypercube(&mut coeffs);
    points
        .iter()
        .map(|x| {
            let coeff_vec = coeffs.iter().rev();
            let mut acc = E::ZERO;
            for c in coeff_vec {
                acc = acc * *x + *c;
            }
            acc
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use p3::field::PrimeCharacteristicRing;

    use crate::utils::base_decomposition;

    use super::{is_power_of_two, stack_evaluations, to_binary};

    #[test]
    fn test_evaluations_stack() {
        use p3::goldilocks::Goldilocks as F;

        let num = 256;
        let folding_factor = 3;
        let fold_size = 1 << folding_factor;
        assert_eq!(num % fold_size, 0);
        let evals: Vec<F> = (0..num as u64).map(F::from_u64).collect();

        let stacked = stack_evaluations(evals, folding_factor);
        assert_eq!(stacked.len(), num);

        for (i, fold) in stacked.chunks_exact(fold_size).enumerate() {
            assert_eq!(fold.len(), fold_size);
            for (j, item) in fold.iter().copied().enumerate().take(fold_size) {
                assert_eq!(item, F::from_u64((i + j * num / fold_size) as u64));
            }
        }
    }

    #[test]
    fn test_to_binary() {
        assert_eq!(to_binary(0b10111, 5), vec![true, false, true, true, true]);
        assert_eq!(to_binary(0b11001, 2), vec![false, true]); // truncate
        let empty_vec: Vec<bool> = vec![]; // just for the explicit bool type.
        assert_eq!(to_binary(1, 0), empty_vec);
        assert_eq!(to_binary(0, 0), empty_vec);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(!is_power_of_two(0));
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(usize::MAX));
    }

    #[test]
    fn test_base_decomposition() {
        assert_eq!(base_decomposition(0b1011, 2, 6), vec![1, 1, 0, 1, 0, 0]);
        assert_eq!(base_decomposition(15, 3, 3), vec![0, 2, 1]);
        // check truncation: This checks the current (undocumented) behaviour (compute modulo base^number_of_limbs) works as believed.
        // If we actually specify the API to have a different behaviour, this test should change.
        assert_eq!(base_decomposition(15 + 81, 3, 3), vec![0, 2, 1]);
    }
}
