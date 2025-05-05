pub mod arithmetic;
pub mod expression;
pub mod hash;
use std::collections::VecDeque;

use ff_ext::{ExtensionField, SmallField};
use itertools::{Either, Itertools, izip};
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType, MultilinearExtension},
    op_mle,
};
use serde::{Deserialize, Serialize};
pub mod merkle_tree;
use crate::Error;
use p3::{
    field::{PrimeCharacteristicRing, PrimeField},
    maybe_rayon::prelude::*,
};

pub fn ext_to_usize<E: ExtensionField>(x: &E) -> usize {
    let bases = x.as_bases();
    bases[0].to_canonical_u64() as usize
}

pub fn base_to_usize<E: ExtensionField>(x: &E::BaseField) -> usize {
    x.to_canonical_u64() as usize
}

pub fn u32_to_field<E: ExtensionField>(x: u32) -> E::BaseField {
    E::BaseField::from_u32(x)
}

pub trait BitIndex {
    fn nth_bit(&self, nth: usize) -> bool;
}

impl BitIndex for usize {
    fn nth_bit(&self, nth: usize) -> bool {
        (self >> nth) & 1 == 1
    }
}

/// How many bytes are required to store n field elements?
pub fn num_of_bytes<F: PrimeField>(n: usize) -> usize {
    F::bits().next_power_of_two() * n / 8
}

pub fn poly_index_ext<E: ExtensionField>(poly: &DenseMultilinearExtension<E>, index: usize) -> E {
    match &poly.evaluations {
        FieldType::Ext(coeffs) => coeffs[index],
        FieldType::Base(coeffs) => E::from(coeffs[index]),
        _ => unreachable!(),
    }
}

pub fn field_type_index_base<E: ExtensionField>(poly: &FieldType<E>, index: usize) -> E::BaseField {
    match &poly {
        FieldType::Ext(_) => panic!("Cannot get base field from extension field"),
        FieldType::Base(coeffs) => coeffs[index],
        _ => unreachable!(),
    }
}

pub fn field_type_index_ext<E: ExtensionField>(poly: &FieldType<E>, index: usize) -> E {
    match &poly {
        FieldType::Ext(coeffs) => coeffs[index],
        FieldType::Base(coeffs) => E::from(coeffs[index]),
        _ => unreachable!(),
    }
}

pub fn field_type_index_mul_base<E: ExtensionField>(
    poly: &mut FieldType<E>,
    index: usize,
    scalar: &E::BaseField,
) {
    match poly {
        FieldType::Ext(coeffs) => coeffs[index] *= *scalar,
        FieldType::Base(coeffs) => coeffs[index] *= *scalar,
        _ => unreachable!(),
    }
}

pub fn field_type_index_set_base<E: ExtensionField>(
    poly: &mut FieldType<E>,
    index: usize,
    scalar: &E::BaseField,
) {
    match poly {
        FieldType::Ext(coeffs) => coeffs[index] = E::from(*scalar),
        FieldType::Base(coeffs) => coeffs[index] = *scalar,
        _ => unreachable!(),
    }
}

pub fn field_type_index_set_ext<E: ExtensionField>(
    poly: &mut FieldType<E>,
    index: usize,
    scalar: &E,
) {
    match poly {
        FieldType::Ext(coeffs) => coeffs[index] = *scalar,
        FieldType::Base(_) => panic!("Cannot set base field from extension field"),
        _ => unreachable!(),
    }
}

pub fn poly_iter_ext<E: ExtensionField>(
    poly: &DenseMultilinearExtension<E>,
) -> impl Iterator<Item = E> + '_ {
    field_type_iter_ext(&poly.evaluations)
}

pub fn field_type_iter_ext<E: ExtensionField>(
    evaluations: &FieldType<E>,
) -> impl Iterator<Item = E> + '_ {
    match evaluations {
        FieldType::Ext(coeffs) => Either::Left(coeffs.iter().copied()),
        FieldType::Base(coeffs) => Either::Right(coeffs.iter().map(|x| (*x).into())),
        _ => unreachable!(),
    }
}

pub fn field_type_to_ext_vec<E: ExtensionField>(evaluations: &FieldType<E>) -> Vec<E> {
    match evaluations {
        FieldType::Ext(coeffs) => coeffs.to_vec(),
        FieldType::Base(coeffs) => coeffs.iter().map(|&x| x.into()).collect(),
        _ => unreachable!(),
    }
}

pub fn field_type_as_ext<E: ExtensionField>(values: &FieldType<E>) -> &Vec<E> {
    match values {
        FieldType::Ext(coeffs) => coeffs,
        FieldType::Base(_) => panic!("Expected ext field"),
        _ => unreachable!(),
    }
}

pub fn field_type_iter_base<E: ExtensionField>(
    values: &FieldType<E>,
) -> impl Iterator<Item = &E::BaseField> + '_ {
    match values {
        FieldType::Ext(coeffs) => Either::Left(coeffs.iter().flat_map(|x| x.as_bases())),
        FieldType::Base(coeffs) => Either::Right(coeffs.iter()),
        _ => unreachable!(),
    }
}

pub fn multiply_poly<E: ExtensionField>(poly: &mut DenseMultilinearExtension<E>, scalar: &E) {
    match &mut poly.evaluations {
        FieldType::Ext(coeffs) => {
            for coeff in coeffs.iter_mut() {
                *coeff *= *scalar;
            }
        }
        FieldType::Base(coeffs) => {
            *poly = DenseMultilinearExtension::<E>::from_evaluations_ext_vec(
                poly.num_vars,
                coeffs.iter().map(|x| E::from(*x) * *scalar).collect(),
            );
        }
        _ => unreachable!(),
    }
}

/// Resize to the new number of variables, which must be greater than or equal to
/// the current number of variables.
pub fn resize_num_vars<E: ExtensionField>(
    poly: &mut DenseMultilinearExtension<E>,
    num_vars: usize,
) {
    assert!(num_vars >= poly.num_vars);
    if num_vars == poly.num_vars {
        return;
    }
    match &mut poly.evaluations {
        FieldType::Base(evaluations) => {
            evaluations.resize(1 << num_vars, E::BaseField::ZERO);
            // When evaluate a multilinear polynomial outside of its original interpolated hypercube,
            // the evaluations are just repetitions of the original evaluations
            (1 << poly.num_vars..1 << num_vars)
                .for_each(|i| evaluations[i] = evaluations[i & ((1 << poly.num_vars) - 1)]);
        }
        FieldType::Ext(evaluations) => {
            evaluations.resize(1 << num_vars, E::ZERO);
            (1 << poly.num_vars..1 << num_vars)
                .for_each(|i| evaluations[i] = evaluations[i & ((1 << poly.num_vars) - 1)])
        }
        _ => unreachable!(),
    }
    poly.num_vars = num_vars;
}

// TODO remove this function once mpcs development stable
pub fn add_polynomial_with_coeff<E: ExtensionField>(
    lhs: &mut DenseMultilinearExtension<E>,
    rhs: &DenseMultilinearExtension<E>,
    coeff: &E,
) {
    match (lhs.num_vars == 0, rhs.num_vars == 0) {
        (_, true) => {}
        (true, false) => {
            *lhs = rhs.clone();
            multiply_poly(lhs, coeff);
        }
        (false, false) => {
            if lhs.num_vars < rhs.num_vars {
                resize_num_vars(lhs, rhs.num_vars);
            }
            if rhs.num_vars < lhs.num_vars {
                match &mut lhs.evaluations {
                    FieldType::Ext(ref mut lhs) => {
                        let mask = (1 << rhs.num_vars) - 1;
                        op_mle!(rhs, |rhs| {
                            lhs.par_iter_mut()
                                .enumerate()
                                .for_each(|(index, lhs)| *lhs += *coeff * rhs[index & mask]);
                        });
                    }
                    FieldType::Base(ref mut lhs_evals) => {
                        *lhs = DenseMultilinearExtension::<E>::from_evaluations_ext_vec(
                            lhs.num_vars,
                            lhs_evals
                                .iter()
                                .enumerate()
                                .map(|(index, lhs)| {
                                    E::from(*lhs)
                                        + *coeff
                                            * poly_index_ext(rhs, index & ((1 << rhs.num_vars) - 1))
                                })
                                .collect(),
                        );
                    }
                    _ => unreachable!(),
                }
            } else {
                match &mut lhs.evaluations {
                    FieldType::Ext(ref mut lhs) => {
                        op_mle!(rhs, |rhs| {
                            lhs.par_iter_mut()
                                .zip(rhs.par_iter())
                                .for_each(|(lhs, rhs)| *lhs += *coeff * *rhs);
                        });
                    }
                    FieldType::Base(ref mut lhs_evals) => {
                        *lhs = DenseMultilinearExtension::<E>::from_evaluations_ext_vec(
                            lhs.num_vars,
                            lhs_evals
                                .iter()
                                .enumerate()
                                .map(|(index, lhs)| {
                                    E::from(*lhs) + *coeff * poly_index_ext(rhs, index)
                                })
                                .collect(),
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}

pub fn ext_try_into_base<E: ExtensionField>(x: &E) -> Result<E::BaseField, Error> {
    let bases = x.as_bases();
    if bases[1..].iter().any(|x| *x != E::BaseField::ZERO) {
        Err(Error::ExtensionFieldElementNotFit)
    } else {
        Ok(bases[0])
    }
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
    #[cfg(test)]
    use crate::util::{base_to_usize, u32_to_field};
    use ff_ext::FromUniformBytes;
    use p3::field::PrimeCharacteristicRing;
    #[cfg(test)]
    type E = ff_ext::GoldilocksExt2;
    #[cfg(test)]
    type F = p3::goldilocks::Goldilocks;
    use rand::{
        CryptoRng, RngCore, SeedableRng,
        rngs::{OsRng, StdRng},
    };
    use std::{array, iter, ops::Range};

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
        assert_eq!(F::from_u64(2) * F::from_u64(3), F::from_u64(6));
        assert_eq!(base_to_usize::<E>(&u32_to_field::<E>(1u32)), 1);
        assert_eq!(base_to_usize::<E>(&u32_to_field::<E>(10u32)), 10);
    }
}
