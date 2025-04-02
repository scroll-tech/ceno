pub mod arithmetic;
pub mod expression;
pub mod hash;
pub mod parallel;
use ff_ext::{ExtensionField, SmallField};
use itertools::{Either, Itertools, izip};
use multilinear_extensions::mle::{DenseMultilinearExtension, FieldType};
use serde::{Deserialize, Serialize};
pub mod merkle_tree;
use crate::{Error, util::parallel::parallelize};
use p3::field::{PrimeCharacteristicRing, PrimeField};

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
                        parallelize(lhs, |(lhs, start)| {
                            for (index, lhs) in lhs.iter_mut().enumerate() {
                                *lhs += *coeff
                                    * poly_index_ext(
                                        rhs,
                                        (start + index) & ((1 << rhs.num_vars) - 1),
                                    );
                            }
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
                        parallelize(lhs, |(lhs, start)| {
                            for (index, lhs) in lhs.iter_mut().enumerate() {
                                *lhs += *coeff * poly_index_ext(rhs, start + index);
                            }
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

/// splits a slice into multiple sub-slices at given indices.
///
/// # arguments
/// * `slice` - the slice to split.
/// * `indices` - positions where the slice should be split.
///
/// # returns
/// * a `Vec<&[T]>` containing the sub-slices.
///
/// # notes
/// * indices should be in non-decreasing order.
/// * the last segment extends to the slice end.
///
/// # example
/// ```
/// let data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
/// let parts = split_slice(&data, &[2, 5, 7]);
/// assert_eq!(parts, vec![&[1, 2], &[3, 4, 5], &[6, 7], &[8, 9]]);
/// ```
pub fn split_slice<'a, T>(slice: &'a [T], indices: &[usize]) -> Vec<&'a [T]> {
    indices
        .iter()
        .chain(std::iter::once(&slice.len())) // append slice.len() as the final boundary
        .scan(0, |start, &end| {
            let segment = &slice[*start..end.min(slice.len())]; // slice safely within bounds
            *start = end.min(slice.len()); // update `start` for the next iteration
            Some(segment) // yield the segment
        })
        .collect()
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
