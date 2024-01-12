use ff::{BatchInvert, Field, PrimeField};
use halo2_curves::{
    bn256, grumpkin,
    pairing::{self, MillerLoopResult},
    pasta::{pallas, vesta},
};
use num_integer::Integer;
use std::{borrow::Borrow, fmt::Debug, iter};

mod bh;
pub use bh::BooleanHypercube;
pub use bitvec::field::BitField;
use num_bigint::BigUint;

use itertools::{chain, izip, Itertools};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

/// Evaluate the given coeffs as a univariate polynomial at x
pub fn horner<F: Field>(coeffs: &[F], x: &F) -> F {
    let coeff_vec: Vec<&F> = coeffs.iter().rev().collect();
    let mut acc = F::ZERO;
    for c in coeff_vec {
        acc = acc * x + c;
    }
    acc
    //2
    //.fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

pub fn steps<F: Field>(start: F) -> impl Iterator<Item = F> {
    steps_by(start, F::ONE)
}

pub fn steps_by<F: Field>(start: F, step: F) -> impl Iterator<Item = F> {
    iter::successors(Some(start), move |state| Some(step + state))
}

pub fn powers<F: Field>(scalar: F) -> impl Iterator<Item = F> {
    iter::successors(Some(F::ONE), move |power| Some(scalar * power))
}

pub fn squares<F: Field>(scalar: F) -> impl Iterator<Item = F> {
    iter::successors(Some(scalar), move |scalar| Some(scalar.square()))
}

pub fn product<F: Field>(values: impl IntoIterator<Item = impl Borrow<F>>) -> F {
    values
        .into_iter()
        .fold(F::ONE, |acc, value| acc * value.borrow())
}

pub fn sum<F: Field>(values: impl IntoIterator<Item = impl Borrow<F>>) -> F {
    values
        .into_iter()
        .fold(F::ZERO, |acc, value| acc + value.borrow())
}

pub fn inner_product<'a, 'b, F: Field>(
    lhs: impl IntoIterator<Item = &'a F>,
    rhs: impl IntoIterator<Item = &'b F>,
) -> F {
    lhs.into_iter()
        .zip_eq(rhs.into_iter())
        .map(|(lhs, rhs)| *lhs * rhs)
        .reduce(|acc, product| acc + product)
        .unwrap_or_default()
}

pub fn inner_product_three<'a, 'b, 'c, F: Field>(
    a: impl IntoIterator<Item = &'a F>,
    b: impl IntoIterator<Item = &'b F>,
    c: impl IntoIterator<Item = &'c F>,
) -> F {
    a.into_iter()
        .zip_eq(b.into_iter())
        .zip_eq(c.into_iter())
        .map(|((a, b), c)| *a * b * c)
        .reduce(|acc, product| acc + product)
        .unwrap_or_default()
}

pub fn barycentric_weights<F: Field>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter_map(|(i, point_i)| (i != j).then(|| *point_j - point_i))
                .reduce(|acc, value| acc * &value)
                .unwrap_or(F::ONE)
        })
        .collect_vec();
    weights.iter_mut().batch_invert();
    weights
}

pub fn barycentric_interpolate<F: Field>(weights: &[F], points: &[F], evals: &[F], x: &F) -> F {
    let (coeffs, sum_inv) = {
        let mut coeffs = points.iter().map(|point| *x - point).collect_vec();
        coeffs.iter_mut().batch_invert();
        coeffs.iter_mut().zip(weights).for_each(|(coeff, weight)| {
            *coeff *= weight;
        });
        let sum_inv = coeffs.iter().fold(F::ZERO, |sum, coeff| sum + coeff);
        (coeffs, sum_inv.invert().unwrap())
    };
    inner_product(&coeffs, evals) * &sum_inv
}

pub fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_bytes_le((-F::ONE).to_repr().as_ref()) + 1u64
}

pub fn fe_from_bool<F: Field>(value: bool) -> F {
    if value {
        F::ONE
    } else {
        F::ZERO
    }
}

pub fn fe_mod_from_le_bytes<F: PrimeField>(bytes: impl AsRef<[u8]>) -> F {
    fe_from_le_bytes((BigUint::from_bytes_le(bytes.as_ref()) % modulus::<F>()).to_bytes_le())
}

pub fn fe_truncated_from_le_bytes<F: PrimeField>(bytes: impl AsRef<[u8]>, num_bits: usize) -> F {
    let mut big = BigUint::from_bytes_le(bytes.as_ref());
    (num_bits as u64..big.bits()).for_each(|idx| big.set_bit(idx, false));
    fe_from_le_bytes(big.to_bytes_le())
}

pub fn fe_from_le_bytes<F: PrimeField>(bytes: impl AsRef<[u8]>) -> F {
    let bytes = bytes.as_ref();
    let mut repr = F::Repr::default();
    assert!(bytes.len() <= repr.as_ref().len());
    repr.as_mut()[..bytes.len()].copy_from_slice(bytes);
    F::from_repr(repr).unwrap()
}

pub fn fe_to_fe<F1: PrimeField, F2: PrimeField>(fe: F1) -> F2 {
    debug_assert!(BigUint::from_bytes_le(fe.to_repr().as_ref()) < modulus::<F2>());
    let mut repr = F2::Repr::default();
    repr.as_mut().copy_from_slice(fe.to_repr().as_ref());
    F2::from_repr(repr).unwrap()
}

pub fn fe_truncated<F: PrimeField>(fe: F, num_bits: usize) -> F {
    let (num_bytes, num_bits_last_byte) = div_rem(num_bits, 8);
    let mut repr = fe.to_repr();
    repr.as_mut()[num_bytes + 1..].fill(0);
    repr.as_mut()[num_bytes] &= (1 << num_bits_last_byte) - 1;
    F::from_repr(repr).unwrap()
}

pub fn usize_from_bits_le(bits: &[bool]) -> usize {
    bits.iter()
        .rev()
        .fold(0, |int, bit| (int << 1) + (*bit as usize))
}

pub fn div_rem(dividend: usize, divisor: usize) -> (usize, usize) {
    Integer::div_rem(&dividend, &divisor)
}

pub fn div_ceil(dividend: usize, divisor: usize) -> usize {
    Integer::div_ceil(&dividend, &divisor)
}
