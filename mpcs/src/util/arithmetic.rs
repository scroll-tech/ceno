use ctr;
use crate::util::{BigUint, Itertools, new_fields::{Mersenne127,Mersenne61}};
use halo2_curves::{
    bn256, grumpkin,
    pairing::{self, MillerLoopResult},
    pasta::{pallas, vesta},
};
use num_integer::Integer;
use std::{borrow::Borrow, fmt::Debug, iter};

mod bh;
mod msm;

pub use bh::BooleanHypercube;
pub use bitvec::field::BitField;
pub use halo2_curves::{
    group::{
        ff::{BatchInvert, Field, FromUniformBytes, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group,
    },
    Coordinates, CurveAffine, CurveExt,
};
pub use msm::{fixed_base_msm, variable_base_msm, window_size, window_table};




pub trait MultiMillerLoop: pairing::MultiMillerLoop + Debug + Sync {
    fn pairings_product_is_identity(terms: &[(&Self::G1Affine, &Self::G2Prepared)]) -> bool {
        Self::multi_miller_loop(terms)
            .final_exponentiation()
            .is_identity()
            .into()
    }
}

impl<M> MultiMillerLoop for M where M: pairing::MultiMillerLoop + Debug + Sync {}

pub trait TwoChainCurve: CurveAffine {
    type Secondary: TwoChainCurve<ScalarExt = Self::Base, Base = Self::ScalarExt, Secondary = Self>;
}

impl TwoChainCurve for bn256::G1Affine {
    type Secondary = grumpkin::G1Affine;
}

impl TwoChainCurve for grumpkin::G1Affine {
    type Secondary = bn256::G1Affine;
}

impl TwoChainCurve for pallas::Affine {
    type Secondary = vesta::Affine;
}

impl TwoChainCurve for vesta::Affine {
    type Secondary = pallas::Affine;
}

pub fn field_size<F: PrimeField>() -> usize {
    let neg_one = (-F::ONE).to_repr();
    let bytes = neg_one.as_ref();
    8 * bytes.len() - bytes.last().unwrap().leading_zeros() as usize
}

pub fn horner_new<F: Field>(coeffs: &[F], x: &F) -> F {
    let coeff_vec:Vec<&F> = coeffs
        .iter()
        .rev()
	.collect();
    let mut acc = F::ZERO;
    for c in coeff_vec{
	acc = acc*x + c;
    }
    acc
    //2
    //.fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

pub fn horner<F: Field>(coeffs: &[F], x: &F) -> F {
    let coeff_vec:Vec<&F> = coeffs
        .iter()
        .rev()
	.collect();
    let mut acc = F::ZERO;
    for c in coeff_vec{
	acc = acc*x + c;
    }
    acc
    //2
    //.fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

pub fn horner_orig<F: Field>(coeffs: &[F], x: &F) -> F {
    coeffs
        .iter()
        .rev()
	.fold(F::ZERO, |acc, coeff| acc * x + coeff)
}
#[test]
fn bench_horner(){
    use rand::{rngs::OsRng, Rng};
    use std::time::Instant;
    use crate::poly::{Polynomial,multilinear::MultilinearPolynomial};
    let poly = MultilinearPolynomial::rand(10, OsRng);
    let test1 = Instant::now();
    horner_orig(&poly.evals()[..],&Mersenne61::ONE);
    println!("orig {:?}", test1.elapsed());

    let test2 = Instant::now();
    horner_new(&poly.evals()[..],&Mersenne61::ONE);
    println!("new {:?}", test2.elapsed());
    

    
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

#[cfg(test)]
mod test {
    use crate::util::arithmetic;
    use halo2_curves::bn256;

    #[test]
    fn field_size() {
        assert_eq!(arithmetic::field_size::<bn256::Fr>(), 254);
    }
}
