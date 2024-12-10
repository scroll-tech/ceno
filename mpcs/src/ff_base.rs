use ark_ff::{AdditiveGroup, BigInt, Field, LegendreSymbol};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags,
};
use ark_std::{One as ArkOne, Zero};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use ff::{Field as FfField, PrimeField};
use ff_ext::ExtensionField as FfExtField;
use goldilocks::SmallField;
use num_bigint::BigUint;
use rand::distributions::{Distribution, Standard};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    iter::{Product, Sum},
    str::FromStr,
};
use zeroize::Zeroize;

#[derive(
    PartialEq, PartialOrd, Eq, Ord, Default, Copy, Clone, Debug, Hash, Serialize, Deserialize,
)]
pub struct BaseFieldWrapper<E: FfExtField>(pub E::BaseField);

impl<E: FfExtField> BaseFieldWrapper<E> {
    pub fn inner(&self) -> &E::BaseField {
        &self.0
    }

    fn is_zero(&self) -> bool {
        self.inner().is_zero_vartime()
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }

    fn double_in_place(&mut self) {
        self.0 = self.0.double();
    }
}

impl<E: FfExtField> Zero for BaseFieldWrapper<E> {
    fn zero() -> Self {
        Self(E::BaseField::ZERO)
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl<E: FfExtField> ArkOne for BaseFieldWrapper<E> {
    fn one() -> Self {
        Self(E::BaseField::ONE)
    }
}

impl<E: FfExtField> Neg for BaseFieldWrapper<E> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<E: FfExtField> Display for BaseFieldWrapper<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<E: FfExtField> Distribution<BaseFieldWrapper<E>> for Standard
where
    Standard: Distribution<E::BaseField>,
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BaseFieldWrapper<E> {
        BaseFieldWrapper(rng.gen())
    }
}

impl<E: FfExtField> Div for BaseFieldWrapper<E> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        Self(self.0 * other.0.invert().unwrap())
    }
}

impl<'a, E: FfExtField> Div<&'a Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn div(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 * rhs.0.invert().unwrap())
    }
}

impl<'a, E: FfExtField> Div<&'a mut Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn div(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 * rhs.0.invert().unwrap())
    }
}

impl<E: FfExtField> DivAssign<Self> for BaseFieldWrapper<E> {
    fn div_assign(&mut self, other: Self) {
        *self = self.div(&other);
    }
}

impl<'a, E: FfExtField> DivAssign<&'a Self> for BaseFieldWrapper<E> {
    fn div_assign(&mut self, other: &'a Self) {
        *self = self.div(other);
    }
}

impl<'a, E: FfExtField> DivAssign<&'a mut Self> for BaseFieldWrapper<E> {
    fn div_assign(&mut self, other: &'a mut Self) {
        *self = self.div(other)
    }
}

macro_rules! impl_from_u_for_extension_field_wrapper {
    ($type: ty) => {
        impl<E: FfExtField> From<$type> for BaseFieldWrapper<E> {
            fn from(b: $type) -> Self {
                Self(E::BaseField::from(b.into()))
            }
        }
    };
}

impl<E: FfExtField> From<u128> for BaseFieldWrapper<E> {
    fn from(_: u128) -> Self {
        panic!("Shouldn't be called. SmallField is too small to hold u128.")
    }
}

impl_from_u_for_extension_field_wrapper!(u8);
impl_from_u_for_extension_field_wrapper!(u16);
impl_from_u_for_extension_field_wrapper!(u32);
impl_from_u_for_extension_field_wrapper!(u64);
impl_from_u_for_extension_field_wrapper!(bool);

macro_rules! impl_from_i_for_extension_field_wrapper {
    ($type: ty) => {
        impl<E: FfExtField> From<$type> for BaseFieldWrapper<E> {
            fn from(b: $type) -> Self {
                if b >= 0 {
                    Self(E::BaseField::from(b as u64))
                } else {
                    -Self(E::BaseField::from(-b as u64))
                }
            }
        }
    };
}
impl_from_i_for_extension_field_wrapper!(i8);
impl_from_i_for_extension_field_wrapper!(i16);
impl_from_i_for_extension_field_wrapper!(i32);
impl_from_i_for_extension_field_wrapper!(i64);

impl<E: FfExtField> From<i128> for BaseFieldWrapper<E> {
    fn from(_: i128) -> Self {
        panic!("Shouldn't be called. SmallField is too small to hold i128.")
    }
}

impl<E: FfExtField> AdditiveGroup for BaseFieldWrapper<E>
where
    Standard: Distribution<E::BaseField>,
{
    type Scalar = Self;

    const ZERO: Self = Self(<E::BaseField as FfField>::ZERO);

    fn double(&self) -> Self {
        self.double()
    }

    fn double_in_place(&mut self) -> &mut Self {
        self.double_in_place();
        self
    }

    fn neg_in_place(&mut self) -> &mut Self {
        self.0 = -self.0;
        self
    }
}

impl<E: FfExtField> FromStr for BaseFieldWrapper<E> {
    type Err = ();

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<E: FfExtField> From<BigUint> for BaseFieldWrapper<E> {
    fn from(b: BigUint) -> Self {
        Self(E::BaseField::from(b.to_u64_digits()[0]))
    }
}

impl<E: FfExtField> Into<BigUint> for BaseFieldWrapper<E> {
    fn into(self) -> BigUint {
        BigUint::from(self.0.to_canonical_u64())
    }
}

impl<E: FfExtField> From<BigInt<1>> for BaseFieldWrapper<E> {
    fn from(b: BigInt<1>) -> Self {
        Self(E::BaseField::from(b.0[0]))
    }
}

impl<E: FfExtField> Into<BigInt<1>> for BaseFieldWrapper<E> {
    fn into(self) -> BigInt<1> {
        BigInt([self.0.to_canonical_u64()])
    }
}

impl<E: FfExtField> ark_ff::PrimeField for BaseFieldWrapper<E>
where
    Standard: Distribution<E::BaseField>,
{
    type BigInt = BigInt<1>;

    const MODULUS: Self::BigInt = Self::BigInt::new([E::BaseField::MODULUS_U64]);

    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInt =
        Self::BigInt::new([(E::BaseField::MODULUS_U64 - 1) / 2]);

    const MODULUS_BIT_SIZE: u32 = 64;

    const TRACE: Self::BigInt =
        Self::BigInt::new([(E::BaseField::MODULUS_U64 - 1) / (1 << E::BaseField::S)]);

    const TRACE_MINUS_ONE_DIV_TWO: Self::BigInt =
        Self::BigInt::new([((E::BaseField::MODULUS_U64 - 1) / (1 << E::BaseField::S) - 1) / 2]);

    fn from_bigint(repr: Self::BigInt) -> Option<Self> {
        Some(Self::from(repr))
    }

    fn into_bigint(self) -> Self::BigInt {
        self.into()
    }
}

impl<E: FfExtField> Field for BaseFieldWrapper<E>
where
    Standard: Distribution<E::BaseField>,
{
    type BasePrimeField = Self;
    const SQRT_PRECOMP: Option<ark_ff::SqrtPrecomputation<Self>> = None;
    const ONE: Self = Self(<E::BaseField as FfField>::ONE);

    fn extension_degree() -> u64 {
        1
    }

    fn to_base_prime_field_elements(
        &self,
    ) -> impl Iterator<Item = <Self as ark_ff::Field>::BasePrimeField> {
        std::iter::once(*self)
    }

    fn from_base_prime_field_elems(
        elems: impl IntoIterator<Item = Self::BasePrimeField>,
    ) -> Option<Self> {
        elems.into_iter().next()
    }

    fn from_base_prime_field(elem: Self::BasePrimeField) -> Self {
        elem
    }

    fn legendre(&self) -> LegendreSymbol {
        todo!()
    }

    fn square(&self) -> Self {
        Self(self.0.square())
    }

    fn square_in_place(&mut self) -> &mut Self {
        self.0 = self.0.square();
        self
    }

    fn inverse(&self) -> Option<Self> {
        self.0.invert().map(Self).into_option()
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        if let Some(v) = self.0.invert().into_option() {
            self.0 = v;
            Some(self)
        } else {
            None
        }
    }

    fn frobenius_map_in_place(&mut self, power: usize) {
        self.0 = self.0.pow([power as u64])
    }

    fn mul_by_base_prime_field(&self, elem: &Self::BasePrimeField) -> Self {
        Self(self.0 * elem.0)
    }

    fn characteristic() -> &'static [u64] {
        &[E::BaseField::MODULUS_U64]
    }

    fn from_random_bytes_with_flags<F: Flags>(_bytes: &[u8]) -> Option<(Self, F)> {
        todo!()
    }

    fn sqrt(&self) -> Option<Self> {
        match Self::SQRT_PRECOMP {
            Some(tv) => tv.sqrt(self),
            None => std::unimplemented!(),
        }
    }

    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        (*self).sqrt().map(|sqrt| {
            *self = sqrt;
            self
        })
    }

    fn sum_of_products<const T: usize>(a: &[Self; T], b: &[Self; T]) -> Self {
        let mut sum = Self::zero();
        for i in 0..a.len() {
            sum += a[i] * b[i];
        }
        sum
    }

    fn frobenius_map(&self, power: usize) -> Self {
        let mut this = *self;
        this.frobenius_map_in_place(power);
        this
    }

    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        Self(self.0.pow(exp))
    }

    fn pow_with_table<S: AsRef<[u64]>>(powers_of_2: &[Self], exp: S) -> Option<Self> {
        let mut res = E::BaseField::ONE;
        for (pow, bit) in ark_ff::BitIteratorLE::without_trailing_zeros(exp).enumerate() {
            if bit {
                res *= powers_of_2.get(pow)?.0;
            }
        }
        Some(Self(res))
    }
}

impl<E: FfExtField> ark_ff::FftField for BaseFieldWrapper<E>
where
    Standard: Distribution<E::BaseField>,
{
    const GENERATOR: Self = Self(<E::BaseField as PrimeField>::MULTIPLICATIVE_GENERATOR);
    const TWO_ADICITY: u32 = <E::BaseField as PrimeField>::S;
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self(<E::BaseField as PrimeField>::ROOT_OF_UNITY);
    const SMALL_SUBGROUP_BASE: Option<u32> = None;
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = None;
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Self> = None;
}

impl<E: FfExtField> Zeroize for BaseFieldWrapper<E> {
    fn zeroize(&mut self) {
        self.0 = E::BaseField::ZERO;
    }
}

impl<E: FfExtField> Add for BaseFieldWrapper<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<E: FfExtField> AddAssign for BaseFieldWrapper<E> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<E: FfExtField> Mul for BaseFieldWrapper<E> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<E: FfExtField> MulAssign for BaseFieldWrapper<E> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<E: FfExtField> Sub for BaseFieldWrapper<E> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<E: FfExtField> SubAssign for BaseFieldWrapper<E> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl<'a, E: FfExtField> Add<&'a Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a, E: FfExtField> Add<&'a mut Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn add(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a, E: FfExtField> Sub<&'a mut Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn sub(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a, E: FfExtField> Sub<&'a Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a, E: FfExtField> Mul<&'a Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn mul(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<'a, E: FfExtField> Mul<&'a mut Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn mul(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<'a, E: FfExtField> AddAssign<&'a Self> for BaseFieldWrapper<E> {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 += rhs.0;
    }
}

impl<'a, E: FfExtField> AddAssign<&'a mut Self> for BaseFieldWrapper<E> {
    fn add_assign(&mut self, rhs: &'a mut Self) {
        self.0 += rhs.0;
    }
}

impl<'a, E: FfExtField> SubAssign<&'a Self> for BaseFieldWrapper<E> {
    fn sub_assign(&mut self, rhs: &'a Self) {
        self.0 -= rhs.0;
    }
}

impl<'a, E: FfExtField> SubAssign<&'a mut Self> for BaseFieldWrapper<E> {
    fn sub_assign(&mut self, rhs: &'a mut Self) {
        self.0 -= rhs.0;
    }
}

impl<'a, E: FfExtField> MulAssign<&'a Self> for BaseFieldWrapper<E> {
    fn mul_assign(&mut self, rhs: &'a Self) {
        self.0 *= rhs.0;
    }
}

impl<'a, E: FfExtField> MulAssign<&'a mut Self> for BaseFieldWrapper<E> {
    fn mul_assign(&mut self, rhs: &'a mut Self) {
        self.0 *= rhs.0;
    }
}

impl<E: FfExtField> Sum for BaseFieldWrapper<E> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(E::BaseField::ZERO), |acc, x| Self(acc.0 + x.0))
    }
}

impl<'a, E: FfExtField> Sum<&'a Self> for BaseFieldWrapper<E> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self(E::BaseField::ZERO), |acc, x| Self(acc.0 + x.0))
    }
}

impl<E: FfExtField> Product for BaseFieldWrapper<E> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(E::BaseField::ONE), |acc, x| Self(acc.0 * x.0))
    }
}

impl<'a, E: FfExtField> Product<&'a Self> for BaseFieldWrapper<E> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self(E::BaseField::ONE), |acc, x| Self(acc.0 * x.0))
    }
}

impl<E: FfExtField> ark_serialize::Valid for BaseFieldWrapper<E> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl<E: FfExtField> CanonicalSerialize for BaseFieldWrapper<E> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        _writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        todo!()
    }
}

impl<E: FfExtField> CanonicalDeserialize for BaseFieldWrapper<E> {
    fn deserialize_with_mode<R: std::io::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        todo!()
    }
}

impl<E: FfExtField> CanonicalSerializeWithFlags for BaseFieldWrapper<E> {
    fn serialize_with_flags<W: ark_serialize::Write, F: ark_serialize::Flags>(
        &self,
        _writer: W,
        _flags: F,
    ) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }

    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        todo!()
    }
}

impl<E: FfExtField> CanonicalDeserializeWithFlags for BaseFieldWrapper<E> {
    fn deserialize_with_flags<R: std::io::Read, F: ark_serialize::Flags>(
        _reader: R,
    ) -> Result<(Self, F), ark_serialize::SerializationError> {
        todo!()
    }
}
