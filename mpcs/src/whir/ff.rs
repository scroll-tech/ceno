use ark_ff::{AdditiveGroup, Field, LegendreSymbol};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags,
};
use ark_std::{One as ArkOne, Zero};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use ff::{Field as FfField, PrimeField};
use ff_ext::ExtensionField as FfExtField;
use rand::distributions::{Distribution, Standard};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    iter::{Product, Sum},
    str::FromStr,
};
use zeroize::Zeroize;

use super::ff_base::BaseFieldWrapper;

#[derive(
    PartialEq, PartialOrd, Eq, Ord, Default, Copy, Clone, Debug, Hash, Serialize, Deserialize,
)]
pub struct ExtensionFieldWrapper<E: FfExtField>(E);

impl<E: FfExtField> ExtensionFieldWrapper<E> {
    pub fn inner(&self) -> &E {
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

    fn square(&self) -> Self {
        Self(self.0.square())
    }

    fn square_in_place(&mut self) {
        self.0 = self.0.square();
    }

    fn norm(&self) -> BaseFieldWrapper<E> {
        assert!(E::DEGREE == 2);
        // t1 = c0.square() - P::NON_RESIDUE * c1^2
        let bases = self.0.as_bases();
        let mut result = bases[1].square();
        Self::sub_and_mul_base_field_by_nonresidue(&mut result, &bases[0].square());
        BaseFieldWrapper(result)
    }

    /// A specializable method for multiplying an element of the base field by
    /// the quadratic non-residue. This is used in Karatsuba multiplication
    /// and in complex squaring.
    #[inline(always)]
    fn mul_base_field_by_nonresidue_in_place(fe: &mut E::BaseField) -> &mut E::BaseField {
        *fe *= &E::NONRESIDUE;
        fe
    }

    /// A specializable method for computing x - mul_base_field_by_nonresidue(y)
    /// This allows for optimizations when the non-residue is
    /// canonically negative in the field.
    #[inline(always)]
    fn sub_and_mul_base_field_by_nonresidue(y: &mut E::BaseField, x: &E::BaseField) {
        Self::mul_base_field_by_nonresidue_in_place(y);
        let mut result = *x;
        result -= &*y;
        *y = result;
    }
}

impl<E: FfExtField> Zero for ExtensionFieldWrapper<E> {
    fn zero() -> Self {
        Self(E::ZERO)
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl<E: FfExtField> ArkOne for ExtensionFieldWrapper<E> {
    fn one() -> Self {
        Self(E::ONE)
    }
}

impl<E: FfExtField> Neg for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<E: FfExtField> Display for ExtensionFieldWrapper<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<E: FfExtField> Distribution<ExtensionFieldWrapper<E>> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> ExtensionFieldWrapper<E> {
        let mut limbs = vec![E::BaseField::ZERO; E::DEGREE];
        for limb in &mut limbs {
            let v: BaseFieldWrapper<E> = rng.gen();
            *limb = v.0;
        }
        ExtensionFieldWrapper(E::from_limbs(&limbs))
    }
}

impl<E: FfExtField> Div for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        Self(self.0 * other.0.invert().unwrap())
    }
}

impl<'a, E: FfExtField> Div<&'a Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn div(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 * rhs.0.invert().unwrap())
    }
}

impl<'a, E: FfExtField> Div<&'a mut Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn div(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 * rhs.0.invert().unwrap())
    }
}

impl<E: FfExtField> DivAssign<Self> for ExtensionFieldWrapper<E> {
    fn div_assign(&mut self, other: Self) {
        *self = self.div(&other);
    }
}

impl<'a, E: FfExtField> DivAssign<&'a Self> for ExtensionFieldWrapper<E> {
    fn div_assign(&mut self, other: &'a Self) {
        *self = self.div(other);
    }
}

impl<'a, E: FfExtField> DivAssign<&'a mut Self> for ExtensionFieldWrapper<E> {
    fn div_assign(&mut self, other: &'a mut Self) {
        *self = self.div(other)
    }
}

macro_rules! impl_from_u_for_extension_field_wrapper {
    ($type: ty) => {
        impl<E: FfExtField> From<$type> for ExtensionFieldWrapper<E> {
            fn from(b: $type) -> Self {
                Self(E::from(E::BaseField::from(b.into())))
            }
        }
    };
}

impl<E: FfExtField> From<u128> for ExtensionFieldWrapper<E> {
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
        impl<E: FfExtField> From<$type> for ExtensionFieldWrapper<E> {
            fn from(b: $type) -> Self {
                if b >= 0 {
                    Self(E::from(E::BaseField::from(b as u64)))
                } else {
                    -Self(E::from(E::BaseField::from(-b as u64)))
                }
            }
        }
    };
}
impl_from_i_for_extension_field_wrapper!(i8);
impl_from_i_for_extension_field_wrapper!(i16);
impl_from_i_for_extension_field_wrapper!(i32);
impl_from_i_for_extension_field_wrapper!(i64);

impl<E: FfExtField> From<i128> for ExtensionFieldWrapper<E> {
    fn from(_: i128) -> Self {
        panic!("Shouldn't be called. SmallField is too small to hold i128.")
    }
}

impl<E: FfExtField> AdditiveGroup for ExtensionFieldWrapper<E> {
    type Scalar = Self;

    const ZERO: Self = Self(<E as FfField>::ZERO);

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

impl<E: FfExtField> Field for ExtensionFieldWrapper<E> {
    type BasePrimeField = BaseFieldWrapper<E>;
    const SQRT_PRECOMP: Option<ark_ff::SqrtPrecomputation<Self>> = None;
    const ONE: Self = Self(<E as FfField>::ONE);

    fn extension_degree() -> u64 {
        E::DEGREE as u64
    }

    fn to_base_prime_field_elements(
        &self,
    ) -> impl Iterator<Item = <Self as ark_ff::Field>::BasePrimeField> {
        self.0.as_bases().iter().copied().map(BaseFieldWrapper)
    }

    fn from_base_prime_field_elems(
        elems: impl IntoIterator<Item = Self::BasePrimeField>,
    ) -> Option<Self> {
        Some(Self(E::from_bases(
            elems
                .into_iter()
                .map(|e| e.0)
                .collect::<Vec<_>>()
                .as_slice(),
        )))
    }

    fn from_base_prime_field(elem: Self::BasePrimeField) -> Self {
        Self(E::from(elem.0))
    }

    fn legendre(&self) -> LegendreSymbol {
        // The LegendreSymbol in a field of order q for an element x can be
        // computed as x^((q-1)/2).
        // Since we are in a quadratic extension of a field F_p,
        // we have that q = p^2.
        // Notice then that (q-1)/2 = ((p-1)/2) * (1 + p).
        // This implies that we can compute the symbol as (x^(1+p))^((p-1)/2).
        // Recall that computing x^(1 + p) is equivalent to taking the norm of x,
        // and it will output an element in the base field F_p.
        // Then exponentiating by (p-1)/2 in the base field is equivalent to computing
        // the legendre symbol in the base field.
        self.norm().legendre()
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn square_in_place(&mut self) -> &mut Self {
        self.square_in_place();
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

    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        let split_at = bytes.len() / 2;
        if let Some(c0) = BaseFieldWrapper::<E>::from_random_bytes(&bytes[..split_at]) {
            if let Some((c1, flags)) =
                BaseFieldWrapper::<E>::from_random_bytes_with_flags(&bytes[split_at..])
            {
                return Some((Self(E::from_bases(&[c0.0, c1.0])), flags));
            }
        }
        None
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
        let mut res = E::ONE;
        for (pow, bit) in ark_ff::BitIteratorLE::without_trailing_zeros(exp).enumerate() {
            if bit {
                res *= powers_of_2.get(pow)?.0;
            }
        }
        Some(Self(res))
    }
}

impl<E: FfExtField> ark_ff::FftField for ExtensionFieldWrapper<E> {
    const GENERATOR: Self = Self(<E as FfExtField>::MULTIPLICATIVE_GENERATOR);
    const TWO_ADICITY: u32 = <E::BaseField as PrimeField>::S;
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self(E::TWO_ADIC_ROOT_OF_UNITY);
    const SMALL_SUBGROUP_BASE: Option<u32> = None;
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = None;
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Self> = None;
}

impl<E: FfExtField> Zeroize for ExtensionFieldWrapper<E> {
    fn zeroize(&mut self) {
        self.0 = E::ZERO;
    }
}

impl<E: FfExtField> Add for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<E: FfExtField> AddAssign for ExtensionFieldWrapper<E> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<E: FfExtField> Mul for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<E: FfExtField> MulAssign for ExtensionFieldWrapper<E> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<E: FfExtField> Sub for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<E: FfExtField> SubAssign for ExtensionFieldWrapper<E> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl<'a, E: FfExtField> Add<&'a Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a, E: FfExtField> Add<&'a mut Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn add(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<'a, E: FfExtField> Sub<&'a mut Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn sub(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a, E: FfExtField> Sub<&'a Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<'a, E: FfExtField> Mul<&'a Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn mul(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<'a, E: FfExtField> Mul<&'a mut Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn mul(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<'a, E: FfExtField> AddAssign<&'a Self> for ExtensionFieldWrapper<E> {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 += rhs.0;
    }
}

impl<'a, E: FfExtField> AddAssign<&'a mut Self> for ExtensionFieldWrapper<E> {
    fn add_assign(&mut self, rhs: &'a mut Self) {
        self.0 += rhs.0;
    }
}

impl<'a, E: FfExtField> SubAssign<&'a Self> for ExtensionFieldWrapper<E> {
    fn sub_assign(&mut self, rhs: &'a Self) {
        self.0 -= rhs.0;
    }
}

impl<'a, E: FfExtField> SubAssign<&'a mut Self> for ExtensionFieldWrapper<E> {
    fn sub_assign(&mut self, rhs: &'a mut Self) {
        self.0 -= rhs.0;
    }
}

impl<'a, E: FfExtField> MulAssign<&'a Self> for ExtensionFieldWrapper<E> {
    fn mul_assign(&mut self, rhs: &'a Self) {
        self.0 *= rhs.0;
    }
}

impl<'a, E: FfExtField> MulAssign<&'a mut Self> for ExtensionFieldWrapper<E> {
    fn mul_assign(&mut self, rhs: &'a mut Self) {
        self.0 *= rhs.0;
    }
}

impl<E: FfExtField> Sum for ExtensionFieldWrapper<E> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(E::ZERO), |acc, x| Self(acc.0 + x.0))
    }
}

impl<'a, E: FfExtField> Sum<&'a Self> for ExtensionFieldWrapper<E> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self(E::ZERO), |acc, x| Self(acc.0 + x.0))
    }
}

impl<E: FfExtField> Product for ExtensionFieldWrapper<E> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(E::ONE), |acc, x| Self(acc.0 * x.0))
    }
}

impl<'a, E: FfExtField> Product<&'a Self> for ExtensionFieldWrapper<E> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self(E::ONE), |acc, x| Self(acc.0 * x.0))
    }
}

impl<E: FfExtField> FromStr for ExtensionFieldWrapper<E>
where
    E: FromStr,
{
    type Err = E::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        E::from_str(s).map(Self)
    }
}

impl<E: FfExtField> ark_serialize::Valid for ExtensionFieldWrapper<E> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl<E: FfExtField> CanonicalSerialize for ExtensionFieldWrapper<E> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.serialize_with_flags(writer, ark_serialize::EmptyFlags)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        self.serialized_size_with_flags::<ark_serialize::EmptyFlags>()
    }
}

impl<E: FfExtField> CanonicalDeserialize for ExtensionFieldWrapper<E> {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let c0: BaseFieldWrapper<E> =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c1: BaseFieldWrapper<E> =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self(E::from_bases(&[c0.0, c1.0])))
    }
}

impl<E: FfExtField> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    fn serialize_with_flags<W: ark_serialize::Write, F: ark_serialize::Flags>(
        &self,
        mut writer: W,
        flags: F,
    ) -> Result<(), ark_serialize::SerializationError> {
        let bases = self.0.as_bases();
        BaseFieldWrapper::<E>(bases[0]).serialize_compressed(&mut writer)?;
        BaseFieldWrapper::<E>(bases[1]).serialize_with_flags(&mut writer, flags)?;
        Ok(())
    }

    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        let bases = self.0.as_bases();
        BaseFieldWrapper::<E>(bases[0]).compressed_size()
            + BaseFieldWrapper::<E>(bases[1]).serialized_size_with_flags::<F>()
    }
}

impl<E: FfExtField> CanonicalDeserializeWithFlags for ExtensionFieldWrapper<E> {
    fn deserialize_with_flags<R: std::io::Read, F: ark_serialize::Flags>(
        mut reader: R,
    ) -> Result<(Self, F), ark_serialize::SerializationError> {
        let c0: BaseFieldWrapper<E> = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
        let (c1, flags): (BaseFieldWrapper<E>, F) =
            CanonicalDeserializeWithFlags::deserialize_with_flags(&mut reader)?;
        Ok((Self(E::from_bases(&[c0.0, c1.0])), flags))
    }
}
