use ark_ff::{AdditiveGroup, BigInt, Field, LegendreSymbol};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags,
};
use ark_std::{One as ArkOne, Zero};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use ff_ext::{ExtensionField as FfExtField, SmallField};
use num_bigint::BigUint;
use p3_field::{Field as FfField, FieldAlgebra};
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
        self.inner().is_zero()
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

impl<E: FfExtField> Distribution<BaseFieldWrapper<E>> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BaseFieldWrapper<E> {
        BaseFieldWrapper(E::BaseField::from_canonical_u64(rng.gen::<u64>()))
    }
}

impl<E: FfExtField> Div for BaseFieldWrapper<E> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        Self(self.0 * other.0.inverse())
    }
}

impl<'a, E: FfExtField> Div<&'a Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn div(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 * rhs.0.inverse())
    }
}

impl<'a, E: FfExtField> Div<&'a mut Self> for BaseFieldWrapper<E> {
    type Output = Self;

    fn div(self, rhs: &'a mut Self) -> Self::Output {
        Self(self.0 * rhs.0.inverse())
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

impl<E: FfExtField> From<usize> for BaseFieldWrapper<E> {
    fn from(b: usize) -> Self {
        Self(E::BaseField::from_canonical_usize(b.into()))
    }
}

macro_rules! impl_from_u_for_extension_field_wrapper {
    ($type: ty) => {
        impl<E: FfExtField> From<$type> for BaseFieldWrapper<E> {
            fn from(b: $type) -> Self {
                Self::from(b as usize)
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
                    Self::from(b as usize)
                } else {
                    -Self::from((-b) as usize)
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

impl<E: FfExtField> AdditiveGroup for BaseFieldWrapper<E> {
    type Scalar = Self;

    const ZERO: Self = Self(<E::BaseField as FieldAlgebra>::ZERO);

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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(u64::from_str(s).map_err(|_| ())?))
    }
}

impl<E: FfExtField> From<BigUint> for BaseFieldWrapper<E> {
    fn from(b: BigUint) -> Self {
        Self::from(b.to_u64_digits()[0])
    }
}

impl<E: FfExtField> Into<BigUint> for BaseFieldWrapper<E> {
    fn into(self) -> BigUint {
        BigUint::from(self.0.to_canonical_u64())
    }
}

impl<E: FfExtField> From<BigInt<1>> for BaseFieldWrapper<E> {
    fn from(b: BigInt<1>) -> Self {
        Self::from(b.0[0])
    }
}

impl<E: FfExtField> Into<BigInt<1>> for BaseFieldWrapper<E> {
    fn into(self) -> BigInt<1> {
        BigInt([self.0.to_canonical_u64()])
    }
}

impl<E: FfExtField> ark_ff::PrimeField for BaseFieldWrapper<E> {
    type BigInt = BigInt<1>;

    const MODULUS: Self::BigInt = Self::BigInt::new([E::BaseField::MODULUS_U64]);

    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInt =
        Self::BigInt::new([(E::BaseField::MODULUS_U64 - 1) / 2]);

    const MODULUS_BIT_SIZE: u32 = 64;

    const TRACE: Self::BigInt =
        Self::BigInt::new([(E::BaseField::MODULUS_U64 - 1) / (1 << E::TWO_ADICITY)]);

    const TRACE_MINUS_ONE_DIV_TWO: Self::BigInt =
        Self::BigInt::new([((E::BaseField::MODULUS_U64 - 1) / (1 << E::TWO_ADICITY) - 1) / 2]);

    fn from_bigint(repr: Self::BigInt) -> Option<Self> {
        Some(Self::from(repr))
    }

    fn into_bigint(self) -> Self::BigInt {
        self.into()
    }
}

impl<E: FfExtField> Field for BaseFieldWrapper<E> {
    type BasePrimeField = Self;
    const SQRT_PRECOMP: Option<ark_ff::SqrtPrecomputation<Self>> = None;
    const ONE: Self = Self(<E::BaseField as FieldAlgebra>::ONE);

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

    #[inline]
    fn legendre(&self) -> LegendreSymbol {
        use ark_ff::fields::LegendreSymbol::*;

        // s = self^((MODULUS - 1) // 2)
        let s = self.pow(<Self as ark_ff::PrimeField>::MODULUS_MINUS_ONE_DIV_TWO);
        if s.is_zero() {
            Zero
        } else if s.is_one() {
            QuadraticResidue
        } else {
            QuadraticNonResidue
        }
    }

    fn square(&self) -> Self {
        Self(self.0.square())
    }

    fn square_in_place(&mut self) -> &mut Self {
        self.0 = self.0.square();
        self
    }

    fn inverse(&self) -> Option<Self> {
        Some(Self(self.0.inverse()))
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        self.0 = self.0.inverse();
        Some(self)
    }

    /// The Frobenius map has no effect in a prime field.
    #[inline]
    fn frobenius_map_in_place(&mut self, _: usize) {}

    fn mul_by_base_prime_field(&self, elem: &Self::BasePrimeField) -> Self {
        Self(self.0 * elem.0)
    }

    fn characteristic() -> &'static [u64] {
        &[E::BaseField::MODULUS_U64]
    }

    #[inline]
    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        if F::BIT_SIZE > 8 {
            None
        } else {
            let mut bytes_filled = [0u8; 8];
            bytes_filled[0..8.min(bytes.len())].copy_from_slice(&bytes[0..8.min(bytes.len())]);
            let bytes = bytes_filled;

            let shave_bits = 0;
            // This mask retains everything in the last limb
            // that is below `P::MODULUS_BIT_SIZE`.
            let last_limb_mask =
                (u64::MAX.checked_shr(shave_bits as u32).unwrap_or(0)).to_le_bytes();
            let mut last_bytes_mask = [0u8; 9];
            last_bytes_mask[..8].copy_from_slice(&last_limb_mask);

            let mut bytes_with_flag = [0u8; 9];
            bytes_with_flag[0..8].copy_from_slice(&bytes);

            // Length of the buffer containing the field element and the flag.
            let output_byte_size = ark_serialize::buffer_byte_size(64 + F::BIT_SIZE);
            // Location of the flag is the last byte of the serialized
            // form of the field element.
            let flag_location = output_byte_size - 1;

            // At which byte is the flag located in the last limb?
            let flag_location_in_last_limb = flag_location;

            // Take all but the last 9 bytes.
            let last_bytes = bytes_with_flag.iter_mut();

            // The mask only has the last `F::BIT_SIZE` bits set
            let flags_mask = u8::MAX.checked_shl(8 - (F::BIT_SIZE as u32)).unwrap_or(0);

            // Mask away the remaining bytes, and try to reconstruct the
            // flag
            let mut flags: u8 = 0;
            for (i, (b, m)) in last_bytes.zip(&last_bytes_mask).enumerate() {
                if i == flag_location_in_last_limb {
                    flags = *b & flags_mask
                }
                *b &= m;
            }
            Self::deserialize_compressed(&bytes[..8.min(bytes.len())])
                .ok()
                .and_then(|f| F::from_u8(flags).map(|flag| (f, flag)))
        }
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

impl<E: FfExtField> ark_ff::FftField for BaseFieldWrapper<E> {
    const GENERATOR: Self = Self(<E::BaseField as p3_field::Field>::GENERATOR);
    const TWO_ADICITY: u32 = E::TWO_ADICITY as u32;
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self(E::BASE_TWO_ADIC_ROOT_OF_UNITY);
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
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0
            .to_canonical_u64()
            .serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.0.to_canonical_u64().serialized_size(compress)
    }
}

impl<E: FfExtField> CanonicalDeserialize for BaseFieldWrapper<E> {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Ok(Self(E::BaseField::from_canonical_u64(
            <u64 as CanonicalDeserialize>::deserialize_with_mode(reader, compress, validate)
                .unwrap(),
        )))
    }
}

impl<E: FfExtField> CanonicalSerializeWithFlags for BaseFieldWrapper<E> {
    fn serialize_with_flags<W: ark_serialize::Write, F: ark_serialize::Flags>(
        &self,
        mut writer: W,
        flags: F,
    ) -> Result<(), ark_serialize::SerializationError> {
        // All reasonable `Flags` should be less than 8 bits in size
        // (256 values are enough for anyone!)
        if F::BIT_SIZE > 8 {
            return Err(ark_serialize::SerializationError::NotEnoughSpace);
        }

        writer.write_all(self.0.to_canonical_u64().to_le_bytes().as_ref())?;
        if F::BIT_SIZE > 0 {
            writer.write_all(&[flags.u8_bitmask()])?;
        }
        Ok(())
    }

    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        ark_serialize::buffer_byte_size(64 as usize + F::BIT_SIZE)
    }
}

impl<E: FfExtField> CanonicalDeserializeWithFlags for BaseFieldWrapper<E> {
    fn deserialize_with_flags<R: std::io::Read, F: ark_serialize::Flags>(
        mut reader: R,
    ) -> Result<(Self, F), ark_serialize::SerializationError> {
        // All reasonable `Flags` should be less than 8 bits in size
        // (256 values are enough for anyone!)
        if F::BIT_SIZE > 8 {
            return Err(ark_serialize::SerializationError::NotEnoughSpace);
        }
        // Calculate the number of bytes required to represent a field element
        // serialized with `flags`.
        let output_byte_size = Self::zero().serialized_size_with_flags::<F>();
        let mut masked_bytes = vec![0u8; output_byte_size];
        reader.read_exact(masked_bytes.as_mut_slice())?;

        let flags = F::from_u8_remove_flags(&mut masked_bytes[output_byte_size - 1])
            .ok_or(ark_serialize::SerializationError::UnexpectedFlags)?;

        Ok((
            Self(E::BaseField::from_canonical_u64(u64::from_le_bytes(
                masked_bytes[0..8]
                    .try_into()
                    .map_err(|_| ark_serialize::SerializationError::InvalidData)?,
            ))),
            flags,
        ))
    }
}
