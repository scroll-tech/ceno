use ark_ff::{AdditiveGroup, FftField, Field, LegendreSymbol, One};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Compress, EmptyFlags, Flags, SerializationError, Validate,
};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use ff_ext::ExtensionField;
use std::{
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    iter::Sum,
};
use zeroize::Zeroize;

#[derive(PartialEq, PartialOrd, Eq, Ord, Default, Copy, Clone, Debug, Hash)]
pub struct ExtensionFieldWrapper<E: ExtensionField>(E);

impl<E: ExtensionField> ExtensionFieldWrapper<E> {
    pub fn inner(&self) -> &E {
        &self.0
    }
}

impl<E: ExtensionField> std::iter::Product for ExtensionFieldWrapper<E> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        E::product(iter.map(|x| x.0))
    }
}

impl<'a, E: ExtensionField> std::iter::Product<&'a Self> for ExtensionFieldWrapper<E> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        E::product(iter.map(|x| x.0))
    }
}

macro_rules! impl_from_for_extension_field_wrapper {
    ($type: ty) => {
        impl<E: ExtensionField> From<$type> for ExtensionFieldWrapper<E> {
            fn from(b: $type) -> Self {
                Self(E::from(b))
            }
        }
    };
}

impl<E: ExtensionField> Div for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        Self(self.0 / other.0)
    }
}

impl<'a, E: ExtensionField> Div<&'a Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn div(self, other: &'a Self) -> Self {
        Self(self.0 / other.0)
    }
}

impl<'a, E: ExtensionField> DivAssign<&'a Self> for ExtensionFieldWrapper<E> {
    fn div_assign(&mut self, other: &'a Self) {
        self.0 /= other.0;
    }
}

impl<'a, E: ExtensionField> Div<&'a mut Self> for ExtensionFieldWrapper<E> {
    type Output = Self;

    fn div(self, other: &'a mut Self) -> Self {
        Self(self.0 / other.0)
    }
}

impl<'a, E: ExtensionField> DivAssign<&'a mut Self> for ExtensionFieldWrapper<E> {
    fn div_assign(&mut self, other: &'a mut Self) {
        self.0 /= other.0;
    }
}

impl<'a, E: ExtensionField> DivAssign<Self> for ExtensionFieldWrapper<E> {
    fn div_assign(&mut self, other: Self) {
        self.0 /= other.0;
    }
}

impl<E: ExtensionField> Zeroize for ExtensionFieldWrapper<E> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<E: ExtensionField> CanonicalSerialize for ExtensionFieldWrapper<E> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.serialize_with_flags(writer, EmptyFlags)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.serialized_size_with_flags::<EmptyFlags>()
    }
}

impl<E: ExtensionField> CanonicalDeserialize for ExtensionFieldWrapper<E> {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Self::deserialize_with_flags::<R, EmptyFlags>(reader).map(|(r, _)| r)
    }
}

impl<E: ExtensionField> CanonicalSerializeWithFlags for ExtensionFieldWrapper<E> {
    fn serialize_with_flags<W: std::io::Write, F: ark_ff::Flags>(
        &self,
        writer: W,
        flags: F,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.serialize_with_flags(writer, flags)
    }

    fn serialized_size_with_flags<F: ark_ff::Flags>(&self) -> usize {
        self.0.serialized_size_with_flags::<F>()
    }

    fn serialize_uncompressed_with_flags<W: std::io::Write, F: ark_ff::Flags>(
        &self,
        writer: W,
        flags: F,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.serialize_uncompressed_with_flags(writer, flags)
    }

    fn uncompressed_size_with_flags<F: ark_ff::Flags>(&self) -> usize {
        self.0.uncompressed_size_with_flags::<F>()
    }
}

impl<E: ExtensionField> CanonicalDeserializeWithFlags for ExtensionFieldWrapper<E> {
    fn deserialize_with_flags<R: std::io::Read, F: ark_ff::Flags>(
        reader: R,
    ) -> Result<(Self, F), ark_serialize::SerializationError> {
        E::deserialize_with_flags(reader).map(|(e, f)| (Self(e), f))
    }

    fn deserialize_uncompressed_with_flags<R: std::io::Read, F: ark_ff::Flags>(
        reader: R,
    ) -> Result<(Self, F), ark_serialize::SerializationError> {
        E::deserialize_uncompressed_with_flags(reader).map(|(e, f)| (Self(e), f))
    }
}

impl<E: ExtensionField> One for ExtensionFieldWrapper<E> {
    fn one() -> Self {
        Self(E::one())
    }
}

// Implement Add, AddAsign, Mul, MulAssign, Sub, SubAssign, Neg for ExtensionFieldWrapper<E>
impl<E: ExtensionField> Add for ExtensionFieldWrapper<E> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<E: ExtensionField> AddAssign for ExtensionFieldWrapper<E> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<E: ExtensionField> Mul for ExtensionFieldWrapper<E> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<E: ExtensionField> MulAssign for ExtensionFieldWrapper<E> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<E: ExtensionField> Sub for ExtensionFieldWrapper<E> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<E: ExtensionField> SubAssign for ExtensionFieldWrapper<E> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl<E: ExtensionField> AdditiveGroup for ExtensionFieldWrapper<E> {
    type Scalar = Self;

    const ZERO: Self = Self(E::ZERO);
}

impl_from_for_extension_field_wrapper!(u8);
impl_from_for_extension_field_wrapper!(u16);
impl_from_for_extension_field_wrapper!(u32);
impl_from_for_extension_field_wrapper!(u64);
impl_from_for_extension_field_wrapper!(u128);
impl_from_for_extension_field_wrapper!(i8);
impl_from_for_extension_field_wrapper!(i16);
impl_from_for_extension_field_wrapper!(i32);
impl_from_for_extension_field_wrapper!(i64);
impl_from_for_extension_field_wrapper!(i128);
impl_from_for_extension_field_wrapper!(bool);

impl<E: ExtensionField + ark_ff::Field> AdditiveGroup for ExtensionFieldWrapper<E>
where
    E: Sum<E> + for<'a> Sum<&'a E> + Hash + Debug,
{
    type Scalar = Self;

    const ZERO: Self = Self(E::ZERO);
}

impl<E: ExtensionField + ark_ff::Field> Field for ExtensionFieldWrapper<E>
where
    E: ark_ff::Field + Sum<E> + for<'a> Sum<&'a E> + Hash + Debug,
    E::BasePrimeField: Clone + 'static,
{
    type BasePrimeField = E::BasePrimeField;

    const SQRT_PRECOMP: Option<ark_ff::SqrtPrecomputation<Self>> = None;
    const ONE: Self = Self(E::one());

    fn extension_degree() -> u64 {
        E::extension_degree()
    }

    fn to_base_prime_field_elements(&self) -> impl Iterator<Item = Self::BasePrimeField> + '_ {
        self.0.to_base_prime_field_elements()
    }

    fn from_base_prime_field_elems(
        elems: impl IntoIterator<Item = Self::BasePrimeField>,
    ) -> Option<Self> {
        E::from_base_prime_field_elems(elems).map(Self)
    }

    fn from_base_prime_field(elem: Self::BasePrimeField) -> Self {
        Self(E::from_base_prime_field(elem))
    }

    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        E::from_random_bytes(bytes).map(|x| (Self(x), F::default()))
    }

    fn legendre(&self) -> LegendreSymbol {
        self.0.legendre()
    }

    fn square(&self) -> Self {
        Self(self.0.square())
    }

    fn square_in_place(&mut self) -> &mut Self {
        self.0.square_in_place();
        self
    }

    fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Self)
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        self.0.inverse_in_place().map(|_| self)
    }

    fn frobenius_map_in_place(&mut self, power: usize) {
        self.0.frobenius_map_in_place(power);
    }

    fn mul_by_base_prime_field(&self, elem: &Self::BasePrimeField) -> Self {
        Self(self.0.mul_by_base_prime_field(elem))
    }

    fn zero() -> Self {
        Self(E::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn characteristic() -> Vec<u64> {
        E::characteristic()
    }

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        E::from_random_bytes(bytes).map(Self)
    }

    fn from_random_bytes_with_flags(bytes: &[u8]) -> Option<(Self, EmptyFlags)> {
        E::from_random_bytes(bytes).map(|x| (Self(x), EmptyFlags))
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }

    fn double_in_place(&mut self) -> &mut Self {
        self.0.double_in_place();
        self
    }

    fn neg_in_place(&mut self) -> &mut Self {
        self.0.neg_in_place();
        self
    }

    fn frobenius_map(&self, power: usize) -> Self {
        let mut result = self.clone();
        result.frobenius_map_in_place(power);
        result
    }
}

impl<E: ExtensionField + ark_ff::Field> FftField for ExtensionFieldWrapper<E>
where
    E: ark_ff::Field + Sum<E> + for<'a> Sum<&'a E> + Hash + Debug,
{
    const GENERATOR: Self = Self(E::GENERATOR);
    const TWO_ADICITY: u32 = E::TWO_ADICITY;
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self(E::TWO_ADIC_ROOT_OF_UNITY);
}
