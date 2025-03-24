#![deny(clippy::cargo)]
#![feature(generic_const_exprs)]

use p3::field::{
    ExtensionField as P3ExtensionField, Field as P3Field, PackedValue, PrimeField, TwoAdicField,
};
use rand_core::RngCore;
use serde::Serialize;
use std::{array::from_fn, iter::repeat_with};
mod babybear;
pub use babybear::impl_babybear::*;
mod goldilock;
pub use goldilock::impl_goldilocks::*;
mod poseidon;
pub use poseidon::PoseidonField;

fn array_try_from_uniform_bytes<
    F: Copy + Default + FromUniformBytes<Bytes = [u8; W]>,
    const W: usize,
    const N: usize,
>(
    bytes: &[u8],
) -> Option<[F; N]> {
    let mut array = [F::default(); N];
    for i in 0..N {
        array[i] = F::try_from_uniform_bytes(from_fn(|j| bytes[i * W + j]))?;
    }
    Some(array)
}

pub trait FromUniformBytes: Sized {
    type Bytes: Copy + Default + AsRef<[u8]> + AsMut<[u8]>;

    fn from_uniform_bytes(mut fill: impl FnMut(&mut [u8])) -> Self {
        let mut bytes = Self::Bytes::default();
        loop {
            fill(bytes.as_mut());
            if let Some(value) = Self::try_from_uniform_bytes(bytes) {
                return value;
            }
        }
    }

    fn try_from_uniform_bytes(bytes: Self::Bytes) -> Option<Self>;

    fn random(mut rng: impl RngCore) -> Self {
        Self::from_uniform_bytes(|bytes| rng.fill_bytes(bytes.as_mut()))
    }

    fn random_vec(n: usize, mut rng: impl RngCore) -> Vec<Self> {
        repeat_with(|| Self::random(&mut rng)).take(n).collect()
    }
}

macro_rules! impl_from_uniform_bytes_for_binomial_extension {
    ($base:ty, $degree:literal) => {
        impl FromUniformBytes for p3::field::extension::BinomialExtensionField<$base, $degree> {
            type Bytes = [u8; <$base as FromUniformBytes>::Bytes::WIDTH * $degree];

            fn try_from_uniform_bytes(bytes: Self::Bytes) -> Option<Self> {
                Some(p3::field::BasedVectorSpace::from_basis_coefficients_slice(
                    &array_try_from_uniform_bytes::<
                        $base,
                        { <$base as FromUniformBytes>::Bytes::WIDTH },
                        $degree,
                    >(&bytes)?,
                ))
            }
        }
    };
}

impl_from_uniform_bytes_for_binomial_extension!(p3::goldilocks::Goldilocks, 2);

/// define a custom conversion trait like `From<T>`
/// an util to simulate general from function
pub trait FieldFrom<T> {
    fn from_v(value: T) -> Self;
}

/// define a custom trait that relies on `FieldFrom<T>`
/// an util to simulate general into function
pub trait FieldInto<T> {
    fn into_f(self) -> T;
}

impl<U, T> FieldInto<U> for T
where
    U: FieldFrom<T>,
{
    fn into_f(self) -> U {
        U::from_v(self)
    }
}

// TODO remove SmallField
pub trait SmallField: Serialize + P3Field + FieldFrom<u64> + FieldInto<Self> {
    /// MODULUS as u64
    const MODULUS_U64: u64;

    /// Convert a byte string into a list of field elements
    fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Self>;

    /// Convert a field elements to a u64.
    fn to_canonical_u64(&self) -> u64;
}

pub trait ExtensionField: P3ExtensionField<Self::BaseField> + FromUniformBytes + Ord {
    const DEGREE: usize;
    const MULTIPLICATIVE_GENERATOR: Self;
    const TWO_ADICITY: usize;
    const BASE_TWO_ADIC_ROOT_OF_UNITY: Self::BaseField;
    const TWO_ADIC_ROOT_OF_UNITY: Self;
    const NONRESIDUE: Self::BaseField;

    type BaseField: SmallField + Ord + PrimeField + FromUniformBytes + TwoAdicField + PoseidonField;

    fn from_bases(bases: &[Self::BaseField]) -> Self;

    fn as_bases(&self) -> &[Self::BaseField];

    /// Convert limbs into self
    fn from_limbs(limbs: &[Self::BaseField]) -> Self;

    /// Convert a field elements to a u64 vector
    fn to_canonical_u64_vec(&self) -> Vec<u64>;
}

// #[cfg(not(feature = "babybear"))]
// pub trait ExtensionField: ExtensionFieldInner<8> {}

// #[cfg(feature = "babybear")]
// pub trait ExtensionField: ExtensionFieldInner<16> {}
