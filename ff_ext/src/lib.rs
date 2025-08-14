#![deny(clippy::cargo)]

use p3::field::{
    ExtensionField as P3ExtensionField, Field as P3Field, FieldAlgebra, PrimeField, TwoAdicField,
};
use rand_core::RngCore;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    array::from_fn,
    iter::{self, repeat_with},
};
mod babybear;
pub use babybear::impl_babybear::*;
mod goldilock;
pub use goldilock::impl_goldilocks::*;
mod poseidon;
#[cfg(debug_assertions)]
pub use poseidon::impl_instruments::*;
pub use poseidon::{FieldChallengerExt, PoseidonField};

pub(crate) fn array_try_from_uniform_bytes<
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

#[macro_export]
macro_rules! impl_from_uniform_bytes_for_binomial_extension {
    ($base:ty, $degree:literal) => {
        impl FromUniformBytes for p3::field::extension::BinomialExtensionField<$base, $degree> {
            type Bytes = [u8; <$base as FromUniformBytes>::Bytes::WIDTH * $degree];

            fn try_from_uniform_bytes(bytes: Self::Bytes) -> Option<Self> {
                Some(p3::field::FieldExtensionAlgebra::from_base_slice(
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

pub trait ExtensionField:
    P3ExtensionField<Self::BaseField> + FromUniformBytes + Ord + TwoAdicField
{
    const DEGREE: usize;
    const MULTIPLICATIVE_GENERATOR: Self;
    const TWO_ADICITY: usize;
    const NONRESIDUE: Self::BaseField;

    type BaseField: SmallField
        + Ord
        + PrimeField
        + FromUniformBytes
        + TwoAdicField
        + PoseidonField
        + DeserializeOwned;

    fn from_ref_base(base: &Self::BaseField) -> Self {
        Self::from_base_iter(
            iter::once(*base).chain(iter::repeat_n(Self::BaseField::ZERO, Self::DEGREE - 1)),
        )
    }

    fn from_bases(bases: &[Self::BaseField]) -> Self {
        debug_assert_eq!(bases.len(), Self::D,);
        Self::from_base_slice(bases)
    }

    fn as_bases(&self) -> &[Self::BaseField] {
        self.as_base_slice()
    }

    /// Convert limbs into self
    fn from_limbs(limbs: &[Self::BaseField]) -> Self {
        Self::from_bases(&limbs[0..Self::D])
    }

    /// Convert a field elements to a u64 vector
    fn to_canonical_u64_vec(&self) -> Vec<u64>;

    /// retrive first field elements to u64
    fn to_canonical_u64(&self) -> u64 {
        let res = self.to_canonical_u64_vec();
        assert!(res[1..].iter().all(|v| *v == 0));
        res[0]
    }
}
