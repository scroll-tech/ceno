#![deny(clippy::cargo)]

use p3_field::{
    ExtensionField as P3ExtensionField, Field as P3Field, PackedValue, PrimeField, TwoAdicField,
    extension::BinomialExtensionField,
};
use p3_goldilocks::Goldilocks;
use rand_core::RngCore;
use serde::Serialize;
use std::{array::from_fn, iter::repeat_with};
mod poseidon;
pub use poseidon::PoseidonField;
pub type GoldilocksExt2 = BinomialExtensionField<Goldilocks, 2>;

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
        impl FromUniformBytes for p3_field::extension::BinomialExtensionField<$base, $degree> {
            type Bytes = [u8; <$base as FromUniformBytes>::Bytes::WIDTH * $degree];

            fn try_from_uniform_bytes(bytes: Self::Bytes) -> Option<Self> {
                Some(p3_field::FieldExtensionAlgebra::from_base_slice(
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

impl_from_uniform_bytes_for_binomial_extension!(p3_goldilocks::Goldilocks, 2);

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

// TODO remove SmallField
pub trait SmallField: Serialize + P3Field + FieldFrom<u64> + FieldInto<Self> {
    /// MODULUS as u64
    const MODULUS_U64: u64;

    /// Identifier string
    const NAME: &'static str;

    /// Convert a byte string into a list of field elements
    fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Self>;

    /// Convert a field elements to a u64.
    fn to_canonical_u64(&self) -> u64;

    /// Convert a field elements to a u64. Do not normalize it.
    fn to_noncanonical_u64(&self) -> u64;
}

pub trait ExtensionField: P3ExtensionField<Self::BaseField> + FromUniformBytes + Ord {
    const DEGREE: usize;

    type BaseField: SmallField + Ord + PrimeField + FromUniformBytes + TwoAdicField + PoseidonField;

    fn from_bases(bases: &[Self::BaseField]) -> Self;

    fn as_bases(&self) -> &[Self::BaseField];

    /// Convert limbs into self
    fn from_limbs(limbs: &[Self::BaseField]) -> Self;

    /// Convert a field elements to a u64 vector
    fn to_canonical_u64_vec(&self) -> Vec<u64>;
}

mod impl_goldilocks {
    use crate::{
        ExtensionField, FieldFrom, FieldInto, FromUniformBytes, GoldilocksExt2, SmallField,
        poseidon::{PoseidonField, new_array},
    };
    use p3_field::{FieldAlgebra, FieldExtensionAlgebra, PrimeField64};
    use p3_goldilocks::{
        Goldilocks, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
        HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS, Poseidon2GoldilocksHL,
    };
    use p3_poseidon2::ExternalLayerConstants;

    impl FieldFrom<u64> for Goldilocks {
        fn from_v(v: u64) -> Self {
            Self::from_canonical_u64(v)
        }
    }

    impl FieldFrom<u64> for GoldilocksExt2 {
        fn from_v(v: u64) -> Self {
            Self::from_canonical_u64(v)
        }
    }

    impl<U, T> FieldInto<U> for T
    where
        U: FieldFrom<T>,
    {
        fn into_f(self) -> U {
            U::from_v(self)
        }
    }

    impl FieldInto<Goldilocks> for Goldilocks {
        fn into_f(self) -> Goldilocks {
            self
        }
    }

    impl PoseidonField for Goldilocks {
        type T = Poseidon2GoldilocksHL<8>;
        fn get_perm() -> Self::T {
            Poseidon2GoldilocksHL::new(
                ExternalLayerConstants::<Goldilocks, 8>::new_from_saved_array(
                    HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
                    new_array,
                ),
                new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
            )
        }
    }

    impl FromUniformBytes for Goldilocks {
        type Bytes = [u8; 8];

        fn try_from_uniform_bytes(bytes: [u8; 8]) -> Option<Self> {
            let value = u64::from_le_bytes(bytes);
            let is_canonical = value < Self::ORDER_U64;
            is_canonical.then(|| Self::from_canonical_u64(value))
        }
    }

    impl SmallField for Goldilocks {
        /// Identifier string
        const NAME: &'static str = "Goldilocks";
        const MODULUS_U64: u64 = Self::ORDER_U64;

        /// Convert a byte string into a list of field elements
        fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Self> {
            bytes
                .chunks(8)
                .map(|chunk| {
                    let mut array = [0u8; 8];
                    array[..chunk.len()].copy_from_slice(chunk);
                    unsafe { std::ptr::read_unaligned(array.as_ptr() as *const u64) }
                })
                .map(Self::from_canonical_u64)
                .collect::<Vec<_>>()
        }

        /// Convert a field elements to a u64.
        fn to_canonical_u64(&self) -> u64 {
            self.as_canonical_u64()
        }

        /// Convert a field elements to a u64. Do not normalize it.
        fn to_noncanonical_u64(&self) -> u64 {
            self.as_canonical_u64()
        }
    }

    impl ExtensionField for GoldilocksExt2 {
        const DEGREE: usize = 2;

        type BaseField = Goldilocks;

        fn from_bases(bases: &[Goldilocks]) -> Self {
            debug_assert_eq!(bases.len(), 2);
            Self::from_base_slice(bases)
        }

        fn as_bases(&self) -> &[Goldilocks] {
            self.as_base_slice()
        }

        /// Convert limbs into self
        fn from_limbs(limbs: &[Self::BaseField]) -> Self {
            Self::from_base_slice(&limbs[0..2])
        }

        fn to_canonical_u64_vec(&self) -> Vec<u64> {
            self.as_base_slice()
                .iter()
                .map(|v: &Self::BaseField| v.as_canonical_u64())
                .collect()
        }
    }
}
