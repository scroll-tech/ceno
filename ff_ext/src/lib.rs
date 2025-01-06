#![deny(clippy::cargo)]

use std::{array::from_fn, iter::repeat_with};

pub use ff;
use p3_field::{
    ExtensionField as P3ExtensionField, Field as P3Field, PackedValue,
    extension::BinomialExtensionField,
};
use p3_goldilocks::Goldilocks;
use rand_core::RngCore;
use serde::Serialize;

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

// TODO remove SmallField
pub trait SmallField: Serialize + P3Field {
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

pub trait ExtensionField: P3ExtensionField<Self::BaseField> + FromUniformBytes
// + FromUniformBytes<64>
// + From<Self::BaseField>
// + Add<Self::BaseField, Output = Self>
// + Sub<Self::BaseField, Output = Self>
// + Mul<Self::BaseField, Output = Self>
// // + for<'a> Add<&'a Self::BaseField, Output = Self>
// + for<'a> Sub<&'a Self::BaseField, Output = Self>
// + for<'a> Mul<&'a Self::BaseField, Output = Self>
// + AddAssign<Self::BaseField>
// + SubAssign<Self::BaseField>
// + MulAssign<Self::BaseField>
// + for<'a> AddAssign<&'a Self::BaseField>
// + for<'a> SubAssign<&'a Self::BaseField>
// + for<'a> MulAssign<&'a Self::BaseField>
// + Ord
// + std::hash::Hash
{
    const DEGREE: usize;

    type BaseField: SmallField + Ord + P3Field + FromUniformBytes;

    fn from_bases(bases: &[Self::BaseField]) -> Self;

    fn as_bases(&self) -> &[Self::BaseField];

    /// Convert limbs into self
    fn from_limbs(limbs: &[Self::BaseField]) -> Self;

    /// Convert a field elements to a u64 vector
    fn to_canonical_u64_vec(&self) -> Vec<u64>;
}

mod impl_goldilocks {
    use crate::{ExtensionField, FromUniformBytes, GoldilocksExt2, SmallField};
    use p3_field::{FieldAlgebra, FieldExtensionAlgebra, PrimeField64};
    use p3_goldilocks::Goldilocks;

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
            // Self([bases[0], bases[1]])
        }

        fn as_bases(&self) -> &[Goldilocks] {
            self.as_base_slice()
        }

        /// Convert limbs into self
        fn from_limbs(limbs: &[Self::BaseField]) -> Self {
            // Self([limbs[0], limbs[1]])
            Self::from_base_slice(&limbs[0..2])
        }

        fn to_canonical_u64_vec(&self) -> Vec<u64> {
            self.as_base_slice()
                .iter()
                .map(|v: &Self::BaseField| v.as_canonical_u64())
                .collect()
            // <GoldilocksExt2 as GoldilocksEF>::to_canonical_u64_vec(self)
        }
    }
}
