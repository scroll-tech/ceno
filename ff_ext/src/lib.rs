#![deny(clippy::cargo)]

pub use ff;
use p3_field::{ExtensionField as P3ExtensionField, Field as P3Field};
use serde::Serialize;

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

pub trait ExtensionField: P3ExtensionField<Self::BaseField>
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

    type BaseField: SmallField + Ord + P3Field;

    fn from_bases(bases: &[Self::BaseField]) -> Self;

    fn as_bases(&self) -> &[Self::BaseField];

    /// Convert limbs into self
    fn from_limbs(limbs: &[Self::BaseField]) -> Self;

    /// Convert a field elements to a u64 vector
    fn to_canonical_u64_vec(&self) -> Vec<u64>;
}

mod impl_goldilocks {
    use crate::{ExtensionField, SmallField};
    use p3_field::{
        FieldAlgebra, FieldExtensionAlgebra, PrimeField64, extension::BinomialExtensionField,
    };
    use p3_goldilocks::Goldilocks;

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

    impl ExtensionField for BinomialExtensionField<Goldilocks, 2> {
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
