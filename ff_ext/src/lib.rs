pub use ff;
use ff::FromUniformBytes;
use goldilocks::SmallField;
use serde::Serialize;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use poseidon::poseidon::Poseidon;

pub trait ExtensionField:
    Serialize
    + FromUniformBytes<64>
    + From<Self::BaseField>
    + Add<Self::BaseField, Output = Self>
    + Sub<Self::BaseField, Output = Self>
    + Mul<Self::BaseField, Output = Self>
    + for<'a> Add<&'a Self::BaseField, Output = Self>
    + for<'a> Sub<&'a Self::BaseField, Output = Self>
    + for<'a> Mul<&'a Self::BaseField, Output = Self>
    + AddAssign<Self::BaseField>
    + SubAssign<Self::BaseField>
    + MulAssign<Self::BaseField>
    + for<'a> AddAssign<&'a Self::BaseField>
    + for<'a> SubAssign<&'a Self::BaseField>
    + for<'a> MulAssign<&'a Self::BaseField>
{
    const DEGREE: usize;

    type BaseField: SmallField + FromUniformBytes<64> + Poseidon;

    fn from_bases(bases: &[Self::BaseField]) -> Self;

    fn as_bases(&self) -> &[Self::BaseField];

    /// Convert limbs into self
    fn from_limbs(limbs: &[Self::BaseField]) -> Self;

    /// Convert a field elements to a u64 vector
    fn to_canonical_u64_vec(&self) -> Vec<u64>;
}

mod impl_goldilocks {
    use crate::ExtensionField;
    use goldilocks::{ExtensionField as GoldilocksEF, Goldilocks, GoldilocksExt2};

    impl ExtensionField for GoldilocksExt2 {
        const DEGREE: usize = 2;

        type BaseField = Goldilocks;

        fn from_bases(bases: &[Goldilocks]) -> Self {
            debug_assert_eq!(bases.len(), 2);
            Self([bases[0], bases[1]])
        }

        fn as_bases(&self) -> &[Goldilocks] {
            self.0.as_slice()
        }

        /// Convert limbs into self
        fn from_limbs(limbs: &[Self::BaseField]) -> Self {
            Self([limbs[0], limbs[1]])
        }

        fn to_canonical_u64_vec(&self) -> Vec<u64> {
            <GoldilocksExt2 as GoldilocksEF>::to_canonical_u64_vec(self)
        }
    }
}
