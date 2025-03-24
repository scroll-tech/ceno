use p3::{field::PrimeField, symmetric::CryptographicPermutation};

use crate::SmallField;

/// define default permutation
pub trait PoseidonField: PrimeField + SmallField {
    const PERM_WIDTH: usize;
    const RATE: usize;
    type T: CryptographicPermutation<[Self; <Self as PoseidonField>::PERM_WIDTH]>
    where
        [(); Self::PERM_WIDTH]:;
    fn get_perm() -> Self::T
    where
        [(); Self::PERM_WIDTH]:;
}

pub(crate) fn new_array<const N: usize, F: PrimeField>(input: [u64; N]) -> [F; N] {
    let mut output = [F::ZERO; N];
    let mut i = 0;
    while i < N {
        output[i] = F::from_u64(input[i]);
        i += 1;
    }
    output
}
