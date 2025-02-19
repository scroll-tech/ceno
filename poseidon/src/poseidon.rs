use p3_field::{FieldAlgebra, PrimeField};
use p3_goldilocks::{
    Goldilocks, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS, HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS,
    Poseidon2GoldilocksHL,
};
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::CryptographicPermutation;

pub trait PoseidonField: PrimeField {
    type T: CryptographicPermutation<[Self; 8]>;
    fn get_perm() -> Self::T;
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

pub(crate) fn new_array<const N: usize, F: FieldAlgebra>(input: [u64; N]) -> [F; N] {
    let mut output = [F::ZERO; N];
    let mut i = 0;
    while i < N {
        output[i] = F::from_canonical_u64(input[i]);
        i += 1;
    }
    output
}
