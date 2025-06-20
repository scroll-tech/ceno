pub mod impl_goldilocks {
    use crate::{
        ExtensionField, FieldFrom, FieldInto, FromUniformBytes, SmallField,
        array_try_from_uniform_bytes, impl_from_uniform_bytes_for_binomial_extension,
        poseidon::{PoseidonField, new_array},
    };
    use p3::{
        challenger::DuplexChallenger,
        field::{
            Field, FieldAlgebra, FieldExtensionAlgebra, PackedValue, PrimeField64, TwoAdicField,
            extension::{BinomialExtensionField, BinomiallyExtendable},
        },
        goldilocks::{
            Goldilocks, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
            HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS, Poseidon2GoldilocksHL,
        },
        merkle_tree::MerkleTreeMmcs,
        poseidon2::ExternalLayerConstants,
        symmetric::{PaddingFreeSponge, TruncatedPermutation},
    };

    #[cfg(debug_assertions)]
    use crate::poseidon::impl_instruments::*;
    #[cfg(debug_assertions)]
    use p3::symmetric::CryptographicPermutation;

    pub type GoldilocksExt2 = BinomialExtensionField<Goldilocks, 2>;

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

    impl FieldInto<Goldilocks> for Goldilocks {
        fn into_f(self) -> Goldilocks {
            self
        }
    }

    pub const POSEIDON2_GOLDILICK_WIDTH: usize = 8;
    pub const POSEIDON2_GOLDILICK_RATE: usize = 4;

    #[cfg(debug_assertions)]
    impl CryptographicPermutation<[Goldilocks; POSEIDON2_GOLDILICK_WIDTH]>
        for Instrumented<Poseidon2GoldilocksHL<POSEIDON2_GOLDILICK_WIDTH>>
    {
    }

    impl PoseidonField for Goldilocks {
        #[cfg(debug_assertions)]
        type P = Instrumented<Poseidon2GoldilocksHL<POSEIDON2_GOLDILICK_WIDTH>>;
        #[cfg(not(debug_assertions))]
        type P = Poseidon2GoldilocksHL<POSEIDON2_GOLDILICK_WIDTH>;
        type T =
            DuplexChallenger<Self, Self::P, POSEIDON2_GOLDILICK_WIDTH, POSEIDON2_GOLDILICK_RATE>;
        type S = PaddingFreeSponge<Self::P, POSEIDON2_GOLDILICK_WIDTH, POSEIDON2_GOLDILICK_RATE, 4>;
        type C = TruncatedPermutation<Self::P, 2, 4, POSEIDON2_GOLDILICK_WIDTH>;
        type MMCS = MerkleTreeMmcs<Self, Self, Self::S, Self::C, 4>;
        fn get_default_challenger() -> Self::T {
            DuplexChallenger::<Self, Self::P, POSEIDON2_GOLDILICK_WIDTH, POSEIDON2_GOLDILICK_RATE>::new(
                Self::get_default_perm(),
            )
        }

        #[cfg(debug_assertions)]
        fn get_default_perm() -> Self::P {
            Instrumented::new(Poseidon2GoldilocksHL::new(
                ExternalLayerConstants::<Goldilocks, POSEIDON2_GOLDILICK_WIDTH>::new_from_saved_array(
                    HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
                    new_array,
                ),
                new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
            ))
        }

        #[cfg(not(debug_assertions))]
        fn get_default_perm() -> Self::P {
            Poseidon2GoldilocksHL::new(
                ExternalLayerConstants::<Goldilocks, POSEIDON2_GOLDILICK_WIDTH>::new_from_saved_array(
                    HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
                    new_array,
                ),
                new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
            )
        }

        fn get_default_sponge() -> Self::S {
            PaddingFreeSponge::new(Self::get_default_perm())
        }

        fn get_default_compression() -> Self::C {
            TruncatedPermutation::new(Self::get_default_perm())
        }

        fn get_default_mmcs() -> Self::MMCS {
            MerkleTreeMmcs::new(Self::get_default_sponge(), Self::get_default_compression())
        }
    }

    impl_from_uniform_bytes_for_binomial_extension!(p3::goldilocks::Goldilocks, 2);

    impl FromUniformBytes for Goldilocks {
        type Bytes = [u8; 8];

        fn try_from_uniform_bytes(bytes: [u8; 8]) -> Option<Self> {
            let value = u64::from_le_bytes(bytes);
            let is_canonical = value < Self::ORDER_U64;
            is_canonical.then(|| Self::from_canonical_u64(value))
        }
    }

    impl SmallField for Goldilocks {
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
    }

    impl ExtensionField for GoldilocksExt2 {
        const DEGREE: usize = 2;
        const MULTIPLICATIVE_GENERATOR: Self = <GoldilocksExt2 as Field>::GENERATOR;
        const TWO_ADICITY: usize = Goldilocks::TWO_ADICITY;
        // non-residue is the value w such that the extension field is
        // F[X]/(X^2 - w)
        const NONRESIDUE: Self::BaseField = <Goldilocks as BinomiallyExtendable<2>>::W;

        type BaseField = Goldilocks;

        fn to_canonical_u64_vec(&self) -> Vec<u64> {
            self.as_base_slice()
                .iter()
                .map(|v: &Self::BaseField| v.as_canonical_u64())
                .collect()
        }
    }
}
