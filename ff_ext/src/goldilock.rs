pub mod impl_goldilocks {

    use crate::{
        ExtensionField, FieldFrom, FieldInto, FromUniformBytes, SmallField,
        array_try_from_uniform_bytes, impl_from_uniform_bytes_for_binomial_extension,
        poseidon::{PoseidonField, PoseidonFieldExt, new_array},
    };
    use p3::{
        challenger::DuplexChallenger,
        field::{
            BasedVectorSpace, Field, PackedValue, PrimeCharacteristicRing, PrimeField64,
            TwoAdicField,
            extension::{BinomialExtensionField, BinomiallyExtendable},
        },
        goldilocks::{
            Goldilocks, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
            HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS, Poseidon2GoldilocksHL,
        },
        matrix::{dense::RowMajorMatrix, extension::FlatMatrixView},
        merkle_tree::{MerkleTree, MerkleTreeMmcs},
        poseidon2::ExternalLayerConstants,
        symmetric::{PaddingFreeSponge, TruncatedPermutation},
    };

    pub type GoldilocksExt2 = BinomialExtensionField<Goldilocks, 2>;

    impl FieldFrom<u64> for Goldilocks {
        fn from_v(v: u64) -> Self {
            Self::from_u64(v)
        }
    }

    impl FieldFrom<u64> for GoldilocksExt2 {
        fn from_v(v: u64) -> Self {
            Self::from_u64(v)
        }
    }

    impl FieldInto<Goldilocks> for Goldilocks {
        fn into_f(self) -> Goldilocks {
            self
        }
    }

    pub const POSEIDON2_GOLDILICK_WIDTH: usize = 8;
    pub const POSEIDON2_GOLDILICK_RATE: usize = 4;

    impl PoseidonField for Goldilocks {
        type P = Poseidon2GoldilocksHL<POSEIDON2_GOLDILICK_WIDTH>;
        type T =
            DuplexChallenger<Self, Self::P, POSEIDON2_GOLDILICK_WIDTH, POSEIDON2_GOLDILICK_RATE>;
        type S = PaddingFreeSponge<Self::P, 8, 4, 4>;
        type C = TruncatedPermutation<Self::P, 2, 4, 8>;
        type MMCS = MerkleTreeMmcs<Self, Self, Self::S, Self::C, 4>;
        fn get_default_challenger() -> Self::T {
            DuplexChallenger::<Self, Self::P, POSEIDON2_GOLDILICK_WIDTH, POSEIDON2_GOLDILICK_RATE>::new(
                Self::get_default_perm(),
            )
        }

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
            is_canonical.then(|| Self::from_u64(value))
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
                .map(Self::from_u64)
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
        // Passing two-adacity itself to this function will get the root of unity
        // with the largest order, i.e., order = 2^two-adacity.
        const BASE_TWO_ADIC_ROOT_OF_UNITY: Self::BaseField =
            Goldilocks::two_adic_generator_const(Goldilocks::TWO_ADICITY);
        const TWO_ADIC_ROOT_OF_UNITY: Self = BinomialExtensionField::new_unchecked(
            Goldilocks::ext_two_adic_generator_const(Goldilocks::TWO_ADICITY),
        );
        // non-residue is the value w such that the extension field is
        // F[X]/(X^2 - w)
        const NONRESIDUE: Self::BaseField = <Goldilocks as BinomiallyExtendable<2>>::W;

        type BaseField = Goldilocks;

        fn to_canonical_u64_vec(&self) -> Vec<u64> {
            self.as_basis_coefficients_slice()
                .iter()
                .map(|v: &Self::BaseField| v.as_canonical_u64())
                .collect()
        }
    }

    impl PoseidonFieldExt for GoldilocksExt2 {
        type MkExt = MerkleTree<
            <Self as ExtensionField>::BaseField,
            <Self as ExtensionField>::BaseField,
            FlatMatrixView<<Self as ExtensionField>::BaseField, Self, RowMajorMatrix<Self>>,
            4,
        >;
    }
}
