pub mod impl_babybear {
    use crate::array_try_from_uniform_bytes;
    use p3::{
        self,
        babybear::{BabyBear, Poseidon2BabyBear},
        challenger::DuplexChallenger,
        field::{
            Field, FieldAlgebra, FieldExtensionAlgebra, PackedValue, PrimeField32, TwoAdicField,
            extension::{BinomialExtensionField, BinomiallyExtendable},
        },
        merkle_tree::MerkleTreeMmcs,
        poseidon2::ExternalLayerConstants,
        symmetric::{PaddingFreeSponge, TruncatedPermutation},
    };

    use crate::{
        ExtensionField, FieldFrom, FieldInto, FromUniformBytes, PoseidonField, SmallField,
        impl_from_uniform_bytes_for_binomial_extension,
    };

    pub type BabyBearExt4 = BinomialExtensionField<BabyBear, 4>;

    pub const POSEIDON2_BABYBEAR_WIDTH: usize = 16;
    pub const POSEIDON2_BABYBEAR_RATE: usize = 8;

    pub const BABYBEAR_RC16_EXTERNAL_INITIAL: [[BabyBear; 16]; 4] = BabyBear::new_2d_array([
        [
            0x69cbb6af, 0x46ad93f9, 0x60a00f4e, 0x6b1297cd, 0x23189afe, 0x732e7bef, 0x72c246de,
            0x2c941900, 0x0557eede, 0x1580496f, 0x3a3ea77b, 0x54f3f271, 0x0f49b029, 0x47872fe1,
            0x221e2e36, 0x1ab7202e,
        ],
        [
            0x487779a6, 0x3851c9d8, 0x38dc17c0, 0x209f8849, 0x268dcee8, 0x350c48da, 0x5b9ad32e,
            0x0523272b, 0x3f89055b, 0x01e894b2, 0x13ddedde, 0x1b2ef334, 0x7507d8b4, 0x6ceeb94e,
            0x52eb6ba2, 0x50642905,
        ],
        [
            0x05453f3f, 0x06349efc, 0x6922787c, 0x04bfff9c, 0x768c714a, 0x3e9ff21a, 0x15737c9c,
            0x2229c807, 0x0d47f88c, 0x097e0ecc, 0x27eadba0, 0x2d7d29e4, 0x3502aaa0, 0x0f475fd7,
            0x29fbda49, 0x018afffd,
        ],
        [
            0x0315b618, 0x6d4497d1, 0x1b171d9e, 0x52861abd, 0x2e5d0501, 0x3ec8646c, 0x6e5f250a,
            0x148ae8e6, 0x17f5fa4a, 0x3e66d284, 0x0051aa3b, 0x483f7913, 0x2cfe5f15, 0x023427ca,
            0x2cc78315, 0x1e36ea47,
        ],
    ]);

    pub const BABYBEAR_RC16_EXTERNAL_FINAL: [[BabyBear; 16]; 4] = BabyBear::new_2d_array([
        [
            0x7290a80d, 0x6f7e5329, 0x598ec8a8, 0x76a859a0, 0x6559e868, 0x657b83af, 0x13271d3f,
            0x1f876063, 0x0aeeae37, 0x706e9ca6, 0x46400cee, 0x72a05c26, 0x2c589c9e, 0x20bd37a7,
            0x6a2d3d10, 0x20523767,
        ],
        [
            0x5b8fe9c4, 0x2aa501d6, 0x1e01ac3e, 0x1448bc54, 0x5ce5ad1c, 0x4918a14d, 0x2c46a83f,
            0x4fcf6876, 0x61d8d5c8, 0x6ddf4ff9, 0x11fda4d3, 0x02933a8f, 0x170eaf81, 0x5a9c314f,
            0x49a12590, 0x35ec52a1,
        ],
        [
            0x58eb1611, 0x5e481e65, 0x367125c9, 0x0eba33ba, 0x1fc28ded, 0x066399ad, 0x0cbec0ea,
            0x75fd1af0, 0x50f5bf4e, 0x643d5f41, 0x6f4fe718, 0x5b3cbbde, 0x1e3afb3e, 0x296fb027,
            0x45e1547b, 0x4a8db2ab,
        ],
        [
            0x59986d19, 0x30bcdfa3, 0x1db63932, 0x1d7c2824, 0x53b33681, 0x0673b747, 0x038a98a3,
            0x2c5bce60, 0x351979cd, 0x5008fb73, 0x547bca78, 0x711af481, 0x3f93bf64, 0x644d987b,
            0x3c8bcd87, 0x608758b8,
        ],
    ]);

    pub const BABYBEAR_RC16_INTERNAL: [BabyBear; 13] = BabyBear::new_array([
        0x5a8053c0, 0x693be639, 0x3858867d, 0x19334f6b, 0x128f0fd8, 0x4e2b1ccb, 0x61210ce0,
        0x3c318939, 0x0b5b2f22, 0x2edb11d5, 0x213effdf, 0x0cac4606, 0x241af16d,
    ]);

    impl FieldFrom<u64> for BabyBear {
        fn from_v(v: u64) -> Self {
            Self::from_canonical_u64(v)
        }
    }

    impl FieldFrom<u64> for BabyBearExt4 {
        fn from_v(v: u64) -> Self {
            Self::from_canonical_u64(v)
        }
    }

    impl FieldInto<BabyBear> for BabyBear {
        fn into_f(self) -> BabyBear {
            self
        }
    }

    #[cfg(debug_assertions)]
    use crate::poseidon::impl_instruments::*;
    #[cfg(debug_assertions)]
    use p3::symmetric::CryptographicPermutation;

    #[cfg(debug_assertions)]
    impl CryptographicPermutation<[BabyBear; POSEIDON2_BABYBEAR_WIDTH]>
        for Instrumented<Poseidon2BabyBear<POSEIDON2_BABYBEAR_WIDTH>>
    {
    }

    impl PoseidonField for BabyBear {
        #[cfg(debug_assertions)]
        type P = Instrumented<Poseidon2BabyBear<POSEIDON2_BABYBEAR_WIDTH>>;
        #[cfg(not(debug_assertions))]
        type P = Poseidon2BabyBear<POSEIDON2_BABYBEAR_WIDTH>;

        type T = DuplexChallenger<Self, Self::P, POSEIDON2_BABYBEAR_WIDTH, POSEIDON2_BABYBEAR_RATE>;
        type S = PaddingFreeSponge<Self::P, POSEIDON2_BABYBEAR_WIDTH, POSEIDON2_BABYBEAR_RATE, 8>;
        type C = TruncatedPermutation<Self::P, 2, 8, POSEIDON2_BABYBEAR_WIDTH>;
        type MMCS = MerkleTreeMmcs<Self, Self, Self::S, Self::C, 8>;
        fn get_default_challenger() -> Self::T {
            DuplexChallenger::<
                Self,
                Self::P,
                POSEIDON2_BABYBEAR_WIDTH,
                POSEIDON2_BABYBEAR_RATE,
            >::new(Self::get_default_perm())
        }

        #[cfg(debug_assertions)]
        fn get_default_perm() -> Self::P {
            Instrumented::new(Poseidon2BabyBear::new(
                ExternalLayerConstants::new(
                    BABYBEAR_RC16_EXTERNAL_INITIAL.to_vec(),
                    BABYBEAR_RC16_EXTERNAL_FINAL.to_vec(),
                ),
                BABYBEAR_RC16_INTERNAL.to_vec(),
            ))
        }

        #[cfg(not(debug_assertions))]
        fn get_default_perm() -> Self::P {
            Poseidon2BabyBear::new(
                ExternalLayerConstants::new(
                    BABYBEAR_RC16_EXTERNAL_INITIAL.to_vec(),
                    BABYBEAR_RC16_EXTERNAL_FINAL.to_vec(),
                ),
                BABYBEAR_RC16_INTERNAL.to_vec(),
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

    impl FromUniformBytes for BabyBear {
        type Bytes = [u8; 8];

        fn try_from_uniform_bytes(bytes: [u8; 8]) -> Option<Self> {
            let value = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            let is_canonical = value < Self::ORDER_U32;
            is_canonical.then(|| Self::from_canonical_u32(value))
        }
    }

    impl SmallField for BabyBear {
        const MODULUS_U64: u64 = Self::ORDER_U32 as u64;

        /// Convert a byte string into a list of field elements
        fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Self> {
            bytes
                .chunks(4)
                .map(|chunk| {
                    let mut array = [0u8; 4];
                    array[..chunk.len()].copy_from_slice(chunk);
                    unsafe { std::ptr::read_unaligned(array.as_ptr() as *const u32) }
                })
                .map(Self::from_canonical_u32)
                .collect::<Vec<_>>()
        }

        /// Convert a field elements to a u64.
        fn to_canonical_u64(&self) -> u64 {
            self.as_canonical_u32() as u64
        }
    }

    impl_from_uniform_bytes_for_binomial_extension!(p3::babybear::BabyBear, 4);

    impl ExtensionField for BabyBearExt4 {
        const DEGREE: usize = 4;
        const MULTIPLICATIVE_GENERATOR: Self = <BabyBearExt4 as Field>::GENERATOR;
        const TWO_ADICITY: usize = BabyBear::TWO_ADICITY;
        // non-residue is the value w such that the extension field is
        // F[X]/(X^2 - w)
        const NONRESIDUE: Self::BaseField = <BabyBear as BinomiallyExtendable<4>>::W;

        type BaseField = BabyBear;

        fn to_canonical_u64_vec(&self) -> Vec<u64> {
            self.as_base_slice()
                .iter()
                .map(|v: &Self::BaseField| v.as_canonical_u32() as u64)
                .collect()
        }
    }
}
