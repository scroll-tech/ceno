pub mod impl_babybear {
    use crate::array_try_from_uniform_bytes;
    use p3::{
        self,
        babybear::{BabyBear, Poseidon2BabyBear},
        challenger::DuplexChallenger,
        field::{
            BasedVectorSpace, Field, PackedValue, PrimeCharacteristicRing, PrimeField32,
            TwoAdicField,
            extension::{BinomialExtensionField, BinomiallyExtendable},
        },
    };
    use rand_core::OsRng;

    use crate::{
        ExtensionField, FieldFrom, FieldInto, FromUniformBytes, PoseidonField, SmallField,
        impl_from_uniform_bytes_for_binomial_extension,
    };

    pub type BabyBearExt4 = BinomialExtensionField<BabyBear, 4>;

    pub const POSEIDON2_BABYBEAR_WIDTH: usize = 16;
    pub const POSEIDON2_BABYBEAR_RATE: usize = 8;

    impl FieldFrom<u64> for BabyBear {
        fn from_v(v: u64) -> Self {
            Self::from_u64(v)
        }
    }

    impl FieldFrom<u64> for BabyBearExt4 {
        fn from_v(v: u64) -> Self {
            Self::from_u64(v)
        }
    }

    impl FieldInto<BabyBear> for BabyBear {
        fn into_f(self) -> BabyBear {
            self
        }
    }

    impl PoseidonField for BabyBear {
        const PERM_WIDTH: usize = POSEIDON2_BABYBEAR_WIDTH;
        const RATE: usize = POSEIDON2_BABYBEAR_RATE;
        type P = Poseidon2BabyBear<POSEIDON2_BABYBEAR_WIDTH>;
        type T = DuplexChallenger<Self, Self::P, POSEIDON2_BABYBEAR_WIDTH, POSEIDON2_BABYBEAR_RATE>;
        fn get_perm() -> Self::T {
            let p = Poseidon2BabyBear::new_from_rng_128(&mut OsRng);
            DuplexChallenger::<
                Self,
                Self::P,
                POSEIDON2_BABYBEAR_WIDTH,
                POSEIDON2_BABYBEAR_RATE,
            >::new(p)
        }
    }

    impl FromUniformBytes for BabyBear {
        type Bytes = [u8; 8];

        fn try_from_uniform_bytes(bytes: [u8; 8]) -> Option<Self> {
            let value = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            let is_canonical = value < Self::ORDER_U32;
            is_canonical.then(|| Self::from_u32(value))
        }
    }

    impl SmallField for BabyBear {
        const MODULUS_U64: u64 = Self::ORDER_U32 as u64;

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
            self.as_canonical_u32() as u64
        }
    }

    impl_from_uniform_bytes_for_binomial_extension!(p3::babybear::BabyBear, 4);

    impl ExtensionField for BabyBearExt4 {
        const DEGREE: usize = 4;
        const MULTIPLICATIVE_GENERATOR: Self = <BabyBearExt4 as Field>::GENERATOR;
        const TWO_ADICITY: usize = BabyBear::TWO_ADICITY;
        // Passing two-adacity itself to this function will get the root of unity
        // with the largest order, i.e., order = 2^two-adacity.
        const BASE_TWO_ADIC_ROOT_OF_UNITY: Self::BaseField = BabyBear::new(0x78000000);
        const TWO_ADIC_ROOT_OF_UNITY: Self =
            BinomialExtensionField::new_unchecked([BabyBear::new(0x78000000); 4]);
        // non-residue is the value w such that the extension field is
        // F[X]/(X^2 - w)
        const NONRESIDUE: Self::BaseField = <BabyBear as BinomiallyExtendable<4>>::W;

        type BaseField = BabyBear;

        fn from_bases(bases: &[BabyBear]) -> Self {
            debug_assert_eq!(bases.len(), 2);
            Self::from_basis_coefficients_slice(bases)
        }

        fn as_bases(&self) -> &[BabyBear] {
            self.as_basis_coefficients_slice()
        }

        /// Convert limbs into self
        fn from_limbs(limbs: &[Self::BaseField]) -> Self {
            Self::from_bases(&limbs[0..4])
        }

        fn to_canonical_u64_vec(&self) -> Vec<u64> {
            self.as_basis_coefficients_slice()
                .iter()
                .map(|v: &Self::BaseField| v.as_canonical_u32() as u64)
                .collect()
        }
    }
}
