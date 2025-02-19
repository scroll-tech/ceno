use core::fmt::Debug;
use ff_ext::ExtensionField;
use p3_field::{FieldExtensionAlgebra, PrimeField};
use p3_symmetric::CryptographicPermutation;
use std::ops::{Deref, DerefMut};

pub use p3_challenger::*;

use crate::poseidon::PoseidonField;

// pub trait FieldChallengerExt<F: Field>: FieldChallenger<F> {
//     fn observe_ext_slice<EF: FieldExtensionAlgebra<F>>(&mut self, exts: &[EF]) {
//         exts.iter()
//             .for_each(|ext| self.observe_slice(ext.as_base_slice()));
//     }

//     fn sample_ext_vec<EF: FieldExtensionAlgebra<F>>(&mut self, n: usize) -> Vec<EF> {
//         (0..n).map(|_| self.sample_ext_element()).collect()
//     }
// }

// impl<F: Field, T: FieldChallenger<F>> FieldChallengerExt<F> for T {}

#[derive(Clone, Debug)]
pub struct DefaultChallenger<F, P>
where
    F: PrimeField,
    P: CryptographicPermutation<[F; 8]>,
{
    inner: DuplexChallenger<F, P, 8, 4>,
}

impl<F, P> DefaultChallenger<F, P>
where
    F: PrimeField,
    P: CryptographicPermutation<[F; 8]>,
{
    pub fn new(perm: P) -> Self {
        Self {
            inner: DuplexChallenger::<F, P, 8, 4>::new(perm),
        }
    }
}

impl<F: PoseidonField> DefaultChallenger<F, F::T>
where
    F::T: CryptographicPermutation<[F; 8]>,
{
    pub fn new_poseidon_default() -> Self {
        Self {
            inner: DuplexChallenger::<F, F::T, 8, 4>::new(F::get_perm()),
        }
    }
}

// pub trait Default<T> {
//     fn default_new() -> T;
// }

// impl Default<Self> for DefaultChallenger<Goldilocks, Poseidon2GoldilocksHL<8>> {
//     fn default_new() -> Self {
//         let perm: Poseidon2GoldilocksHL<8> = Poseidon2GoldilocksHL::new(
//             ExternalLayerConstants::<Goldilocks, 8>::new_from_saved_array(
//                 HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
//                 new_array,
//             ),
//             new_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
//         );
//         Self::new(perm)
//     }
// }

impl<F, P> Deref for DefaultChallenger<F, P>
where
    F: PrimeField,
    P: CryptographicPermutation<[F; 8]>,
{
    type Target = DuplexChallenger<F, P, 8, 4>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, P> DerefMut for DefaultChallenger<F, P>
where
    F: PrimeField,
    P: CryptographicPermutation<[F; 8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub trait FieldChallengerExt<F: PoseidonField>: FieldChallenger<F> {
    fn observe_ext_slice<E: ExtensionField<BaseField = F>>(&mut self, exts: &[E]) {
        exts.iter()
            .for_each(|ext| self.observe_slice(ext.as_base_slice()));
    }

    fn sample_ext_vec<EF: FieldExtensionAlgebra<F>>(&mut self, n: usize) -> Vec<EF> {
        (0..n).map(|_| self.sample_ext_element()).collect()
    }
}

impl<F, P> CanObserve<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; 8]>,
{
    fn observe(&mut self, value: F) {
        self.inner.observe(value);
    }
}

impl<F, P> CanSampleBits<usize> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; 8]>,
{
    fn sample_bits(&mut self, _bits: usize) -> usize {
        todo!()
    }
}

impl<F, P> CanSample<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; 8]>,
{
    fn sample(&mut self) -> F {
        self.inner.sample()
    }
}

impl<F, P> FieldChallenger<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; 8]>,
{
}

impl<F, P> FieldChallengerExt<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; 8]>,
{
}

// impl<F, T, H> CanObserve<T> for DefaultChallenger<F, H>
// where
//     T: Serialize,
//     H: CryptographicHasher<u8, [u8; 32]>,
// {
//     fn observe(&mut self, value: T) {
//         todo!()
//     }
// }

// impl<F, E, H> CanSample<E> for DefaultChallenger<F, H>
// where
//     F: SmallField,
//     E: ExtensionField,
//     H: CryptographicHasher<u8, [u8; 32]>,
// {
//     fn sample(&mut self) -> E {
//         let sample_base = |inner: &mut HashChallenger<u8, H, 32>| {
//             F::from_uniform_bytes(|bytes| bytes.fill_with(|| inner.sample()))
//         };
//         E::from_base_fn(|_| sample_base(&mut self.inner))
//     }
// }

// impl<F, H> CanSampleBits<usize> for DefaultChallenger<F, H>
// where
//     H: CryptographicHasher<u8, [u8; 32]>,
// {
//     fn sample_bits(&mut self, bits: usize) -> usize {
//         usize::from_le_bytes(self.inner.sample_array()) & ((1 << bits) - 1)
//     }
// }

// impl<F, H> FieldChallenger<F> for DefaultChallenger<F, H>
// where
//     F: Sync + Field + FromUniformBytes,
//     H: Sync + CryptographicHasher<u8, [u8; 32]>,
// {
// }
