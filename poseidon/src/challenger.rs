use core::fmt::Debug;
use ff_ext::ExtensionField;
use p3::symmetric::CryptographicPermutation;
use std::ops::{Deref, DerefMut};

pub use p3::challenger::*;

use ff_ext::PoseidonField;

/// this wrap a DuplexChallenger as inner field,
/// while expose some factory method to create default permutation object with defined constant
#[derive(Clone, Debug)]
pub struct DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    inner: DuplexChallenger<F, P, { F::PERM_WIDTH }, { F::RATE }>,
}

impl<F, P> DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    pub fn new(perm: P) -> Self {
        Self {
            inner: DuplexChallenger::<F, P, { F::PERM_WIDTH }, { F::RATE }>::new(perm),
        }
    }
}

impl<F: PoseidonField> DefaultChallenger<F, F::T>
where
    F::T: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    pub fn new_poseidon_default() -> Self {
        Self {
            inner: DuplexChallenger::<F, F::T, { F::PERM_WIDTH }, { F::RATE }>::new(F::get_perm()),
        }
    }
}

impl<F, P> Deref for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    type Target = DuplexChallenger<F, P, { F::PERM_WIDTH }, { F::RATE }>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, P> DerefMut for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub trait FieldChallengerExt<F: PoseidonField>: FieldChallenger<F> {
    fn observe_ext_slice<E: ExtensionField<BaseField = F>>(&mut self, exts: &[E]) {
        exts.iter()
            .for_each(|ext| self.observe_slice(ext.as_basis_coefficients_slice()));
    }

    fn sample_ext_vec<E: ExtensionField<BaseField = F>>(&mut self, n: usize) -> Vec<E> {
        (0..n).map(|_| self.sample_algebra_element()).collect()
    }
}

impl<F, P> CanObserve<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    fn observe(&mut self, value: F) {
        self.inner.observe(value);
    }
}

impl<F, P> CanSampleBits<usize> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    fn sample_bits(&mut self, _bits: usize) -> usize {
        todo!()
    }
}

impl<F, P> CanSample<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
    fn sample(&mut self) -> F {
        self.inner.sample()
    }
}

impl<F, P> FieldChallenger<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
}

impl<F, P> FieldChallengerExt<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; F::PERM_WIDTH]>,
    [(); F::RATE]:,
{
}
