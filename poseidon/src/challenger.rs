use core::fmt::Debug;
use ff_ext::ExtensionField;
use p3_challenger::{
    CanObserve, CanSample as P3CanSample, CanSampleBits, DuplexChallenger, FieldChallenger,
};
use p3_field::PrimeField;
use p3_symmetric::CryptographicPermutation;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use ff_ext::PoseidonField;
#[cfg(feature = "hash_count")]
use p3_field::BasedVectorSpace;

/// this wrap a DuplexChallenger as inner field,
/// while expose some factory method to create default permutation object with defined constant
#[derive(Clone, Debug)]
pub struct DefaultChallenger<F, P>
where
    F: PrimeField,
    P: CryptographicPermutation<[F; 8]>,
{
    inner: DuplexChallenger<F, P, 8, 4>,
    #[cfg(feature = "hash_count")]
    tracking: HashMap<&'static str, usize>,
}

impl<F, P> DefaultChallenger<F, P>
where
    F: PrimeField,
    P: CryptographicPermutation<[F; 8]>,
{
    pub fn new(perm: P) -> Self {
        Self {
            inner: DuplexChallenger::<F, P, 8, 4>::new(perm),
            tracking: HashMap::default(),
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
            tracking: HashMap::default(),
        }
    }
}

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
            .for_each(|ext| self.observe_slice(ext.as_basis_coefficients_slice()));
    }

    fn sample_ext_vec<E: ExtensionField<BaseField = F>>(&mut self, n: usize) -> Vec<E> {
        (0..n).map(|_| self.sample_algebra_element()).collect()
    }

    #[cfg(feature = "hash_count")]
    fn sample_algebra_element_tracking<A: BasedVectorSpace<F>>(
        &mut self,
        source: &'static str,
    ) -> A;

    #[cfg(feature = "hash_count")]
    fn sample_ext_vec_tracking<E: ExtensionField<BaseField = F>>(
        &mut self,
        n: usize,
        _source: &'static str,
    ) -> Vec<E>;
}

#[cfg(feature = "hash_count")]
pub trait CanSample<F: PrimeField>: P3CanSample<F> {
    fn sample_tracking(&mut self, source: &'static str) -> F;
    fn sample_vec_tracking(&mut self, n: usize, source: &'static str) -> Vec<F>;
    fn sample_array_tracking<const N: usize>(&mut self, source: &'static str) -> [F; N];
}

impl<F, P> P3CanSample<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; 8]>,
{
    fn sample(&mut self) -> F {
        self.inner.sample()
    }
}

#[cfg(feature = "hash_count")]
impl<F, P> CanSample<F> for DefaultChallenger<F, P>
where
    F: PoseidonField,
    P: CryptographicPermutation<[F; 8]>,
{
    fn sample_tracking(&mut self, source: &'static str) -> F {
        *self.tracking.entry(source).or_default() += 1;
        self.inner.sample()
    }

    fn sample_vec_tracking(&mut self, n: usize, source: &'static str) -> Vec<F> {
        *self.tracking.entry(source).or_default() += n;
        self.inner.sample_vec(n)
    }

    fn sample_array_tracking<const N: usize>(&mut self, source: &'static str) -> [F; N] {
        *self.tracking.entry(source).or_default() += N;
        self.inner.sample_array()
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
    #[cfg(feature = "hash_count")]
    fn sample_ext_vec_tracking<E: ExtensionField<BaseField = F>>(
        &mut self,
        n: usize,
        source: &'static str,
    ) -> Vec<E> {
        *self.tracking.entry(source).or_default() += n;
        (0..n).map(|_| self.sample_algebra_element()).collect()
    }

    fn sample_algebra_element_tracking<A: BasedVectorSpace<F>>(
        &mut self,
        source: &'static str,
    ) -> A {
        *self.tracking.entry(source).or_default() += 1;
        <Self as FieldChallenger<F>>::sample_algebra_element(self)
    }
}
