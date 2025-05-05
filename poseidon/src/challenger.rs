use core::fmt::Debug;
use ff_ext::{FieldChallengerExt, PoseidonField};
use std::ops::{Deref, DerefMut};

pub use p3::challenger::*;

/// this wrap a DuplexChallenger as inner field,
/// while expose some factory method to create default permutation object with defined constant
#[derive(Clone, Debug)]
pub struct DefaultChallenger<F>
where
    F: PoseidonField,
{
    inner: F::T,
}

impl<F> DefaultChallenger<F>
where
    F: PoseidonField,
{
    pub fn new(inner: F::T) -> Self {
        Self { inner }
    }
}

impl<F: PoseidonField> DefaultChallenger<F> {
    pub fn new_poseidon_default() -> Self {
        DefaultChallenger::new(F::get_default_challenger())
    }
}

impl<F: PoseidonField> Deref for DefaultChallenger<F> {
    type Target = F::T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F: PoseidonField> DerefMut for DefaultChallenger<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<F> CanObserve<F> for DefaultChallenger<F>
where
    F: PoseidonField,
{
    fn observe(&mut self, value: F) {
        self.inner.observe(value);
    }
}

impl<F> CanSampleBits<usize> for DefaultChallenger<F>
where
    F: PoseidonField,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl<F> CanSample<F> for DefaultChallenger<F>
where
    F: PoseidonField,
{
    fn sample(&mut self) -> F {
        self.inner.sample()
    }
}

impl<F> GrindingChallenger for DefaultChallenger<F>
where
    F: PoseidonField,
    F::T: GrindingChallenger,
{
    type Witness = <<F as PoseidonField>::T as GrindingChallenger>::Witness;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        self.inner.grind(bits)
    }
}

impl<F> FieldChallenger<F> for DefaultChallenger<F> where F: PoseidonField {}

impl<F> FieldChallengerExt<F> for DefaultChallenger<F> where F: PoseidonField {}
