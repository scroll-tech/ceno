use p3_field::PrimeField;
use p3_mds::MdsPermutation;
use p3_poseidon::Poseidon;

use crate::{
    constants::{
        ALL_ROUND_CONSTANTS, HALF_N_FULL_ROUNDS, N_PARTIAL_ROUNDS, SPONGE_RATE, SPONGE_WIDTH,
    },
    poseidon::PoseidonField,
};
use p3_symmetric::Permutation;

// follow https://github.com/Plonky3/Plonky3/blob/main/poseidon/benches/poseidon.rs#L22
pub(crate) const ALPHA: u64 = 7;

#[derive(Clone)]
pub struct PoseidonPermutation<T: PoseidonField, Mds> {
    poseidon: Poseidon<T, Mds, SPONGE_WIDTH, ALPHA>,
    state: [T; SPONGE_WIDTH],
}

impl<T: PoseidonField + PrimeField, Mds> PoseidonPermutation<T, Mds>
where
    Mds: MdsPermutation<T, SPONGE_WIDTH> + Default,
{
    /// Initialises internal state with values from `iter` until
    /// `iter` is exhausted or `SPONGE_WIDTH` values have been
    /// received; remaining state (if any) initialised with
    /// `T::default()`. To initialise remaining elements with a
    /// different value, instead of your original `iter` pass
    /// `iter.chain(core::iter::repeat(F::from_canonical_u64(12345)))`
    /// or similar.
    pub fn new<I: IntoIterator<Item = T>>(elts: I) -> Self {
        let mut perm = Self {
            poseidon: Poseidon::<T, _, SPONGE_WIDTH, ALPHA>::new(
                HALF_N_FULL_ROUNDS,
                N_PARTIAL_ROUNDS,
                ALL_ROUND_CONSTANTS.map(T::from_canonical_u64).to_vec(),
                Mds::default(),
            ),
            state: [T::default(); SPONGE_WIDTH],
        };
        perm.set_from_iter(elts, 0);
        perm
    }

    /// Set state element `i` to be `elts[i] for i =
    /// start_idx..start_idx + n` where `n = min(elts.len(),
    /// WIDTH-start_idx)`. Panics if `start_idx > SPONGE_WIDTH`.
    pub fn set_from_slice(&mut self, elts: &[T], start_idx: usize) {
        let begin = start_idx;
        let end = start_idx + elts.len();
        self.state[begin..end].copy_from_slice(elts)
    }

    /// Same semantics as for `set_from_iter` but probably faster than
    /// just calling `set_from_iter(elts.iter())`.
    fn set_from_iter<I: IntoIterator<Item = T>>(&mut self, elts: I, start_idx: usize) {
        for (s, e) in self.state[start_idx..].iter_mut().zip(elts) {
            *s = e;
        }
    }

    /// Apply permutation to internal state
    pub fn permute(&mut self) {
        self.poseidon.permute_mut(&mut self.state);
    }

    /// Return a slice of `RATE` elements
    pub fn squeeze(&self) -> &[T] {
        &self.state[..SPONGE_RATE]
    }
}
