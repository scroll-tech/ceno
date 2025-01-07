use std::array;

use crate::{Challenge, ForkableTranscript, Transcript};
use ff_ext::{ExtensionField, SmallField};
use p3_field::{FieldAlgebra, PrimeField};
use p3_mds::MdsPermutation;
use p3_poseidon::Poseidon;
use p3_symmetric::Permutation;

#[derive(Clone)]
pub struct BasicTranscript<E: ExtensionField, Mds> {
    // TODO generalized to accept general permutation
    poseidon: Poseidon<E::BaseField, Mds, 8, 7>,
    state: [E::BaseField; 8],
}

impl<E: ExtensionField, Mds> BasicTranscript<E, Mds>
where
    Mds: MdsPermutation<E::BaseField, 8> + Default,
{
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        let mds = Mds::default();

        // TODO: Should be calculated for the particular field, width and ALPHA.
        let half_num_full_rounds = 4;
        let num_partial_rounds = 22;

        let num_rounds = 2 * half_num_full_rounds + num_partial_rounds;
        let num_constants = 8 * num_rounds;
        let constants = vec![E::BaseField::ZERO; num_constants];

        let poseidon = Poseidon::<E::BaseField, _, _, _>::new(
            half_num_full_rounds,
            num_partial_rounds,
            constants,
            mds,
        );
        let input: [E::BaseField; 8] = array::from_fn(|_| E::BaseField::ZERO);
        let label_f = E::BaseField::bytes_to_field_elements(label);
        let mut new = BasicTranscript::<E, _> {
            poseidon,
            state: input,
        };
        new.set_from_slice(label_f.as_slice(), 0);
        new.poseidon.permute_mut(&mut new.state);
        new
    }

    /// Set state element `i` to be `elts[i] for i =
    /// start_idx..start_idx + n` where `n = min(elts.len(),
    /// WIDTH-start_idx)`. Panics if `start_idx > SPONGE_WIDTH`.
    fn set_from_slice(&mut self, elts: &[E::BaseField], start_idx: usize) {
        let begin = start_idx;
        let end = start_idx + elts.len();
        self.state[begin..end].copy_from_slice(elts)
    }
}

impl<E: ExtensionField, Mds> Transcript<E> for BasicTranscript<E, Mds>
where
    Mds: MdsPermutation<E::BaseField, 8> + Default,
{
    fn append_field_element_ext(&mut self, element: &E) {
        self.append_field_elements(element.as_bases());
    }

    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.set_from_slice(elements, 0);
        self.poseidon.permute_mut(&mut self.state);
    }

    fn read_challenge(&mut self) -> Challenge<E> {
        // Notice `from_bases` and `from_limbs` have the same behavior but
        // `from_bases` has a sanity check for length of input slices
        // while `from_limbs` use the first two elements silently.
        // We select `from_base` here to make it more clear that
        // we only use the first 2 fields here to construct the
        // challenge as an extension field element.
        let elements = E::from_bases(&self.state[..8][..2]);

        Challenge { elements }
    }

    fn read_field_element_exts(&self) -> Vec<E> {
        unimplemented!()
    }

    fn read_field_element(&self) -> E::BaseField {
        unimplemented!()
    }

    fn send_challenge(&self, _challenge: E) {
        unimplemented!()
    }

    fn commit_rolling(&mut self) {
        // do nothing
    }
}

impl<E: ExtensionField, Mds> ForkableTranscript<E> for BasicTranscript<E, Mds>
where
    E::BaseField: FieldAlgebra + PrimeField,
    Mds: MdsPermutation<E::BaseField, 8> + Default,
{
}
