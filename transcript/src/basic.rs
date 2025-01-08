use ff_ext::ExtensionField;
use p3_mds::MdsPermutation;
use poseidon::{SPONGE_WIDTH, poseidon_permutation::PoseidonPermutation};

use crate::{Challenge, ForkableTranscript, Transcript};
use ff_ext::SmallField;
use p3_field::FieldAlgebra;

#[derive(Clone)]
pub struct BasicTranscript<E: ExtensionField, Mds> {
    permutation: PoseidonPermutation<E::BaseField, Mds>,
}

impl<E: ExtensionField, Mds> BasicTranscript<E, Mds>
where
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        let mut permutation = PoseidonPermutation::new(core::iter::repeat(E::BaseField::ZERO));
        let label_f = E::BaseField::bytes_to_field_elements(label);
        permutation.set_from_slice(label_f.as_slice(), 0);
        permutation.permute();
        Self { permutation }
    }
}

impl<E: ExtensionField, Mds> Transcript<E> for BasicTranscript<E, Mds>
where
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.permutation.set_from_slice(elements, 0);
        self.permutation.permute();
    }

    fn append_field_element_ext(&mut self, element: &E) {
        self.append_field_elements(element.as_bases())
    }

    fn read_challenge(&mut self) -> Challenge<E> {
        // Notice `from_bases` and `from_limbs` have the same behavior but
        // `from_bases` has a sanity check for length of input slices
        // while `from_limbs` use the first two elements silently.
        // We select `from_base` here to make it more clear that
        // we only use the first 2 fields here to construct the
        // challenge as an extension field element.
        let elements = E::from_bases(&self.permutation.squeeze()[..2]);

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

impl<E: ExtensionField, Mds> ForkableTranscript<E> for BasicTranscript<E, Mds> where
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default
{
}
