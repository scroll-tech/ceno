use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use poseidon::poseidon_permutation::PoseidonPermutation;

use crate::{Challenge, ForkableTranscript, Transcript};

#[derive(Clone)]
pub struct BasicTranscript<E: ExtensionField> {
    permutation: PoseidonPermutation<E::BaseField>,
}

impl<E: ExtensionField> BasicTranscript<E> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        let mut perm = PoseidonPermutation::new(core::iter::repeat(E::BaseField::ZERO));
        let label_f = E::BaseField::bytes_to_field_elements(label);
        perm.set_from_slice(label_f.as_slice(), 0);
        perm.permute();
        Self { permutation: perm }
    }
}

impl<E: ExtensionField> Transcript<E> for BasicTranscript<E> {
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.permutation.set_from_slice(elements, 0);
        self.permutation.permute();
    }

    fn append_field_element_ext(&mut self, element: &E) {
        self.append_field_elements(element.as_bases())
    }

    fn read_challenge(&mut self) -> Challenge<E> {
        let r = E::from_bases(self.permutation.squeeze());

        Challenge { elements: r }
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

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscript<E> {}
