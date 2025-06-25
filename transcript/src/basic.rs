use ff_ext::{ExtensionField, FieldChallengerExt};
use p3::challenger::{CanSampleBits, GrindingChallenger};
use poseidon::challenger::{CanObserve, DefaultChallenger, FieldChallenger};

use crate::{Challenge, ForkableTranscript, Transcript};
use ff_ext::SmallField;

#[derive(Clone)]
pub struct BasicTranscript<E: ExtensionField> {
    challenger: DefaultChallenger<E::BaseField>,
}

impl<E: ExtensionField> BasicTranscript<E> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        let mut challenger = DefaultChallenger::<E::BaseField>::new_poseidon_default();
        let label_f = E::BaseField::bytes_to_field_elements(label);
        challenger.observe_slice(label_f.as_slice());
        Self { challenger }
    }
}

impl<E: ExtensionField> Transcript<E> for BasicTranscript<E> {
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.challenger.observe_slice(elements);
    }

    fn append_field_element_ext(&mut self, element: &E) {
        self.challenger.observe_ext_element(*element);
    }

    fn read_challenge(&mut self) -> Challenge<E> {
        Challenge {
            elements: self.challenger.sample_ext_element(),
        }
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

    fn sample_vec(&mut self, n: usize) -> Vec<E> {
        self.challenger.sample_ext_vec(n)
    }
}

impl<E: ExtensionField> CanObserve<E::BaseField> for BasicTranscript<E> {
    fn observe(&mut self, value: E::BaseField) {
        self.challenger.observe(value)
    }
}

impl<E: ExtensionField> CanSampleBits<usize> for BasicTranscript<E> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.challenger.sample_bits(bits)
    }
}

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscript<E> {}

impl<E: ExtensionField> GrindingChallenger for BasicTranscript<E> {
    type Witness = E::BaseField;
    fn grind(&mut self, bits: usize) -> E::BaseField {
        self.challenger.grind(bits)
    }

    fn check_witness(&mut self, bits: usize, witness: E::BaseField) -> bool {
        self.challenger.check_witness(bits, witness)
    }
}
