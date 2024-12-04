use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use poseidon::poseidon_permutation::PoseidonPermutation;

use crate::Challenge;

/// The Transcript trait
pub trait Transcript<E: ExtensionField> {
    /// Append slice of base field elemets to the transcript. Implement
    /// has to override at least one of append_field_elements / append_field_element
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        for e in elements {
            self.append_field_element(e);
        }
    }

    // Append a single field element to the transcript. Implement
    /// has to override at least one of append_field_elements / append_field_element
    fn append_field_element(&mut self, element: &E::BaseField) {
        self.append_field_elements(&[*element])
    }

    /// Append the message to the transcript.
    fn append_message(&mut self, msg: &[u8]) {
        let msg_f = E::BaseField::bytes_to_field_elements(msg);
        self.append_field_elements(&msg_f);
    }

    /// Append the field extension element to the transcript.Implement
    /// has to override at least one of append_field_element_ext / append_field_element_exts
    fn append_field_element_ext(&mut self, element: &E) {
        self.append_field_element_exts(&[*element])
    }

    /// Append slice of field extension elements to the transcript. Implement
    /// has to override at least one of append_field_element_ext / append_field_element_exts
    fn append_field_element_exts(&mut self, element: &[E]) {
        for e in element {
            self.append_field_element_ext(e);
        }
    }

    /// Append the challenge to the transcript.
    fn append_challenge(&mut self, challenge: Challenge<E>) {
        self.append_field_element_ext(&challenge.elements)
    }

    // // Append the message to the transcript.
    // pub fn append_serializable_element<S: Serialize>(
    //     &mut self,
    //     _label: &'static [u8],
    //     _element: &S,
    // ) {
    //     unimplemented!()
    // }

    /// Generate the challenge from the current transcript
    /// and append it to the transcript.
    ///
    /// The output field element is statistical uniform as long
    /// as the field has a size less than 2^384.
    fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Challenge<E> {
        self.append_message(label);
        self.read_challenge()
    }

    fn read_field_element_ext(&self) -> E {
        self.read_field_element_exts()[0]
    }

    fn read_field_element_exts(&self) -> Vec<E>;

    fn read_field_element(&self) -> E::BaseField;

    fn read_challenge(&mut self) -> Challenge<E>;

    fn send_challenge(&self, challenge: E);

    fn commit_rolling(&mut self) {
        // do nothing
    }
}

pub trait ForkableTranscript<E: ExtensionField>: Transcript<E> + Sized + Clone {
    /// Fork this transcript into n different threads.
    fn fork(self, n: usize) -> Vec<Self> {
        let mut forks = Vec::with_capacity(n);
        for i in 0..n {
            let mut fork = self.clone();
            fork.append_field_element(&(i as u64).into());
            forks.push(fork);
        }
        forks
    }
}

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
}

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscript<E> {}
