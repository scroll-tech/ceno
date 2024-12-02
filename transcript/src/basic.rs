use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use poseidon::poseidon_permutation::PoseidonPermutation;

use crate::Challenge;

#[derive(Clone)]
pub struct Transcript<E: ExtensionField> {
    permutation: PoseidonPermutation<E::BaseField>,
}

impl<E: ExtensionField> Transcript<E> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        let mut perm = PoseidonPermutation::new(core::iter::repeat(E::BaseField::ZERO));
        let label_f = E::BaseField::bytes_to_field_elements(label);
        perm.set_from_slice(label_f.as_slice(), 0);
        perm.permute();
        Self { permutation: perm }
    }
}

impl<E: ExtensionField> Transcript<E> {
    /// Fork this transcript into n different threads.
    pub fn fork(self, n: usize) -> Vec<Self> {
        let mut forks = Vec::with_capacity(n);
        for i in 0..n {
            let mut fork = self.clone();
            fork.append_field_element(&(i as u64).into());
            forks.push(fork);
        }
        forks
    }

    // Append the message to the transcript.
    pub fn append_message(&mut self, msg: &[u8]) {
        let msg_f = E::BaseField::bytes_to_field_elements(msg);
        self.permutation.set_from_slice(&msg_f, 0);
        self.permutation.permute();
    }

    // Append the field extension element to the transcript.
    pub fn append_field_element_ext(&mut self, element: &E) {
        self.permutation.set_from_slice(element.as_bases(), 0);
        self.permutation.permute();
    }

    pub fn append_field_element_exts(&mut self, element: &[E]) {
        for e in element {
            self.append_field_element_ext(e);
        }
    }

    // Append the field elemetn to the transcript.
    pub fn append_field_element(&mut self, element: &E::BaseField) {
        self.permutation.set_from_slice(&[*element], 0);
        self.permutation.permute();
    }

    // Append the challenge to the transcript.
    pub fn append_challenge(&mut self, challenge: Challenge<E>) {
        self.permutation
            .set_from_slice(challenge.elements.as_bases(), 0);
        self.permutation.permute();
    }

    // // Append the message to the transcript.
    // pub fn append_serializable_element<S: Serialize>(
    //     &mut self,
    //     _label: &'static [u8],
    //     _element: &S,
    // ) {
    //     unimplemented!()
    // }

    // Generate the challenge from the current transcript
    // and append it to the transcript.
    //
    // The output field element is statistical uniform as long
    // as the field has a size less than 2^384.
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Challenge<E> {
        self.append_message(label);

        let challenge = Challenge {
            elements: E::from_limbs(self.permutation.squeeze()),
        };
        challenge
    }

    pub fn commit_rolling(&mut self) {
        // do nothing
    }

    pub fn read_field_element_ext(&self) -> E {
        unimplemented!()
    }

    pub fn read_field_element_exts(&self) -> Vec<E> {
        unimplemented!()
    }

    pub fn read_field_element(&self) -> E::BaseField {
        unimplemented!()
    }

    pub fn read_challenge(&mut self) -> Challenge<E> {
        let r = E::from_bases(&self.permutation.squeeze()[..2]);

        Challenge { elements: r }
    }

    pub fn send_challenge(&self, _challenge: E) {
        unimplemented!()
    }
}
