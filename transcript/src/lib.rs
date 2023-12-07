//! This repo is not properly implemented
//! Transcript APIs are placeholders; the actual logic is to be implemented later.

mod hasher;

use ff::{FromUniformBytes, PrimeField};
use goldilocks::SmallField;
use poseidon::Poseidon;

// temporarily using 12-4 hashes
pub const INPUT_WIDTH: usize = 12;
pub const OUTPUT_WIDTH: usize = 4;

#[derive(Clone)]
pub struct Transcript<F: PrimeField> {
    sponge_hasher: Poseidon<F, 12, 11>,
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub struct Challenge<F> {
    pub elements: [F; OUTPUT_WIDTH],
}

impl<F: SmallField + FromUniformBytes<64>> Transcript<F> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        // FIXME: change me the the right parameter
        let mut hasher = Poseidon::new(8, 22);
        let label_f = F::bytes_to_field_elements(label);
        hasher.update(label_f.as_slice());
        Self {
            sponge_hasher: hasher,
        }
    }

    // Append the message to the transcript.
    pub fn append_message(&mut self, msg: &[u8]) {
        let msg_f = F::bytes_to_field_elements(msg);
        self.sponge_hasher.update(&msg_f);
    }

    // Append the field elemetn to the transcript.
    pub fn append_field_element(&mut self, element: &F) {
        self.sponge_hasher.update(&[*element]);
    }

    // Append the challenge to the transcript.
    pub fn append_challenge(&mut self, challenge: Challenge<F>) {
        self.sponge_hasher.update(challenge.elements.as_slice())
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
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Challenge<F> {
        self.append_message(label);

        let challenge = Challenge {
            elements: self.sponge_hasher.squeeze_vec()[0..OUTPUT_WIDTH]
                .try_into()
                .unwrap(),
        };
        println!("challenge: {:?}", challenge);

        challenge
    }
}
