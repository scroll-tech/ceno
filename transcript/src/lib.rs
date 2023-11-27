//! This repo is not properly implemented
//! Transcript APIs are placeholders; the actual logic is to be implemented later.

use std::marker::PhantomData;

use goldilocks::SmallField;
use serde::Serialize;

// temporarily using 12-4 hashes
pub const INPUT_WIDTH: usize = 12;
pub const OUTPUT_WIDTH: usize = 12;

// TODO
#[derive(Default, Copy, Clone)]
pub struct Transcript<F> {
    is_empty: bool,
    state: [F; INPUT_WIDTH],
}

// TODO
#[derive(Default, Copy, Clone)]
pub struct Challenge<F> {
    pub elements: [F; OUTPUT_WIDTH],
}

impl<F: SmallField> Transcript<F> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        // TODO!
        println!("mock function. remember to fix me");
        Self::default()
    }

    // Append the message to the transcript.
    pub fn append_message(&mut self, msg: &[u8]) {
        // TODO!
        println!("mock function. remember to fix me");
    }

    // Append the field elemetn to the transcript.
    pub fn append_field_element(&mut self, element: F) {
        // TODO!
        println!("mock function. remember to fix me");
    }

    // Append the challenge to the transcript.
    pub fn append_challenge(&mut self, challenge: Challenge<F>) {
        // TODO!
        println!("mock function. remember to fix me");
    }

    // Append the message to the transcript.
    pub fn append_serializable_element<S: Serialize>(&mut self, label: &'static [u8], element: &S) {
        // TODO!
        println!("mock function. remember to fix me");
    }

    // Generate the challenge from the current transcript
    // and append it to the transcript.
    //
    // The output field element is statistical uniform as long
    // as the field has a size less than 2^384.
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Challenge<F> {
        //  we need to reject when transcript is empty
        println!("mock function. remember to fix me");
        assert!(!self.is_empty);
        Challenge::<F>::default()
    }
}
