use std::array;

use crossbeam_channel::{Receiver, Sender, bounded};
use ff_ext::ExtensionField;
use p3::challenger::{CanSampleBits, GrindingChallenger};
use poseidon::challenger::CanObserve;

use crate::{Challenge, Transcript};

#[derive(Clone)]
pub struct TranscriptSyncronized<E: ExtensionField> {
    ef_append_tx: [Sender<Vec<E>>; 2],
    ef_append_rx: [Receiver<Vec<E>>; 2],
    bf_append_tx: [Sender<Vec<E::BaseField>>; 2],
    bf_append_rx: [Receiver<Vec<E::BaseField>>; 2],
    challenge_rx: [Receiver<E>; 2],
    challenge_tx: [Sender<E>; 2],
    rolling_index: usize,
}

impl<E: ExtensionField> TranscriptSyncronized<E> {
    /// Create a new IOP transcript.
    pub fn new(max_thread_id: usize) -> Self {
        let (bf_append_tx, bf_append_rx) = array::from_fn::<_, 2, _>(|_| bounded(max_thread_id))
            .into_iter()
            .unzip::<_, _, Vec<Sender<Vec<E::BaseField>>>, Vec<Receiver<Vec<E::BaseField>>>>();
        let (ef_append_tx, ef_append_rx) = array::from_fn::<_, 2, _>(|_| bounded(max_thread_id))
            .into_iter()
            .unzip::<_, _, Vec<Sender<Vec<E>>>, Vec<Receiver<Vec<E>>>>();
        let (challenge_tx, challenge_rx) = array::from_fn::<_, 2, _>(|_| bounded(max_thread_id))
            .into_iter()
            .unzip::<_, _, Vec<Sender<E>>, Vec<Receiver<E>>>();

        Self {
            bf_append_rx: bf_append_rx.try_into().unwrap(),
            bf_append_tx: bf_append_tx.try_into().unwrap(),
            ef_append_rx: ef_append_rx.try_into().unwrap(),
            ef_append_tx: ef_append_tx.try_into().unwrap(),
            challenge_tx: challenge_tx.try_into().unwrap(),
            challenge_rx: challenge_rx.try_into().unwrap(),
            rolling_index: 0,
        }
    }
}

impl<E: ExtensionField> Transcript<E> for TranscriptSyncronized<E> {
    fn append_field_element(&mut self, element: &E::BaseField) {
        self.bf_append_tx[self.rolling_index]
            .send(vec![*element])
            .unwrap();
    }

    fn append_field_element_exts(&mut self, element: &[E]) {
        self.ef_append_tx[self.rolling_index]
            .send(element.to_vec())
            .unwrap();
    }

    fn append_field_element_exts_iter<'a>(&mut self, element: impl Iterator<Item = &'a E>) {
        self.ef_append_tx[self.rolling_index]
            .send(element.copied().collect::<Vec<_>>())
            .unwrap();
    }

    fn append_challenge(&mut self, _challenge: Challenge<E>) {
        unimplemented!()
    }

    fn sample_and_append_challenge(&mut self, _label: &'static [u8]) -> Challenge<E> {
        Challenge {
            elements: self.challenge_rx[self.rolling_index].recv().unwrap(),
        }
    }

    fn read_field_element_exts(&self) -> Vec<E> {
        self.ef_append_rx[self.rolling_index].recv().unwrap()
    }

    fn read_field_element(&self) -> E::BaseField {
        self.bf_append_rx[self.rolling_index].recv().unwrap()[0]
    }

    fn read_challenge(&mut self) -> Challenge<E> {
        unimplemented!()
    }

    fn send_challenge(&self, challenge: E) {
        self.challenge_tx[self.rolling_index]
            .send(challenge)
            .unwrap();
    }

    fn commit_rolling(&mut self) {
        self.rolling_index = (self.rolling_index + 1) % 2
    }

    fn sample_vec(&mut self, _n: usize) -> Vec<E> {
        unimplemented!()
    }
}

impl<E: ExtensionField> CanSampleBits<usize> for TranscriptSyncronized<E> {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        unimplemented!()
    }
}

impl<E: ExtensionField> CanObserve<E::BaseField> for TranscriptSyncronized<E> {
    fn observe(&mut self, _value: E::BaseField) {
        unimplemented!()
    }
}

impl<E: ExtensionField> GrindingChallenger for TranscriptSyncronized<E> {
    type Witness = E::BaseField;
    fn grind(&mut self, _bits: usize) -> E::BaseField {
        unimplemented!()
    }
    fn check_witness(&mut self, _bits: usize, _witness: E::BaseField) -> bool {
        unimplemented!()
    }
}
