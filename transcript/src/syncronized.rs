use std::array;

use crossbeam_channel::{bounded, Receiver, Sender};
use ff_ext::ExtensionField;
use goldilocks::SmallField;

use crate::Challenge;

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

impl<E: ExtensionField> TranscriptSyncronized<E> {
    // Append the message to the transcript.
    pub fn append_message(&mut self, msg: &[u8]) {
        let msg_f = E::BaseField::bytes_to_field_elements(msg);
        self.bf_append_tx[self.rolling_index].send(msg_f).unwrap();
    }

    pub fn append_field_element_ext(&mut self, element: &E) {
        self.ef_append_tx[self.rolling_index]
            .send(vec![*element])
            .unwrap();
    }

    pub fn append_field_element_exts(&mut self, element: &[E]) {
        self.ef_append_tx[self.rolling_index]
            .send(element.to_vec())
            .unwrap();
    }

    pub fn append_field_element(&mut self, element: &E::BaseField) {
        self.bf_append_tx[self.rolling_index]
            .send(vec![*element])
            .unwrap();
    }

    pub fn append_challenge(&mut self, _challenge: Challenge<E>) {
        unimplemented!()
    }

    pub fn get_and_append_challenge(&mut self, _label: &'static [u8]) -> Challenge<E> {
        Challenge {
            elements: self.challenge_rx[self.rolling_index].recv().unwrap(),
        }
        // loop {
        //     match self.challenge_rx[self.rolling_index].try_recv() {
        //         Ok(val) => {
        //             return Challenge { elements: val };
        //         }
        //         Err(TryRecvError::Empty) => {
        //             // keey rayon thread busy and avoid "rayon::yield_now"
        //             // rayon::yield_now();
        //         }
        //         Err(e) => {
        //             panic!("Error: {}", e);
        //         }
        //     }
        // }
    }

    pub fn read_field_element_ext(&self) -> E {
        self.ef_append_rx[self.rolling_index].recv().unwrap()[0]
    }

    pub fn read_field_element_exts(&self) -> Vec<E> {
        self.ef_append_rx[self.rolling_index].recv().unwrap()
    }

    pub fn read_field_element(&self) -> E::BaseField {
        self.bf_append_rx[self.rolling_index].recv().unwrap()[0]
    }

    pub fn read_challenge(&self, _challenge: Challenge<E>) {
        unimplemented!()
    }

    pub fn send_challenge(&self, challenge: E) {
        self.challenge_tx[self.rolling_index]
            .send(challenge)
            .unwrap();
    }

    pub fn commit_rolling(&mut self) {
        self.rolling_index = (self.rolling_index + 1) % 2
    }
}
