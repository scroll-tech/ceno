use crate::{BasicTranscript, Challenge, ForkableTranscript, Transcript};
use ff_ext::{ExtensionField, PoseidonField};
use poseidon::challenger::DefaultChallenger;
use std::cell::RefCell;

#[derive(Debug, Default)]
pub struct Statistic {
    pub field_appended_num: u32,
}

pub type StatisticRecorder = RefCell<Statistic>;

#[derive(Clone)]
pub struct BasicTranscriptWithStat<'a, E: ExtensionField> {
    inner: BasicTranscript<E>,
    stat: &'a StatisticRecorder,
}

impl<'a, E: ExtensionField> BasicTranscriptWithStat<'a, E> {
    pub fn new(stat: &'a StatisticRecorder, label: &'static [u8]) -> Self {
        Self {
            inner: BasicTranscript::new(label),
            stat,
        }
    }
}

impl<E: ExtensionField> Transcript<E> for BasicTranscriptWithStat<'_, E> {
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.stat.borrow_mut().field_appended_num += 1;
        self.inner.append_field_elements(elements)
    }

    #[cfg(feature = "ro_query_stats")]
    fn read_challenge_tracking(&mut self, source: &'static str) -> Challenge<E> {
        self.inner.read_challenge_tracking(source)
    }

    fn append_field_element_ext(&mut self, element: &E) {
        self.stat.borrow_mut().field_appended_num += E::DEGREE as u32;
        self.inner.append_field_element_ext(element)
    }

    fn read_challenge(&mut self) -> Challenge<E> {
        self.inner.read_challenge()
    }

    fn read_field_element_exts(&self) -> Vec<E> {
        self.inner.read_field_element_exts()
    }

    fn read_field_element(&self) -> E::BaseField {
        self.inner.read_field_element()
    }

    fn send_challenge(&self, challenge: E) {
        self.inner.send_challenge(challenge)
    }

    fn commit_rolling(&mut self) {
        self.inner.commit_rolling()
    }

    fn sample_vec(&mut self, n: usize) -> Vec<E> {
        self.inner.sample_vec(n)
    }

    #[cfg(feature = "ro_query_stats")]
    fn sample_vec_tracking(&mut self, n: usize, source: &'static str) -> std::vec::Vec<E> {
        self.inner.sample_vec_tracking(n, source)
    }

    fn get_inner_challenger(
        &self,
    ) -> &DefaultChallenger<E::BaseField, <E::BaseField as PoseidonField>::T> {
        self.inner.get_inner_challenger()
    }
}

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscriptWithStat<'_, E> {}
