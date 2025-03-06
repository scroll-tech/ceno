use crate::{BasicTranscript, Challenge, ForkableTranscript, Transcript};
use ff_ext::ExtensionField;
use std::cell::RefCell;

#[derive(Debug, Default)]
pub struct Statistic {
    pub field_appended_num: u32,
}

pub type StatisticRecorder = RefCell<Statistic>;
pub type TranscriptRecorder<E> = RefCell<BasicTranscript<E>>;

#[derive(Clone)]
pub struct BasicTranscriptWithStat<'a, E: ExtensionField> {
    inner: &'a TranscriptRecorder<E>,
    // TODO merge stats into basic BasicTranscript
    stat: &'a StatisticRecorder,
}

impl<'a, E: ExtensionField> BasicTranscriptWithStat<'a, E> {
    pub fn new(stat: &'a StatisticRecorder, inner: &'a TranscriptRecorder<E>) -> Self {
        Self { inner, stat }
    }
}

impl<E: ExtensionField> Transcript<E> for BasicTranscriptWithStat<'_, E> {
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.stat.borrow_mut().field_appended_num += 1;
        self.inner.borrow_mut().append_field_elements(elements)
    }

    fn append_field_element_ext(&mut self, element: &E) {
        self.stat.borrow_mut().field_appended_num += E::DEGREE as u32;
        self.inner.borrow_mut().append_field_element_ext(element)
    }

    #[cfg(feature = "ro_query_stats")]
    fn read_challenge_tracking(&mut self, source: &'static str) -> Challenge<E> {
        self.inner.borrow_mut().read_challenge_tracking(source)
    }

    fn read_challenge(&mut self) -> Challenge<E> {
        self.inner.borrow_mut().read_challenge()
    }

    fn read_field_element_exts(&self) -> Vec<E> {
        self.inner.borrow().read_field_element_exts()
    }

    fn read_field_element(&self) -> E::BaseField {
        self.inner.borrow().read_field_element()
    }

    fn send_challenge(&self, challenge: E) {
        self.inner.borrow().send_challenge(challenge)
    }

    fn commit_rolling(&mut self) {
        self.inner.borrow_mut().commit_rolling()
    }
}

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscriptWithStat<'_, E> {}
