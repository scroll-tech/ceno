use crate::{BasicTranscript, Challenge, ForkableTranscript, Transcript};
use ff_ext::ExtensionField;
use std::cell::RefCell;

#[derive(Debug, Default)]
pub struct StatisticRecorder {
    pub field_appended_num: u32,
}

pub type SharedStatisticRecorder = RefCell<StatisticRecorder>;

#[derive(Clone)]
pub struct BasicTranscriptWitStat<'a, E: ExtensionField> {
    inner: BasicTranscript<E>,
    stat: &'a SharedStatisticRecorder,
}

impl<'a, E: ExtensionField> BasicTranscriptWitStat<'a, E> {
    pub fn new(stat: &'a SharedStatisticRecorder, label: &'static [u8]) -> Self {
        Self {
            inner: BasicTranscript::<_>::new(label),
            stat,
        }
    }
}

impl<E: ExtensionField> Transcript<E> for BasicTranscriptWitStat<'_, E> {
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.stat.borrow_mut().field_appended_num += 1;
        self.inner.append_field_elements(elements)
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
}

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscriptWitStat<'_, E> {}
