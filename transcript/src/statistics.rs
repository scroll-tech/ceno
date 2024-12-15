use crate::{BasicTranscript, Challenge, ForkableTranscript, Transcript};
use ff_ext::ExtensionField;
use std::{cell::RefCell, rc::Rc};

#[derive(Debug, Default)]
pub struct StatisticRecorder {
    pub field_appended_num: u32,
}

type SharedStatisticRecorder = RefCell<StatisticRecorder>;

impl StatisticRecorder {
    pub fn new() -> Rc<SharedStatisticRecorder> {
        Rc::new(RefCell::new(Default::default()))
    }
}

#[derive(Clone)]
pub struct BasicTranscriptWitStat<E: ExtensionField> {
    inner: BasicTranscript<E>,
    stat: Rc<SharedStatisticRecorder>,
    field_appended_num: u32,
}

impl<E: ExtensionField> BasicTranscriptWitStat<E> {
    pub fn new(stat: Rc<SharedStatisticRecorder>, label: &'static [u8]) -> Self {
        Self {
            inner: BasicTranscript::<_>::new(label),
            stat: stat.clone(),
            field_appended_num: 0,
        }
    }

    fn sync_stat(&mut self) {
        let cur_num = self.field_appended_num;
        self.stat.borrow_mut().field_appended_num += cur_num;
        self.field_appended_num = 0;
    }
}

impl<E: ExtensionField> Transcript<E> for BasicTranscriptWitStat<E> {
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        self.field_appended_num += 1;
        self.inner.append_field_elements(elements)
    }

    fn append_field_element_ext(&mut self, element: &E) {
        self.field_appended_num += E::DEGREE as u32;
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

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscriptWitStat<E> {
    fn fork(mut self, n: usize) -> Vec<Self> {
        self.sync_stat();
        let mut forks = Vec::with_capacity(n);
        for i in 0..n {
            let mut fork = self.clone();
            fork.append_field_element(&(i as u64).into());
            forks.push(fork);
        }
        forks
    }
}

impl<E: ExtensionField> std::ops::Drop for BasicTranscriptWitStat<E> {
    fn drop(&mut self) {
        self.sync_stat();
    }
}
