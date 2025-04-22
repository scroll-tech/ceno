use crate::{BasicTranscript, Challenge, ForkableTranscript, GrindingChallenger, Transcript};
use ff_ext::ExtensionField;
use p3::challenger::{CanObserve, CanSampleBits};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct Statistic {
    pub field_appended_num: u32,
}

pub type StatisticRecorder = Arc<Mutex<Statistic>>;

#[derive(Clone)]
pub struct BasicTranscriptWithStat<E: ExtensionField> {
    inner: BasicTranscript<E>,
    stat: StatisticRecorder,
}

impl<E: ExtensionField> BasicTranscriptWithStat<E> {
    pub fn new(stat: Arc<Mutex<Statistic>>, label: &'static [u8]) -> Self {
        Self {
            inner: BasicTranscript::new(label),
            stat,
        }
    }
}

impl<E: ExtensionField> Transcript<E> for BasicTranscriptWithStat<E> {
    fn append_field_elements(&mut self, elements: &[E::BaseField]) {
        if let Ok(mut stat) = self.stat.lock() {
            stat.field_appended_num += 1;
        } else {
            panic!("StatisticRecorder mutex is poisoned");
        }
        self.inner.append_field_elements(elements)
    }

    fn append_field_element_ext(&mut self, element: &E) {
        if let Ok(mut stat) = self.stat.lock() {
            stat.field_appended_num += E::DEGREE as u32;
        } else {
            panic!("statisticRecorder mutex is poisoned");
        }
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
}

impl<E: ExtensionField> CanObserve<E::BaseField> for BasicTranscriptWithStat<E> {
    fn observe(&mut self, value: E::BaseField) {
        self.inner.observe(value)
    }
}

impl<E: ExtensionField> CanSampleBits<usize> for BasicTranscriptWithStat<E> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl<E: ExtensionField> GrindingChallenger for BasicTranscriptWithStat<E> {
    type Witness = E::BaseField;
    fn grind(&mut self, bits: usize) -> E::BaseField {
        self.inner.grind(bits)
    }

    fn check_witness(&mut self, bits: usize, witness: E::BaseField) -> bool {
        self.inner.check_witness(bits, witness)
    }
}

impl<E: ExtensionField> ForkableTranscript<E> for BasicTranscriptWithStat<E> {}
