use crate::{BasicTranscript, Challenge, ForkableTranscript, Transcript};
use ff_ext::ExtensionField;
use p3_mds::MdsPermutation;
use poseidon::{SPONGE_WIDTH, poseidon::PoseidonField};
use std::cell::RefCell;

#[derive(Debug, Default)]
pub struct Statistic {
    pub field_appended_num: u32,
}

pub type StatisticRecorder = RefCell<Statistic>;

#[derive(Clone)]
pub struct BasicTranscriptWithStat<'a, E: ExtensionField, Mds>
where
    E::BaseField: PoseidonField,
{
    inner: BasicTranscript<E, Mds>,
    stat: &'a StatisticRecorder,
}

impl<'a, E: ExtensionField, Mds> BasicTranscriptWithStat<'a, E, Mds>
where
    E::BaseField: PoseidonField,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    pub fn new(stat: &'a StatisticRecorder, label: &'static [u8]) -> Self {
        Self {
            inner: BasicTranscript::<_, _>::new(label),
            stat,
        }
    }
}

impl<E: ExtensionField, Mds> Transcript<E> for BasicTranscriptWithStat<'_, E, Mds>
where
    E::BaseField: PoseidonField,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
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

impl<E: ExtensionField, Mds> ForkableTranscript<E> for BasicTranscriptWithStat<'_, E, Mds>
where
    E::BaseField: PoseidonField,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
}
