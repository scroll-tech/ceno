use super::plonky2_util::log2_strict;
use blake2b_simd::{
    many::{hash_many, HashManyJob},
    Params, State,
};
use ff::PrimeField;
use generic_array::GenericArray;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator, ParallelSlice,
};
use sha3::digest::{Digest, FixedOutput, HashMarker, OutputSizeUser, Reset};
pub use sha3::{
    digest::{FixedOutputReset, Output, Update},
    Keccak256,
};
use std::fmt::Debug;
use std::time::Instant;

pub use blake2::Blake2s256;
use generic_array::typenum::U32;
pub use poseidon::{self, Poseidon};

pub trait Hash:
    'static + Sized + Clone + Debug + FixedOutputReset + Default + Update + HashMarker
{
    fn new() -> Self {
        Self::default()
    }

    fn update_field_element(&mut self, field: &impl PrimeField) {
        Digest::update(self, field.to_repr());
    }

    fn update_consec_field_pairs(values: &Vec<impl PrimeField>) -> Vec<Output<Self>> {
        let _log_v = log2_strict(values.len());
        let mut hashes = vec![Output::<Self>::default(); values.len() >> 1];
        hashes.par_iter_mut().enumerate().for_each(|(i, hash)| {
            let mut hasher = Self::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            *hash = hasher.finalize_fixed();
        });
        hashes
    }

    fn update_consec_hash_pairs(values: &Vec<Output<Self>>) -> Vec<Output<Self>> {
        let _log_v = log2_strict(values.len());
        let oracle = values
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = Self::new();
                let _hash = Output::<Self>::default();
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect::<Vec<_>>();
        oracle
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut hasher = Self::default();
        hasher.update(data.as_ref());
        hasher.finalize()
    }
}

impl Hash for Keccak256 {}

impl Hash for Blake2s256 {}

impl Hash for Blake2s {
    fn update_consec_field_pairs(values: &Vec<impl PrimeField>) -> Vec<Output<Self>> {
        let v = values
            .par_chunks_exact(2)
            .map(|c| [c[0].to_repr().as_ref(), c[1].to_repr().as_ref()].concat())
            .collect::<Vec<Vec<u8>>>();
        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        let mut jobs = v
            .iter()
            .map(|v| HashManyJob::new(&params, v))
            .collect::<Vec<HashManyJob>>();

        hash_many(jobs.iter_mut());
        let mut output = Vec::with_capacity(v.len());
        for job in jobs.iter() {
            output.push(*GenericArray::from_slice(job.to_hash().as_bytes()));
        }
        output
    }
    fn new() -> Self {
        Self::default()
    }

    fn update_field_element(&mut self, field: &impl PrimeField) {
        Digest::update(self, field.to_repr());
    }

    fn update_consec_hash_pairs(values: &Vec<Output<Self>>) -> Vec<Output<Self>> {
        let v = values
            .par_chunks_exact(2)
            .map(|c| [c[0], c[1]].concat())
            .collect::<Vec<Vec<u8>>>();

        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        let _now = Instant::now();
        let mut jobs = v
            .iter()
            .map(|v| HashManyJob::new(&params, v))
            .collect::<Vec<HashManyJob>>();

        hash_many(jobs.iter_mut());

        let outputs: Vec<Output<Self>> = jobs
            .iter()
            .map(|job| *GenericArray::from_slice(job.to_hash().as_bytes()))
            .collect();

        outputs
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut state = State::new();
        state.update(data.as_ref());
        *GenericArray::from_slice(state.finalize().as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2s {
    state: State,
}

impl Blake2s {
    const OUTPUTLEN: usize = 32;
    fn new() -> Self {
        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        Self {
            state: params.to_state(),
        }
    }
}
impl Default for Blake2s {
    fn default() -> Self {
        Self::new()
    }
}

impl HashMarker for Blake2s {}

impl FixedOutputReset for Blake2s {
    /// Write result into provided array and reset the hasher state.
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let output = self.state.finalize();
        *out = *GenericArray::from_slice(output.as_bytes());
        *self = Self::new();
    }
}

impl Reset for Blake2s {
    fn reset(&mut self) {
        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        *self = Self::new();
    }
}

impl FixedOutput for Blake2s {
    fn finalize_into(self, out: &mut Output<Self>) {
        let output = self.state.finalize();
        *out = *GenericArray::from_slice(output.as_bytes());
    }
}

impl Update for Blake2s {
    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
}

impl OutputSizeUser for Blake2s {
    type OutputSize = U32;
    fn output_size() -> usize {
        return Self::OUTPUTLEN;
    }
}
