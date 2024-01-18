use crate::{util::Itertools, Error};
use ff::Field;
use goldilocks::SmallField;
use serde::{de::DeserializeOwned, Serialize};

use std::fmt::Debug;

use super::hash::{new_hasher, Digest, Hasher, DIGEST_WIDTH};

pub const OUTPUT_WIDTH: usize = 4; // Must be at least the degree of F

pub trait FieldTranscript<F> {
    fn squeeze_challenge(&mut self) -> F;

    fn squeeze_challenges(&mut self, n: usize) -> Vec<F> {
        (0..n).map(|_| self.squeeze_challenge()).collect()
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error>;

    fn common_field_elements(&mut self, fes: &[F]) -> Result<(), Error> {
        fes.iter()
            .map(|fe| self.common_field_element(fe))
            .try_collect()
    }
}

pub trait FieldTranscriptRead<F>: FieldTranscript<F> {
    fn read_field_element(&mut self) -> Result<F, Error>;

    fn read_field_elements(&mut self, n: usize) -> Result<Vec<F>, Error> {
        (0..n).map(|_| self.read_field_element()).collect()
    }
}

pub trait FieldTranscriptWrite<F>: FieldTranscript<F> {
    fn write_field_element(&mut self, fe: &F) -> Result<(), Error>;

    fn write_field_elements<'a>(
        &mut self,
        fes: impl IntoIterator<Item = &'a F>,
    ) -> Result<(), Error>
    where
        F: 'a,
    {
        for fe in fes.into_iter() {
            self.write_field_element(fe)?;
        }
        Ok(())
    }
}

pub trait Transcript<C, F>: FieldTranscript<F> {
    fn common_commitment(&mut self, comm: &C) -> Result<(), Error>;

    fn common_commitments(&mut self, comms: &[C]) -> Result<(), Error> {
        comms
            .iter()
            .map(|comm| self.common_commitment(comm))
            .try_collect()
    }
}

pub trait TranscriptRead<C, F>: Transcript<C, F> + FieldTranscriptRead<F> {
    fn read_commitment(&mut self) -> Result<C, Error>;

    fn read_commitments(&mut self, n: usize) -> Result<Vec<C>, Error> {
        (0..n).map(|_| self.read_commitment()).collect()
    }
}

pub trait TranscriptWrite<C, F>: Transcript<C, F> + FieldTranscriptWrite<F> {
    fn write_commitment(&mut self, comm: &C) -> Result<(), Error>;

    fn write_commitments<'a>(&mut self, comms: impl IntoIterator<Item = &'a C>) -> Result<(), Error>
    where
        C: 'a,
    {
        for comm in comms.into_iter() {
            self.write_commitment(comm)?;
        }
        Ok(())
    }
}

pub trait InMemoryTranscript<F: SmallField> {
    fn new() -> Self;

    fn into_proof(self) -> Vec<F::BaseField>;

    fn from_proof(proof: &[F::BaseField]) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Stream<T> {
    inner: Vec<T>,
    pointer: usize,
}

impl<T: Copy> Stream<T> {
    pub fn new(content: Vec<T>) -> Self {
        Self {
            inner: content,
            pointer: 0,
        }
    }

    pub fn into_inner(self) -> Vec<T> {
        self.inner
    }

    fn left(&self) -> usize {
        self.inner.len() - self.pointer
    }

    pub fn read_exact(&mut self, output: &mut Vec<T>) -> Result<(), Error> {
        let left = self.left();
        if left < output.len() {
            return Err(Error::Transcript(
                "Insufficient data in transcript".to_string(),
            ));
        }
        let len = output.len();
        output.copy_from_slice(&self.inner[self.pointer..(self.pointer + len)]);
        self.pointer += output.len();
        Ok(())
    }

    pub fn write_all(&mut self, input: &[T]) -> Result<(), Error> {
        self.inner.extend_from_slice(input);
        Ok(())
    }
}

#[derive(Debug)]
pub struct PoseidonTranscript<F: SmallField> {
    state: Hasher,
    stream: Stream<F::BaseField>,
}

impl<F: SmallField> Default for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self {
            state: new_hasher(),
            stream: Stream::default(),
        }
    }
}

impl<F: SmallField> InMemoryTranscript<F> for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn new() -> Self {
        Self::default()
    }

    fn into_proof(self) -> Vec<F::BaseField> {
        self.stream.into_inner()
    }

    fn from_proof(proof: &[F::BaseField]) -> Self {
        Self {
            state: new_hasher(),
            stream: Stream::new(proof.to_vec()),
        }
    }
}

impl<F: SmallField> FieldTranscript<F> for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn squeeze_challenge(&mut self) -> F {
        let hash: [F::BaseField; OUTPUT_WIDTH] = self.state.squeeze_vec::<F>()[0..OUTPUT_WIDTH]
            .try_into()
            .unwrap();
        self.state = new_hasher();
        self.state.update(&hash);
        F::from_limbs(&hash[..F::DEGREE])
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.state.update(fe.to_limbs().as_slice());
        Ok(())
    }
}

impl<F: SmallField> FieldTranscriptRead<F> for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn read_field_element(&mut self) -> Result<F, Error> {
        let mut repr = vec![F::BaseField::ZERO; F::DEGREE];

        self.stream.read_exact(&mut repr)?;

        let fe = F::from_limbs(&repr);
        self.common_field_element(&fe)?;
        Ok(fe)
    }
}

impl<F: SmallField> FieldTranscriptWrite<F> for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn write_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.common_field_element(fe)?;
        self.stream.write_all(fe.to_limbs().as_slice())
    }
}

impl<F: SmallField> Transcript<Digest<F>, F> for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn common_commitment(&mut self, comm: &Digest<F>) -> Result<(), Error> {
        self.state.update(&comm.0);
        Ok(())
    }

    fn common_commitments(&mut self, comms: &[Digest<F>]) -> Result<(), Error> {
        comms
            .iter()
            .map(|comm| self.common_commitment(comm))
            .try_collect()
    }
}

impl<F: SmallField> TranscriptRead<Digest<F>, F> for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn read_commitment(&mut self) -> Result<Digest<F>, Error> {
        let mut repr = vec![F::BaseField::ZERO; DIGEST_WIDTH];
        self.stream.read_exact(&mut repr)?;
        let comm = Digest(repr.as_slice().try_into().unwrap());
        self.common_commitment(&comm)?;
        Ok(comm)
    }
}

impl<F: SmallField> TranscriptWrite<Digest<F>, F> for PoseidonTranscript<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    fn write_commitment(&mut self, comm: &Digest<F>) -> Result<(), Error> {
        self.common_commitment(comm)?;
        self.stream.write_all(&comm.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldilocks::Goldilocks as F;
    use goldilocks::GoldilocksExt2 as EF;

    #[test]
    fn test_transcript() {
        let mut transcript = PoseidonTranscript::<F>::new();
        transcript.write_field_element(&F::from(1)).unwrap();
        let a = transcript.squeeze_challenge();
        transcript.write_field_element(&F::from(2)).unwrap();
        transcript
            .write_commitment(&Digest([F::from(3); DIGEST_WIDTH]))
            .unwrap();
        let b = transcript.squeeze_challenge();
        let proof = transcript.into_proof();
        let mut transcript = PoseidonTranscript::<F>::from_proof(&proof);
        assert_eq!(transcript.read_field_element().unwrap(), F::from(1));
        assert_eq!(transcript.squeeze_challenge(), a);
        assert_eq!(transcript.read_field_element().unwrap(), F::from(2));
        assert_eq!(
            transcript.read_commitment().unwrap(),
            Digest([F::from(3); DIGEST_WIDTH])
        );
        assert_eq!(transcript.squeeze_challenge(), b);

        let mut transcript = PoseidonTranscript::<EF>::new();
        transcript.write_field_element(&EF::from(1)).unwrap();
        let a = transcript.squeeze_challenge();
        transcript.write_field_element(&EF::from(2)).unwrap();
        transcript
            .write_commitment(&Digest([F::from(3); DIGEST_WIDTH]))
            .unwrap();
        let b = transcript.squeeze_challenge();
        let proof = transcript.into_proof();
        let mut transcript = PoseidonTranscript::<EF>::from_proof(&proof);
        assert_eq!(transcript.read_field_element().unwrap(), EF::from(1));
        assert_eq!(transcript.squeeze_challenge(), a);
        assert_eq!(transcript.read_field_element().unwrap(), EF::from(2));
        assert_eq!(
            transcript.read_commitment().unwrap(),
            Digest([F::from(3); DIGEST_WIDTH])
        );
        assert_eq!(transcript.squeeze_challenge(), b);
    }
}
