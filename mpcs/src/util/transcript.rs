use crate::{util::Itertools, Error};
use ff::Field;
use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;

use std::fmt::Debug;

use super::hash::{new_hasher, Digest, Hasher, DIGEST_WIDTH};

pub const OUTPUT_WIDTH: usize = 4; // Must be at least the degree of F

pub trait FieldTranscript<E: ExtensionField> {
    fn squeeze_challenge(&mut self) -> E;

    fn squeeze_challenges(&mut self, n: usize) -> Vec<E> {
        (0..n).map(|_| self.squeeze_challenge()).collect()
    }

    fn common_field_element_base(&mut self, fe: &E::BaseField) -> Result<(), Error>;

    fn common_field_element_ext(&mut self, fe: &E) -> Result<(), Error>;

    fn common_field_elements(&mut self, fes: FieldType<E>) -> Result<(), Error> {
        Ok(match fes {
            FieldType::Base(fes) => fes
                .iter()
                .map(|fe| self.common_field_element_base(fe))
                .try_collect()?,
            FieldType::Ext(fes) => fes
                .iter()
                .map(|fe| self.common_field_element_ext(fe))
                .try_collect()?,
            FieldType::Unreachable => unreachable!(),
        })
    }
}

pub trait FieldTranscriptRead<E: ExtensionField>: FieldTranscript<E> {
    fn read_field_element_base(&mut self) -> Result<E::BaseField, Error>;

    fn read_field_element_ext(&mut self) -> Result<E, Error>;

    fn read_field_elements_base(&mut self, n: usize) -> Result<Vec<E::BaseField>, Error> {
        (0..n).map(|_| self.read_field_element_base()).collect()
    }

    fn read_field_elements_ext(&mut self, n: usize) -> Result<Vec<E>, Error> {
        (0..n).map(|_| self.read_field_element_ext()).collect()
    }
}

pub trait FieldTranscriptWrite<E: ExtensionField>: FieldTranscript<E> {
    fn write_field_element_base(&mut self, fe: &E::BaseField) -> Result<(), Error>;

    fn write_field_element_ext(&mut self, fe: &E) -> Result<(), Error>;

    fn write_field_elements_base<'a>(
        &mut self,
        fes: impl IntoIterator<Item = &'a E::BaseField>,
    ) -> Result<(), Error>
    where
        E::BaseField: 'a,
    {
        for fe in fes.into_iter() {
            self.write_field_element_base(fe)?;
        }
        Ok(())
    }

    fn write_field_elements_ext<'a>(
        &mut self,
        fes: impl IntoIterator<Item = &'a E>,
    ) -> Result<(), Error>
    where
        E::BaseField: 'a,
    {
        for fe in fes.into_iter() {
            self.write_field_element_ext(fe)?;
        }
        Ok(())
    }
}

pub trait Transcript<C, E: ExtensionField>: FieldTranscript<E> {
    fn common_commitment(&mut self, comm: &C) -> Result<(), Error>;

    fn common_commitments(&mut self, comms: &[C]) -> Result<(), Error> {
        comms
            .iter()
            .map(|comm| self.common_commitment(comm))
            .try_collect()
    }
}

pub trait TranscriptRead<C, E: ExtensionField>: Transcript<C, E> + FieldTranscriptRead<E> {
    fn read_commitment(&mut self) -> Result<C, Error>;

    fn read_commitments(&mut self, n: usize) -> Result<Vec<C>, Error> {
        (0..n).map(|_| self.read_commitment()).collect()
    }
}

pub trait TranscriptWrite<C, E: ExtensionField>:
    Transcript<C, E> + FieldTranscriptWrite<E>
{
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

pub trait InMemoryTranscript<E: ExtensionField> {
    fn new() -> Self;

    fn into_proof(self) -> Vec<E::BaseField>;

    fn from_proof(proof: &[E::BaseField]) -> Self;
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
pub struct PoseidonTranscript<E: ExtensionField> {
    state: Hasher<E::BaseField>,
    stream: Stream<E::BaseField>,
}

impl<E: ExtensionField> Default for PoseidonTranscript<E> {
    fn default() -> Self {
        Self {
            state: new_hasher::<E::BaseField>(),
            stream: Stream::default(),
        }
    }
}

impl<E: ExtensionField> InMemoryTranscript<E> for PoseidonTranscript<E> {
    fn new() -> Self {
        Self::default()
    }

    fn into_proof(self) -> Vec<E::BaseField> {
        self.stream.into_inner()
    }

    fn from_proof(proof: &[E::BaseField]) -> Self {
        Self {
            state: new_hasher::<E::BaseField>(),
            stream: Stream::new(proof.to_vec()),
        }
    }
}

impl<E: ExtensionField> FieldTranscript<E> for PoseidonTranscript<E> {
    fn squeeze_challenge(&mut self) -> E {
        let hash: [E::BaseField; OUTPUT_WIDTH] = self.state.squeeze_vec()[0..OUTPUT_WIDTH]
            .try_into()
            .unwrap();
        E::from_limbs(&hash[..E::DEGREE])
    }

    fn common_field_element_base(&mut self, fe: &E::BaseField) -> Result<(), Error> {
        self.state.update(&[*fe]);
        Ok(())
    }

    fn common_field_element_ext(&mut self, fe: &E) -> Result<(), Error> {
        self.state.update(fe.as_bases());
        Ok(())
    }
}

impl<E: ExtensionField> FieldTranscriptRead<E> for PoseidonTranscript<E> {
    fn read_field_element_ext(&mut self) -> Result<E, Error> {
        let mut repr = vec![E::BaseField::ZERO; E::DEGREE];

        self.stream.read_exact(&mut repr)?;

        let fe = E::from_limbs(&repr);
        self.common_field_element_ext(&fe)?;
        Ok(fe)
    }

    fn read_field_element_base(&mut self) -> Result<E::BaseField, Error> {
        let mut repr = vec![E::BaseField::ZERO; 1];
        self.stream.read_exact(&mut repr)?;
        self.common_field_element_base(&repr[0])?;
        Ok(repr[0])
    }
}

impl<E: ExtensionField> FieldTranscriptWrite<E> for PoseidonTranscript<E> {
    fn write_field_element_ext(&mut self, fe: &E) -> Result<(), Error> {
        self.common_field_element_ext(fe)?;
        self.stream.write_all(fe.as_bases())
    }

    fn write_field_element_base(&mut self, fe: &E::BaseField) -> Result<(), Error> {
        self.common_field_element_base(fe)?;
        self.stream.write_all(&[*fe])
    }
}

impl<E: ExtensionField> Transcript<Digest<E::BaseField>, E> for PoseidonTranscript<E> {
    fn common_commitment(&mut self, comm: &Digest<E::BaseField>) -> Result<(), Error> {
        self.state.update(&comm.0);
        Ok(())
    }

    fn common_commitments(&mut self, comms: &[Digest<E::BaseField>]) -> Result<(), Error> {
        comms
            .iter()
            .map(|comm| self.common_commitment(comm))
            .try_collect()
    }
}

impl<E: ExtensionField> TranscriptRead<Digest<E::BaseField>, E> for PoseidonTranscript<E> {
    fn read_commitment(&mut self) -> Result<Digest<E::BaseField>, Error> {
        let mut repr = vec![E::BaseField::ZERO; DIGEST_WIDTH];
        self.stream.read_exact(&mut repr)?;
        let comm = Digest(repr.as_slice().try_into().unwrap());
        self.common_commitment(&comm)?;
        Ok(comm)
    }
}

impl<E: ExtensionField> TranscriptWrite<Digest<E::BaseField>, E> for PoseidonTranscript<E> {
    fn write_commitment(&mut self, comm: &Digest<E::BaseField>) -> Result<(), Error> {
        self.common_commitment(comm)?;
        self.stream.write_all(&comm.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as EF};

    #[test]
    fn test_transcript() {
        let mut transcript = PoseidonTranscript::<EF>::new();
        transcript.write_field_element_base(&F::from(1)).unwrap();
        let a = transcript.squeeze_challenge();
        transcript.write_field_element_base(&F::from(2)).unwrap();
        transcript
            .write_commitment(&Digest([F::from(3); DIGEST_WIDTH]))
            .unwrap();
        let b = transcript.squeeze_challenge();
        let proof = transcript.into_proof();
        let mut transcript = PoseidonTranscript::<EF>::from_proof(&proof);
        assert_eq!(transcript.read_field_element_base().unwrap(), F::from(1));
        assert_eq!(transcript.squeeze_challenge(), a);
        assert_eq!(transcript.read_field_element_base().unwrap(), F::from(2));
        assert_eq!(
            transcript.read_commitment().unwrap(),
            Digest([F::from(3); DIGEST_WIDTH])
        );
        assert_eq!(transcript.squeeze_challenge(), b);

        let mut transcript = PoseidonTranscript::<EF>::new();
        transcript.write_field_element_ext(&EF::from(1)).unwrap();
        let a = transcript.squeeze_challenge();
        transcript.write_field_element_ext(&EF::from(2)).unwrap();
        transcript
            .write_commitment(&Digest([F::from(3); DIGEST_WIDTH]))
            .unwrap();
        let b = transcript.squeeze_challenge();
        let proof = transcript.into_proof();
        let mut transcript = PoseidonTranscript::<EF>::from_proof(&proof);
        assert_eq!(transcript.read_field_element_ext().unwrap(), EF::from(1));
        assert_eq!(transcript.squeeze_challenge(), a);
        assert_eq!(transcript.read_field_element_ext().unwrap(), EF::from(2));
        assert_eq!(
            transcript.read_commitment().unwrap(),
            Digest([F::from(3); DIGEST_WIDTH])
        );
        assert_eq!(transcript.squeeze_challenge(), b);
    }
}
