use crate::{
    util::{
        arithmetic::fe_mod_from_le_bytes,
        hash::{Blake2s, Blake2s256, Hash, Keccak256, Output, Update},
        Itertools,
    },
    Error,
};
use ff::PrimeField;


use std::{
    fmt::Debug,
    io::{self, Cursor},
};

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

pub trait InMemoryTranscript {
    type Param: Clone + Debug;

    fn new(param: Self::Param) -> Self;

    fn into_proof(self) -> Vec<u8>;

    fn from_proof(param: Self::Param, proof: &[u8]) -> Self;
}

pub type Keccak256Transcript<S> = FiatShamirTranscript<Keccak256, S>;

pub type Blake2sTranscript<S> = FiatShamirTranscript<Blake2s, S>;

pub type Blake2s256Transcript<S> = FiatShamirTranscript<Blake2s256, S>;

#[derive(Debug, Default)]
pub struct FiatShamirTranscript<H, S> {
    state: H,
    stream: S,
}

impl<H: Hash> InMemoryTranscript for FiatShamirTranscript<H, Cursor<Vec<u8>>> {
    type Param = ();

    fn new(_: Self::Param) -> Self {
        Self::default()
    }

    fn into_proof(self) -> Vec<u8> {
        self.stream.into_inner()
    }

    fn from_proof(_: Self::Param, proof: &[u8]) -> Self {
        Self {
            state: H::default(),
            stream: Cursor::new(proof.to_vec()),
        }
    }
}

impl<H: Hash, F: PrimeField, S> FieldTranscript<F> for FiatShamirTranscript<H, S> {
    fn squeeze_challenge(&mut self) -> F {
        let hash = self.state.finalize_fixed_reset();
        self.state.update(&hash);
        fe_mod_from_le_bytes(hash)
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.state.update_field_element(fe);
        Ok(())
    }
}

impl<H: Hash, F: PrimeField, R: io::Read> FieldTranscriptRead<F> for FiatShamirTranscript<H, R> {
    fn read_field_element(&mut self) -> Result<F, Error> {
        let mut repr = <F as PrimeField>::Repr::default();

        self.stream
            .read_exact(repr.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        repr.as_mut().reverse();
        let fe = F::from_repr_vartime(repr).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid field element encoding in proof".to_string(),
            )
        })?;
        self.common_field_element(&fe)?;
        Ok(fe)
    }
}

impl<H: Hash, F: PrimeField, W: io::Write> FieldTranscriptWrite<F> for FiatShamirTranscript<H, W> {
    fn write_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.common_field_element(fe)?;
        let mut repr = fe.to_repr();
        repr.as_mut().reverse();
        let _el = repr.as_ref();
        //	println!("field el length {:?}", el.len());
        self.stream
            .write_all(repr.as_ref())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}

impl<F: PrimeField, S> Transcript<Output<Keccak256>, F> for Keccak256Transcript<S> {
    fn common_commitment(&mut self, comm: &Output<Keccak256>) -> Result<(), Error> {
        self.state.update(comm);
        Ok(())
    }
}

impl<F: PrimeField, R: io::Read> TranscriptRead<Output<Keccak256>, F> for Keccak256Transcript<R> {
    fn read_commitment(&mut self) -> Result<Output<Keccak256>, Error> {
        let mut hash = Output::<Keccak256>::default();
        self.stream
            .read_exact(hash.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(hash)
    }
}

impl<F: PrimeField, W: io::Write> TranscriptWrite<Output<Keccak256>, F> for Keccak256Transcript<W> {
    fn write_commitment(&mut self, hash: &Output<Keccak256>) -> Result<(), Error> {
        self.stream
            .write_all(hash)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(())
    }
}

impl<F: PrimeField, S> Transcript<Output<Blake2s>, F> for Blake2sTranscript<S> {
    fn common_commitment(&mut self, comm: &Output<Blake2s>) -> Result<(), Error> {
        self.state.update(comm);
        Ok(())
    }
}

impl<F: PrimeField, R: io::Read> TranscriptRead<Output<Blake2s>, F> for Blake2sTranscript<R> {
    fn read_commitment(&mut self) -> Result<Output<Blake2s>, Error> {
        let mut hash = Output::<Blake2s>::default();
        self.stream
            .read_exact(hash.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(hash)
    }
}

impl<F: PrimeField, W: io::Write> TranscriptWrite<Output<Blake2s>, F> for Blake2sTranscript<W> {
    fn write_commitment(&mut self, hash: &Output<Blake2s>) -> Result<(), Error> {
        self.stream
            .write_all(hash)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(())
    }
}

impl<F: PrimeField, S> Transcript<Output<Blake2s256>, F> for Blake2s256Transcript<S> {
    fn common_commitment(&mut self, comm: &Output<Blake2s256>) -> Result<(), Error> {
        self.state.update(comm);
        Ok(())
    }
}

impl<F: PrimeField, R: io::Read> TranscriptRead<Output<Blake2s256>, F> for Blake2s256Transcript<R> {
    fn read_commitment(&mut self) -> Result<Output<Blake2s256>, Error> {
        let mut hash = Output::<Blake2s256>::default();
        self.stream
            .read_exact(hash.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(hash)
    }
}

impl<F: PrimeField, W: io::Write> TranscriptWrite<Output<Blake2s256>, F>
    for Blake2s256Transcript<W>
{
    fn write_commitment(&mut self, hash: &Output<Blake2s256>) -> Result<(), Error> {
        self.stream
            .write_all(hash)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(())
    }
}
