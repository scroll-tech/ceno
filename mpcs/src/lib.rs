#![feature(unchecked_math)]
use poly::Polynomial;
use rand::RngCore;
use std::fmt::Debug;
use util::{
    arithmetic::{variable_base_msm, Curve, CurveAffine, Field},
    transcript::{TranscriptRead, TranscriptWrite},
    DeserializeOwned, Itertools, Serialize,
};

pub mod multilinear;
pub mod poly;
pub mod sum_check;
pub mod util;

pub type Point<F, P> = <P as Polynomial<F>>::Point;

pub type Commitment<F, Pcs> = <Pcs as PolynomialCommitmentScheme<F>>::Commitment;

pub type CommitmentChunk<F, Pcs> = <Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk;

pub trait PolynomialCommitmentScheme<F: Field>: Clone + Debug {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type Polynomial: Polynomial<F> + Serialize + DeserializeOwned;
    type Commitment: Clone
        + Debug
        + Default
        + AsRef<[Self::CommitmentChunk]>
        + Serialize
        + DeserializeOwned;
    type CommitmentChunk: Clone + Debug + Default;

    fn setup(poly_size: usize, batch_size: usize, rng: impl RngCore) -> Result<Self::Param, Error>;

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Self::Commitment, Error> {
        let comm = Self::commit(pp, poly)?;

        transcript.write_commitments(comm.as_ref())?;

        Ok(comm)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a;

    fn batch_commit_and_write<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a,
    {
        let comms = Self::batch_commit(pp, polys)?;
        for comm in comms.iter() {
            transcript.write_commitments(comm.as_ref())?;
        }
        Ok(comms)
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>;

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Polynomial: 'a,
        Self::Commitment: 'a;

    fn read_commitment(
        vp: &Self::VerifierParam,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Self::Commitment, Error> {
        let comms = Self::read_commitments(vp, 1, transcript)?;
        assert_eq!(comms.len(), 1);
        Ok(comms.into_iter().next().unwrap())
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error>;

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>;

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a;
}

#[derive(Clone, Debug)]
pub struct Evaluation<F> {
    poly: usize,
    point: usize,
    value: F,
}

impl<F> Evaluation<F> {
    pub fn new(poly: usize, point: usize, value: F) -> Self {
        Self { poly, point, value }
    }

    pub fn poly(&self) -> usize {
        self.poly
    }

    pub fn point(&self) -> usize {
        self.point
    }

    pub fn value(&self) -> &F {
        &self.value
    }
}

pub trait AdditiveCommitment<F: Field>: Debug + Default + PartialEq + Eq {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a F> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self
    where
        Self: 'a;
}

impl<C: CurveAffine> AdditiveCommitment<C::Scalar> for C {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a C::Scalar> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self {
        let scalars = scalars.into_iter().collect_vec();
        let bases = bases.into_iter().collect_vec();
        assert_eq!(scalars.len(), bases.len());

        variable_base_msm(scalars, bases).to_affine()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    InvalidSumcheck(String),
    InvalidPcsParam(String),
    InvalidPcsOpen(String),
    InvalidSnark(String),
    Serialization(String),
    Transcript(std::io::ErrorKind, String),
}
