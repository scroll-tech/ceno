#![feature(unchecked_math)]
use goldilocks::SmallField;
use poly::{Polynomial, PolynomialEvalExt};
use rand::RngCore;
use std::fmt::Debug;
use util::{
    arithmetic::Field,
    transcript::{TranscriptRead, TranscriptWrite},
    DeserializeOwned, Serialize,
};

pub mod poly;
pub mod sum_check;
pub mod util;

pub type Point<F, P> = <P as PolynomialEvalExt<F>>::Point;

pub type Commitment<F, PF, Pcs> = <Pcs as PolynomialCommitmentScheme<F, PF>>::Commitment;

pub type CommitmentChunk<F, PF, Pcs> = <Pcs as PolynomialCommitmentScheme<F, PF>>::CommitmentChunk;

pub trait PolynomialCommitmentScheme<F: SmallField, PF: SmallField>: Clone + Debug {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type Polynomial: Polynomial<PF> + PolynomialEvalExt<F> + Serialize + DeserializeOwned;
    type CommitmentWithData: Clone
        + Debug
        + Default
        + AsRef<[Self::CommitmentChunk]>
        + Serialize
        + DeserializeOwned;
    type Commitment: Clone
        + Debug
        + Default
        + AsRef<[Self::CommitmentChunk]>
        + Serialize
        + DeserializeOwned;
    type CommitmentChunk: Clone + Debug + Default;
    type Rng: RngCore + Clone;

    fn setup(poly_size: usize, rng: &Self::Rng) -> Result<Self::Param, Error>;

    fn trim(param: &Self::Param) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
    ) -> Result<Self::CommitmentWithData, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::commit(pp, poly)?;

        transcript.write_commitments(comm.as_ref())?;

        Ok(comm)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error>
    where
        Self::Polynomial: 'a;

    fn batch_commit_and_write<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error>
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
        comm: &Self::CommitmentWithData,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>;

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::CommitmentWithData>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Polynomial: 'a,
        Self::CommitmentWithData: 'a;

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

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    InvalidSumcheck(String),
    InvalidPcsParam(String),
    InvalidPcsOpen(String),
    InvalidSnark(String),
    Serialization(String),
    Transcript(std::io::ErrorKind, String),
}

use poly::multilinear::MultilinearPolynomial;
use util::Itertools;

mod basefold;
pub use basefold::{Basefold, BasefoldCommitmentWithData, BasefoldExtParams, BasefoldParams};

fn validate_input<'a, F: Field>(
    function: &str,
    param_num_vars: usize,
    polys: impl IntoIterator<Item = &'a MultilinearPolynomial<F>>,
    points: impl IntoIterator<Item = &'a Vec<F>>,
) -> Result<(), Error> {
    let polys = polys.into_iter().collect_vec();
    let points = points.into_iter().collect_vec();
    for poly in polys.iter() {
        if param_num_vars < poly.num_vars() {
            return Err(err_too_many_variates(
                function,
                param_num_vars,
                poly.num_vars(),
            ));
        }
    }
    for point in points.iter() {
        if param_num_vars < point.len() {
            return Err(err_too_many_variates(function, param_num_vars, point.len()));
        }
    }
    Ok(())
}

fn err_too_many_variates(function: &str, upto: usize, got: usize) -> Error {
    Error::InvalidPcsParam(if function == "trim" {
        format!(
            "Too many variates to {function} (param supports variates up to {upto} but got {got})"
        )
    } else {
        format!(
            "Too many variates of poly to {function} (param supports variates up to {upto} but got {got})"
        )
    })
}

#[cfg(test)]
mod test {
    use crate::{
        poly::multilinear::MultilinearPolynomial,
        util::{
            chain,
            transcript::{InMemoryTranscript, TranscriptRead, TranscriptWrite},
            Itertools,
        },
        Evaluation, PolynomialCommitmentScheme,
    };
    use goldilocks::SmallField;
    use rand::prelude::*;
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha8Rng;
    use std::time::Instant;
    #[test]
    fn test_transcript() {
        use crate::basefold::BasefoldExtParams;
        use crate::util::transcript::Blake2sTranscript;
        use crate::util::transcript::FieldTranscript;
        use crate::{basefold::Basefold, util::hash::Blake2s};
        use goldilocks::Goldilocks as Fr;
        #[derive(Debug)]
        pub struct Five {}

        impl BasefoldExtParams for Five {
            fn get_reps() -> usize {
                return 5;
            }
            fn get_rate() -> usize {
                return 3;
            }
            fn get_basecode() -> usize {
                return 2;
            }
        }

        type Pcs = Basefold<Fr, Blake2s, Five>;
        let num_vars = 10;
        let rng = ChaCha8Rng::from_seed([0u8; 32]);
        let poly_size = 1 << num_vars;
        let mut transcript = Blake2sTranscript::new(());
        let poly = MultilinearPolynomial::rand(num_vars, OsRng);
        let param = <Pcs as PolynomialCommitmentScheme<Fr, Fr>>::setup(poly_size, &rng).unwrap();

        let (pp, _) = <Pcs as PolynomialCommitmentScheme<Fr, Fr>>::trim(&param).unwrap();
        println!("before commit");
        let comm = <Pcs as PolynomialCommitmentScheme<Fr, Fr>>::commit_and_write(
            &pp,
            &poly,
            &mut transcript,
        )
        .unwrap();
        let point = transcript.squeeze_challenges(num_vars);
        let eval = poly.evaluate(point.as_slice());
        <Pcs as PolynomialCommitmentScheme<Fr, Fr>>::open(
            &pp,
            &poly,
            &comm,
            &point,
            &eval,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.into_proof();
        println!("transcript commit len {:?}", proof.len() * 8);
    }

    pub(super) fn run_commit_open_verify<F, Pcs, T>()
    where
        F: SmallField,
        F::BaseField: Into<F>,
        Pcs: PolynomialCommitmentScheme<
            F,
            F,
            Polynomial = MultilinearPolynomial<F>,
            Rng = ChaCha8Rng,
        >,
        T: TranscriptRead<Pcs::CommitmentChunk, F>
            + TranscriptWrite<Pcs::CommitmentChunk, F>
            + InMemoryTranscript<Param = ()>,
    {
        for num_vars in 10..15 {
            println!("k {:?}", num_vars);
            // Setup
            let (pp, vp) = {
                let rng = ChaCha8Rng::from_seed([0u8; 32]);
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size, &rng).unwrap();
                println!("before trim");
                Pcs::trim(&param).unwrap()
            };
            println!("after trim");
            // Commit and open
            let proof = {
                let mut transcript = T::new(());
                let poly = MultilinearPolynomial::rand(num_vars, OsRng);
                let now = Instant::now();

                let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
                let point = transcript.squeeze_challenges(num_vars);
                let eval = poly.evaluate(point.as_slice());
                transcript.write_field_element(&eval).unwrap();
                Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();
                println!("proof time {:?}", now.elapsed());

                transcript.into_proof()
            };
            // Verify
            let result = {
                let mut transcript = T::from_proof((), proof.as_slice());
                Pcs::verify(
                    &vp,
                    &Pcs::read_commitment(&vp, &mut transcript).unwrap(),
                    &transcript.squeeze_challenges(num_vars),
                    &transcript.read_field_element().unwrap(),
                    &mut transcript,
                )
            };
            assert_eq!(result, Ok(()));
        }
    }

    pub(super) fn run_batch_commit_open_verify<F, Pcs, T>()
    where
        F: SmallField,
        F::BaseField: Into<F>,
        Pcs: PolynomialCommitmentScheme<
            F,
            F,
            Polynomial = MultilinearPolynomial<F>,
            Rng = ChaCha8Rng,
        >,
        T: TranscriptRead<Pcs::CommitmentChunk, F>
            + TranscriptWrite<Pcs::CommitmentChunk, F>
            + InMemoryTranscript<Param = ()>,
    {
        for num_vars in 10..15 {
            println!("k {:?}", num_vars);
            let batch_size = 8;
            let num_points = batch_size >> 1;
            let rng = ChaCha8Rng::from_seed([0u8; 32]);
            // Setup
            let (pp, vp) = {
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size, &rng).unwrap();
                Pcs::trim(&param).unwrap()
            };
            // Batch commit and open
            let evals = chain![
                (0..num_points).map(|point| (point * 2, point)), // Every point matches two polys
                (0..num_points).map(|point| (point * 2 + 1, point)),
            ]
            .unique()
            .collect_vec();

            let proof = {
                let mut transcript = T::new(());
                let polys = (0..batch_size)
                    .map(|i| MultilinearPolynomial::rand(num_vars - (i >> 1), rng.clone()))
                    .collect_vec();
                let now = Instant::now();
                let comms = Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();
                println!("commit {:?}", now.elapsed());

                let points = (0..num_points)
                    .map(|i| transcript.squeeze_challenges(num_vars - i))
                    .take(num_points)
                    .collect_vec();

                let evals = evals
                    .iter()
                    .copied()
                    .map(|(poly, point)| Evaluation {
                        poly,
                        point,
                        value: polys[poly].evaluate(&points[point]),
                    })
                    .collect_vec();
                transcript
                    .write_field_elements(evals.iter().map(Evaluation::value))
                    .unwrap();
                let now = Instant::now();
                Pcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut transcript).unwrap();
                println!("batch open {:?}", now.elapsed());
                transcript.into_proof()
            };
            // Batch verify
            let result = {
                let mut transcript = T::from_proof((), proof.as_slice());
                let comms = &Pcs::read_commitments(&vp, batch_size, &mut transcript).unwrap();

                let points = (0..num_points)
                    .map(|i| transcript.squeeze_challenges(num_vars - i))
                    .take(num_points)
                    .collect_vec();

                let evals2 = transcript.read_field_elements(evals.len()).unwrap();

                Pcs::batch_verify(
                    &vp,
                    comms,
                    &points,
                    &evals
                        .iter()
                        .copied()
                        .zip(evals2)
                        .map(|((poly, point), eval)| Evaluation::new(poly, point, eval))
                        .collect_vec(),
                    &mut transcript,
                )
            };

            assert_eq!(result, Ok(()));
        }
    }
}
