use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use transcript::Transcript;
use util::hash::Digest;

pub mod sum_check;
pub mod util;

pub type Commitment<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::Commitment;
pub type CommitmentChunk<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::CommitmentChunk;
pub type CommitmentWithData<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::CommitmentWithData;

pub type Param<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::Param;
pub type ProverParam<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::ProverParam;
pub type VerifierParam<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::VerifierParam;

pub fn pcs_setup<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    poly_size: usize,
) -> Result<Pcs::Param, Error> {
    Pcs::setup(poly_size)
}

pub fn pcs_trim<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    param: Pcs::Param,
    poly_size: usize,
) -> Result<(Pcs::ProverParam, Pcs::VerifierParam), Error> {
    Pcs::trim(param, poly_size)
}

pub fn pcs_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::commit(pp, poly)
}

pub fn pcs_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
    transcript: &mut Transcript<E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::commit_and_write(pp, poly, transcript)
}

pub fn pcs_batch_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::batch_commit(pp, polys)
}

pub fn pcs_batch_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
    transcript: &mut Transcript<E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::batch_commit_and_write(pp, polys, transcript)
}

pub fn pcs_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
    comm: &Pcs::CommitmentWithData,
    point: &[E],
    eval: &E,
    transcript: &mut Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::open(pp, poly, comm, point, eval, transcript)
}

pub fn pcs_batch_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
    comms: &[Pcs::CommitmentWithData],
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    transcript: &mut Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::batch_open(pp, polys, comms, points, evals, transcript)
}

pub fn pcs_verify<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comm: &Pcs::Commitment,
    point: &[E],
    eval: &E,
    proof: &Pcs::Proof,
    transcript: &mut Transcript<E>,
) -> Result<(), Error> {
    Pcs::verify(vp, comm, point, eval, proof, transcript)
}

pub fn pcs_batch_verify<'a, E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comms: &[Pcs::Commitment],
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    proof: &Pcs::Proof,
    transcript: &mut Transcript<E>,
) -> Result<(), Error>
where
    Pcs::Commitment: 'a,
{
    Pcs::batch_verify(vp, comms, points, evals, proof, transcript)
}

pub trait PolynomialCommitmentScheme<E: ExtensionField>: Clone + Debug {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type CommitmentWithData: Clone + Debug + Default + Serialize + DeserializeOwned;
    type Commitment: Clone + Debug + Default + Serialize + DeserializeOwned;
    type CommitmentChunk: Clone + Debug + Default;
    type Proof: Clone + Debug + Serialize + DeserializeOwned;

    fn setup(poly_size: usize) -> Result<Self::Param, Error>;

    fn trim(
        param: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithData, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::commit(pp, poly)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error>;

    fn get_pure_commitment(comm: &Self::CommitmentWithData) -> Self::Commitment;

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithData, Error>;

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::batch_commit(pp, polys)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        eval: &E,
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithData,
        point: &[E],
        evals: &[E],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error>;

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error>;

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error>;
}

pub trait NoninteractivePCS<E: ExtensionField>:
    PolynomialCommitmentScheme<E, CommitmentChunk = Digest<E::BaseField>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn ni_open(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        eval: &E,
    ) -> Result<Self::Proof, Error> {
        let mut transcript = Transcript::<E>::new(b"BaseFold");
        Self::open(pp, poly, comm, point, eval, &mut transcript)
    }

    fn ni_batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
    ) -> Result<Self::Proof, Error> {
        let mut transcript = Transcript::<E>::new(b"BaseFold");
        Self::batch_open(pp, polys, comms, points, evals, &mut transcript)
    }

    fn ni_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        let mut transcript = Transcript::<E>::new(b"BaseFold");
        Self::verify(vp, comm, point, eval, proof, &mut transcript)
    }

    fn ni_batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let mut transcript = Transcript::<E>::new(b"BaseFold");
        Self::batch_verify(vp, comms, points, evals, proof, &mut transcript)
    }
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

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    InvalidSumcheck(String),
    InvalidPcsParam(String),
    InvalidPcsOpen(String),
    InvalidSnark(String),
    Serialization(String),
    Transcript(String),
    ExtensionFieldElementNotFit,
    PolynomialTooLarge(usize),
    PolynomialSizesNotEqual,
    MerkleRootMismatch,
}

mod basefold;
pub use basefold::{
    Basecode, BasecodeDefaultSpec, Basefold, BasefoldBasecodeParams, BasefoldCommitment,
    BasefoldCommitmentWithData, BasefoldDefault, BasefoldParams, BasefoldRSParams, BasefoldSpec,
    EncodingScheme, RSCode, RSCodeDefaultSpec, coset_fft, fft, fft_root_table, one_level_eval_hc,
    one_level_interp_hc,
};
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;

fn validate_input<E: ExtensionField>(
    function: &str,
    param_num_vars: usize,
    polys: &[DenseMultilinearExtension<E>],
    points: &[Vec<E>],
) -> Result<(), Error> {
    let polys = polys.iter().collect_vec();
    let points = points.iter().collect_vec();
    for poly in polys.iter() {
        if param_num_vars < poly.num_vars {
            return Err(err_too_many_variates(
                function,
                param_num_vars,
                poly.num_vars,
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
pub mod test_util {

    use crate::{Evaluation, PolynomialCommitmentScheme};
    use ff_ext::ExtensionField;
    use itertools::{Itertools, chain};
    use multilinear_extensions::mle::{DenseMultilinearExtension, MultilinearExtension};
    use rand::{prelude::*, rngs::OsRng};
    use rand_chacha::ChaCha8Rng;
    use transcript::Transcript;

    pub fn run_commit_open_verify<E: ExtensionField, Pcs>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            // Setup
            let (pp, vp) = {
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size).unwrap();
                Pcs::trim(param, poly_size).unwrap()
            };
            // Commit and open
            let (comm, eval, proof, challenge) = {
                let mut transcript = Transcript::new(b"BaseFold");
                let poly = if base {
                    DenseMultilinearExtension::random(num_vars, &mut OsRng)
                } else {
                    DenseMultilinearExtension::from_evaluations_ext_vec(
                        num_vars,
                        (0..1 << num_vars).map(|_| E::random(&mut OsRng)).collect(),
                    )
                };

                let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
                let point = (0..num_vars)
                    .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                    .collect::<Vec<_>>();
                let eval = poly.evaluate(point.as_slice());
                transcript.append_field_element_ext(&eval);
                (
                    Pcs::get_pure_commitment(&comm),
                    eval,
                    Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap(),
                    transcript.read_challenge(),
                )
            };
            // Verify
            let result = {
                let mut transcript = Transcript::new(b"BaseFold");
                Pcs::write_commitment(&comm, &mut transcript).unwrap();
                let point = (0..num_vars)
                    .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                    .collect::<Vec<_>>();
                transcript.append_field_element_ext(&eval);
                let result = Pcs::verify(&vp, &comm, &point, &eval, &proof, &mut transcript);

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);

                result
            };
            result.unwrap();
        }
    }

    pub fn run_batch_commit_open_verify<E, Pcs>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let batch_size = 2;
            let num_points = batch_size >> 1;
            let rng = ChaCha8Rng::from_seed([0u8; 32]);
            // Setup
            let (pp, vp) = {
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size).unwrap();
                Pcs::trim(param, poly_size).unwrap()
            };
            // Batch commit and open
            let evals = chain![
                (0..num_points).map(|point| (point * 2, point)), // Every point matches two polys
                (0..num_points).map(|point| (point * 2 + 1, point)),
            ]
            .unique()
            .collect_vec();

            let (comms, points, evals, proof, challenge) = {
                let mut transcript = Transcript::new(b"BaseFold");
                let polys = (0..batch_size)
                    .map(|i| {
                        if base {
                            DenseMultilinearExtension::random(num_vars - (i >> 1), &mut rng.clone())
                        } else {
                            DenseMultilinearExtension::from_evaluations_ext_vec(
                                num_vars,
                                (0..1 << num_vars).map(|_| E::random(&mut OsRng)).collect(),
                            )
                        }
                    })
                    .collect_vec();

                let comms = polys
                    .iter()
                    .map(|poly| Pcs::commit_and_write(&pp, poly, &mut transcript).unwrap())
                    .collect_vec();

                let points = (0..num_points)
                    .map(|i| {
                        (0..num_vars - i)
                            .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                            .collect::<Vec<_>>()
                    })
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
                let values: Vec<E> = evals
                    .iter()
                    .map(Evaluation::value)
                    .copied()
                    .collect::<Vec<E>>();
                transcript.append_field_element_exts(values.as_slice());

                let proof =
                    Pcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut transcript).unwrap();
                (comms, points, evals, proof, transcript.read_challenge())
            };
            // Batch verify
            let result = {
                let mut transcript = Transcript::new(b"BaseFold");
                let comms = comms
                    .iter()
                    .map(|comm| {
                        let comm = Pcs::get_pure_commitment(comm);
                        Pcs::write_commitment(&comm, &mut transcript).unwrap();
                        comm
                    })
                    .collect_vec();

                let old_points = points;
                let points = (0..num_points)
                    .map(|i| {
                        (0..num_vars - i)
                            .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                            .collect::<Vec<_>>()
                    })
                    .take(num_points)
                    .collect_vec();
                assert_eq!(points, old_points);
                let values: Vec<E> = evals
                    .iter()
                    .map(Evaluation::value)
                    .copied()
                    .collect::<Vec<E>>();
                transcript.append_field_element_exts(values.as_slice());

                let result =
                    Pcs::batch_verify(&vp, &comms, &points, &evals, &proof, &mut transcript);
                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);
                result
            };

            result.unwrap();
        }
    }

    pub(super) fn run_simple_batch_commit_open_verify<E, Pcs>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
        batch_size: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let rng = ChaCha8Rng::from_seed([0u8; 32]);
            // Setup
            let (pp, vp) = {
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size).unwrap();
                Pcs::trim(param, poly_size).unwrap()
            };

            let (comm, evals, proof, challenge) = {
                let mut transcript = Transcript::new(b"BaseFold");
                let polys = (0..batch_size)
                    .map(|_| {
                        if base {
                            DenseMultilinearExtension::random(num_vars, &mut rng.clone())
                        } else {
                            DenseMultilinearExtension::from_evaluations_ext_vec(
                                num_vars,
                                (0..1 << num_vars).map(|_| E::random(&mut OsRng)).collect(),
                            )
                        }
                    })
                    .collect_vec();
                let comm = Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();

                let point = (0..num_vars)
                    .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                    .collect::<Vec<_>>();

                let evals = (0..batch_size)
                    .map(|i| polys[i].evaluate(&point))
                    .collect_vec();

                transcript.append_field_element_exts(&evals);
                let proof = Pcs::simple_batch_open(
                    &pp,
                    polys
                        .into_iter()
                        .map(|x| x.into())
                        .collect::<Vec<_>>()
                        .as_slice(),
                    &comm,
                    &point,
                    &evals,
                    &mut transcript,
                )
                .unwrap();
                (
                    Pcs::get_pure_commitment(&comm),
                    evals,
                    proof,
                    transcript.read_challenge(),
                )
            };
            // Batch verify
            let result = {
                let mut transcript = Transcript::new(b"BaseFold");
                Pcs::write_commitment(&comm, &mut transcript).unwrap();

                let point = (0..num_vars)
                    .map(|_| transcript.get_and_append_challenge(b"Point").elements)
                    .collect::<Vec<_>>();

                transcript.append_field_element_exts(&evals);

                let result =
                    Pcs::simple_batch_verify(&vp, &comm, &point, &evals, &proof, &mut transcript);

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);
                result
            };

            result.unwrap();
        }
    }
}
