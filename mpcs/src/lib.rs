#![deny(clippy::cargo)]
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use transcript::{BasicTranscript, Transcript};
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
    transcript: &mut impl Transcript<E>,
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
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::batch_commit_and_write(pp, polys, transcript)
}

pub fn pcs_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
    comm: &Pcs::CommitmentWithData,
    point: &[E],
    eval: &E,
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::open(pp, poly, comm, point, eval, transcript)
}

pub fn pcs_batch_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[DenseMultilinearExtension<E>],
    comms: &[Pcs::CommitmentWithData],
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::batch_open(pp, polys, comms, points, evals, transcript)
}

pub fn pcs_verify<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comm: &Pcs::Commitment,
    point: &[E],
    eval: &E,
    proof: &Pcs::Proof,
    transcript: &mut impl Transcript<E>,
) -> Result<(), Error> {
    Pcs::verify(vp, comm, point, eval, proof, transcript)
}

pub fn pcs_batch_verify<'a, E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comms: &[Pcs::Commitment],
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    proof: &Pcs::Proof,
    transcript: &mut impl Transcript<E>,
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
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::commit(pp, poly)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;

    fn get_pure_commitment(comm: &Self::CommitmentWithData) -> Self::Commitment;

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithData, Error>;

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        transcript: &mut impl Transcript<E>,
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
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl Transcript<E>,
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
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
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
        let mut transcript = BasicTranscript::<E>::new(b"BaseFold");
        Self::open(pp, poly, comm, point, eval, &mut transcript)
    }

    fn ni_batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
    ) -> Result<Self::Proof, Error> {
        let mut transcript = BasicTranscript::<E>::new(b"BaseFold");
        Self::batch_open(pp, polys, comms, points, evals, &mut transcript)
    }

    fn ni_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        let mut transcript = BasicTranscript::<E>::new(b"BaseFold");
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
        let mut transcript = BasicTranscript::<E>::new(b"BaseFold");
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

// TODO: Need to use some functions here in the integration benchmarks. But
// unfortunately integration benchmarks do not compile the #[cfg(test)]
// code. So remove the gate for the entire module, only gate the test
// functions.
// This is not the best way: the test utility functions should not be
// compiled in the release build. Need a better solution.
#[doc(hidden)]
pub mod test_util {
    #[cfg(test)]
    use crate::Evaluation;
    use crate::PolynomialCommitmentScheme;
    use ff_ext::ExtensionField;
    use itertools::Itertools;
    #[cfg(test)]
    use itertools::chain;
    use multilinear_extensions::mle::DenseMultilinearExtension;
    #[cfg(test)]
    use multilinear_extensions::{
        mle::MultilinearExtension, virtual_poly_v2::ArcMultilinearExtension,
    };
    use rand::rngs::OsRng;
    #[cfg(test)]
    use transcript::BasicTranscript;
    use transcript::Transcript;

    pub fn setup_pcs<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        num_vars: usize,
    ) -> (Pcs::ProverParam, Pcs::VerifierParam) {
        let poly_size = 1 << num_vars;
        let param = Pcs::setup(poly_size).unwrap();
        Pcs::trim(param, poly_size).unwrap()
    }

    pub fn gen_rand_poly_base<E: ExtensionField>(num_vars: usize) -> DenseMultilinearExtension<E> {
        DenseMultilinearExtension::random(num_vars, &mut OsRng)
    }

    pub fn gen_rand_poly_ext<E: ExtensionField>(num_vars: usize) -> DenseMultilinearExtension<E> {
        DenseMultilinearExtension::from_evaluations_ext_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| E::random(&mut OsRng))
                .collect_vec(),
        )
    }

    pub fn gen_rand_polys<E: ExtensionField>(
        num_vars: impl Fn(usize) -> usize,
        batch_size: usize,
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
    ) -> Vec<DenseMultilinearExtension<E>> {
        (0..batch_size)
            .map(|i| gen_rand_poly(num_vars(i)))
            .collect_vec()
    }

    pub fn get_point_from_challenge<E: ExtensionField>(
        num_vars: usize,
        transcript: &mut impl Transcript<E>,
    ) -> Vec<E> {
        (0..num_vars)
            .map(|_| transcript.get_and_append_challenge(b"Point").elements)
            .collect()
    }
    pub fn get_points_from_challenge<E: ExtensionField>(
        num_vars: impl Fn(usize) -> usize,
        num_points: usize,
        transcript: &mut impl Transcript<E>,
    ) -> Vec<Vec<E>> {
        (0..num_points)
            .map(|i| get_point_from_challenge(num_vars(i), transcript))
            .collect()
    }

    pub fn commit_polys_individually<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        pp: &Pcs::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        transcript: &mut impl Transcript<E>,
    ) -> Vec<Pcs::CommitmentWithData> {
        polys
            .iter()
            .map(|poly| Pcs::commit_and_write(pp, poly, transcript).unwrap())
            .collect_vec()
    }

    #[cfg(test)]
    pub fn run_commit_open_verify<E: ExtensionField, Pcs>(
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            // Commit and open
            let (comm, eval, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let poly = gen_rand_poly(num_vars);
                let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
                let point = get_point_from_challenge(num_vars, &mut transcript);
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
            {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                Pcs::write_commitment(&comm, &mut transcript).unwrap();
                let point = get_point_from_challenge(num_vars, &mut transcript);
                transcript.append_field_element_ext(&eval);
                Pcs::verify(&vp, &comm, &point, &eval, &proof, &mut transcript).unwrap();

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);
            }
        }
    }

    #[cfg(test)]
    pub fn run_batch_commit_open_verify<E, Pcs>(
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let batch_size = 2;
            let num_points = batch_size >> 1;
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            // Batch commit and open
            let evals = chain![
                (0..num_points).map(|point| (point * 2, point)), // Every point matches two polys
                (0..num_points).map(|point| (point * 2 + 1, point)),
            ]
            .unique()
            .collect_vec();

            let (comms, evals, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let polys = gen_rand_polys(|i| num_vars - (i >> 1), batch_size, gen_rand_poly);

                let comms =
                    commit_polys_individually::<E, Pcs>(&pp, polys.as_slice(), &mut transcript);

                let points =
                    get_points_from_challenge(|i| num_vars - i, num_points, &mut transcript);

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
                (comms, evals, proof, transcript.read_challenge())
            };
            // Batch verify
            {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let comms = comms
                    .iter()
                    .map(|comm| {
                        let comm = Pcs::get_pure_commitment(comm);
                        Pcs::write_commitment(&comm, &mut transcript).unwrap();
                        comm
                    })
                    .collect_vec();

                let points =
                    get_points_from_challenge(|i| num_vars - i, num_points, &mut transcript);

                let values: Vec<E> = evals
                    .iter()
                    .map(Evaluation::value)
                    .copied()
                    .collect::<Vec<E>>();
                transcript.append_field_element_exts(values.as_slice());

                Pcs::batch_verify(&vp, &comms, &points, &evals, &proof, &mut transcript).unwrap();
                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn run_simple_batch_commit_open_verify<E, Pcs>(
        gen_rand_poly: fn(usize) -> DenseMultilinearExtension<E>,
        num_vars_start: usize,
        num_vars_end: usize,
        batch_size: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let (comm, evals, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let polys = gen_rand_polys(|_| num_vars, batch_size, gen_rand_poly);
                let comm =
                    Pcs::batch_commit_and_write(&pp, polys.as_slice(), &mut transcript).unwrap();
                let point = get_point_from_challenge(num_vars, &mut transcript);
                let evals = polys.iter().map(|poly| poly.evaluate(&point)).collect_vec();
                transcript.append_field_element_exts(&evals);

                let polys = polys
                    .iter()
                    .map(|poly| ArcMultilinearExtension::from(poly.clone()))
                    .collect_vec();
                let proof =
                    Pcs::simple_batch_open(&pp, &polys, &comm, &point, &evals, &mut transcript)
                        .unwrap();
                (
                    Pcs::get_pure_commitment(&comm),
                    evals,
                    proof,
                    transcript.read_challenge(),
                )
            };
            // Batch verify
            {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                Pcs::write_commitment(&comm, &mut transcript).unwrap();

                let point = get_point_from_challenge(num_vars, &mut transcript);
                transcript.append_field_element_exts(&evals);

                Pcs::simple_batch_verify(&vp, &comm, &point, &evals, &proof, &mut transcript)
                    .unwrap();

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);
            }
        }
    }
}
