#![deny(clippy::cargo)]
use ff_ext::ExtensionField;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use transcript::Transcript;
use witness::RowMajorMatrix;

pub mod sum_check;
pub mod util;

pub type Commitment<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::Commitment;
pub type CommitmentChunk<E, Pcs> = <Pcs as PolynomialCommitmentScheme<E>>::CommitmentChunk;
pub type CommitmentWithWitness<E, Pcs> =
    <Pcs as PolynomialCommitmentScheme<E>>::CommitmentWithWitness;

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
    rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::commit(pp, rmm)
}

pub fn pcs_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::commit_and_write(pp, rmm, transcript)
}

pub fn pcs_batch_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::batch_commit(pp, rmm)
}

pub fn pcs_batch_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::CommitmentWithWitness, Error> {
    Pcs::batch_commit_and_write(pp, rmm, transcript)
}

pub fn pcs_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &ArcMultilinearExtension<E>,
    comm: &Pcs::CommitmentWithWitness,
    point: &[E],
    eval: &E,
    transcript: &mut impl Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::open(pp, poly, comm, point, eval, transcript)
}

pub fn pcs_batch_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[ArcMultilinearExtension<E>],
    comms: &[Pcs::CommitmentWithWitness],
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

pub trait PolynomialCommitmentScheme<E: ExtensionField>: Clone {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type CommitmentWithWitness;
    type Commitment: Clone + Serialize + DeserializeOwned;
    type CommitmentChunk: Clone;
    type Proof: Clone + Serialize + DeserializeOwned;

    fn setup(poly_size: usize) -> Result<Self::Param, Error>;

    fn trim(
        param: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(
        pp: &Self::ProverParam,
        rmm: RowMajorMatrix<E::BaseField>,
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let comm = Self::commit(pp, rmm)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error>;

    fn get_pure_commitment(comm: &Self::CommitmentWithWitness) -> Self::Commitment;

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: RowMajorMatrix<E::BaseField>,
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        rmm: RowMajorMatrix<<E as ExtensionField>::BaseField>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let comm = Self::batch_commit(pp, rmm)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &ArcMultilinearExtension<E>,
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comms: &[Self::CommitmentWithWitness],
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
        comm: &Self::CommitmentWithWitness,
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

    fn get_arcmle_witness_from_commitment(
        commitment: &Self::CommitmentWithWitness,
    ) -> Vec<ArcMultilinearExtension<'static, E>>;
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

#[derive(Clone, Debug)]
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
    WhirError(whir::Error),
}

mod basefold;
pub use basefold::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldDefault, BasefoldParams,
    BasefoldRSParams, BasefoldSpec, EncodingScheme, RSCode, RSCodeDefaultSpec, one_level_eval_hc,
    one_level_interp_hc,
};
mod whir;
use multilinear_extensions::virtual_poly::ArcMultilinearExtension;
pub use whir::{Whir, WhirDefault, WhirDefaultSpec};

// TODO: Need to use some functions here in the integration benchmarks. But
// unfortunately integration benchmarks do not compile the #[cfg(test)]
// code. So remove the gate for the entire module, only gate the test
// functions.
// This is not the best way: the test utility functions should not be
// compiled in the release build. Need a better solution.
#[doc(hidden)]
pub mod test_util {
    use crate::PolynomialCommitmentScheme;

    use ff_ext::ExtensionField;

    use itertools::Itertools;

    #[cfg(test)]
    use multilinear_extensions::{
        mle::MultilinearExtension, virtual_poly::ArcMultilinearExtension,
    };
    #[cfg(test)]
    use rand::rngs::OsRng;
    #[cfg(test)]
    use rand::{distributions::Standard, prelude::Distribution};
    #[cfg(test)]
    use transcript::BasicTranscript;

    use transcript::Transcript;
    use witness::RowMajorMatrix;

    pub fn setup_pcs<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        num_vars: usize,
    ) -> (Pcs::ProverParam, Pcs::VerifierParam) {
        let poly_size = 1 << num_vars;
        let param = Pcs::setup(poly_size).unwrap();
        Pcs::trim(param, poly_size).unwrap()
    }

    pub fn get_point_from_challenge<E: ExtensionField>(
        num_vars: usize,
        transcript: &mut impl Transcript<E>,
    ) -> Vec<E> {
        transcript.sample_and_append_vec(b"Point", num_vars)
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
        rmms: Vec<RowMajorMatrix<<E as ExtensionField>::BaseField>>,
        transcript: &mut impl Transcript<E>,
    ) -> Vec<Pcs::CommitmentWithWitness> {
        rmms.into_iter()
            .map(|rmm| { Pcs::commit_and_write(pp, rmm, transcript) }.unwrap())
            .collect_vec()
    }

    #[cfg(test)]
    pub fn run_commit_open_verify<E: ExtensionField, Pcs>(
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        Pcs: PolynomialCommitmentScheme<E>,
        Standard: Distribution<E::BaseField>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            // Commit and open
            let (comm, eval, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let rmm = RowMajorMatrix::<E::BaseField>::rand(&mut OsRng, 1 << num_vars, 1);
                let poly: ArcMultilinearExtension<E> = rmm.to_mles().remove(0).into();
                let comm = Pcs::commit_and_write(&pp, rmm, &mut transcript).unwrap();

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

                println!(
                    "Proof size for single poly: {} bytes",
                    bincode::serialized_size(&proof).unwrap()
                );
            }
        }
    }

    #[cfg(test)]
    pub(super) fn run_simple_batch_commit_open_verify<E, Pcs>(
        num_vars_start: usize,
        num_vars_end: usize,
        batch_size: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
        Standard: Distribution<E::BaseField>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let (comm, evals, proof, challenge) = {
                let mut transcript = BasicTranscript::new(b"BaseFold");
                let rmm =
                    RowMajorMatrix::<E::BaseField>::rand(&mut OsRng, 1 << num_vars, batch_size);
                let polys = rmm.to_mles();
                let comm = Pcs::batch_commit_and_write(&pp, rmm, &mut transcript).unwrap();
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

                println!(
                    "Proof size for simple batch: {} bytes",
                    bincode::serialized_size(&proof).unwrap()
                );
            }
        }
    }
}
