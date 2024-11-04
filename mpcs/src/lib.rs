use ff_ext::ExtensionField;
use rand::RngCore;
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
    param: &Pcs::Param,
    poly_size: usize,
) -> Result<(Pcs::ProverParam, Pcs::VerifierParam), Error> {
    Pcs::trim(param, poly_size)
}

pub fn pcs_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &ArcMultilinearExtension<E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::commit(pp, poly)
}

pub fn pcs_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &ArcMultilinearExtension<E>,
    transcript: &mut Transcript<E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::commit_and_write(pp, poly, transcript)
}

pub fn pcs_batch_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[ArcMultilinearExtension<E>],
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::batch_commit(pp, polys)
}

pub fn pcs_batch_commit_and_write<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[ArcMultilinearExtension<E>],
    transcript: &mut Transcript<E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::batch_commit_and_write(pp, polys, transcript)
}

pub fn pcs_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &ArcMultilinearExtension<E>,
    comm: &Pcs::CommitmentWithData,
    point: &[E],
    eval: &E,
    transcript: &mut Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::open(pp, poly, comm, point, eval, transcript)
}

pub fn pcs_batch_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &[ArcMultilinearExtension<E>],
    comms: &[Pcs::CommitmentWithData],
    points: &[&[E]],
    evals: &[Evaluation<E>],
    transcript: &mut Transcript<E>,
) -> Result<Pcs::Proof, Error> {
    Pcs::batch_open_vlmp(pp, polys, comms, points, evals, transcript)
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
    points: &[&[E]],
    evals: &[Evaluation<E>],
    proof: &Pcs::Proof,
    transcript: &mut Transcript<E>,
) -> Result<(), Error>
where
    Pcs::Commitment: 'a,
{
    Pcs::batch_verify_vlmp(vp, comms, points, evals, proof, transcript)
}

pub trait PolynomialCommitmentScheme<E: ExtensionField>: Clone + Debug {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type CommitmentWithData: Clone + Debug + Default + Serialize + DeserializeOwned;
    type Commitment: Clone + Debug + Default + Serialize + DeserializeOwned;
    type CommitmentChunk: Clone + Debug + Default;
    type Proof: Clone + Debug + Serialize + DeserializeOwned;
    type Rng: RngCore + Clone;

    fn setup(poly_size: usize) -> Result<Self::Param, Error>;

    fn trim(
        param: &Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(
        pp: &Self::ProverParam,
        poly: &ArcMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithData, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &ArcMultilinearExtension<E>,
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
        polys: &[ArcMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithData, Error>;

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::batch_commit(pp, polys)?;
        Self::write_commitment(&Self::get_pure_commitment(&comm), transcript)?;
        Ok(comm)
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &ArcMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        eval: &E,
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error>;

    /// Batch version of open that supports variable length opening at multiple
    /// points (VLMP).
    fn batch_open_vlmp(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[&[E]],
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

    /// Another version of batch open (Variable Length One Point, VLOP):
    /// Open polynomials of different number of variables, but still
    /// at just one point. The size of this point is at least the same
    /// as the number of variables of the largest polynomials.
    /// Polynomials of different sizes must be committed separately.
    /// However, this method does not assume polynomials of the same
    /// size are committed together. In another word, different commitments
    /// may be committing polynomials of the same size.
    /// The length of comms should be the same as polys, and the same as
    /// evals. Each entry in these arrays corresponds to one group of
    /// polynomials committed together.
    fn batch_open_vlop(
        pp: &Self::ProverParam,
        polys: &[&[ArcMultilinearExtension<E>]],
        comms: &[Self::CommitmentWithData],
        point: &[E],
        evals: &[&[E]],
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

    /// The corresponding verification method for VLMP.
    fn batch_verify_vlmp(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[&[E]],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error>;

    /// The corresponding verification method for simple batch open.
    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error>;

    /// The corresponding verification method for VLOP. Note that it is
    /// not guaranteed that the commitments contain the num vars info, and
    /// that the point is not necessarily the max num vars of the polys, so
    /// the num vars should be passed in as a parameter.
    fn batch_verify_vlop(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        point: &[E],
        max_num_vars: usize,
        evals: &[&[E]],
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
        poly: &ArcMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        eval: &E,
    ) -> Result<Self::Proof, Error> {
        let mut transcript = Transcript::<E>::new(b"BaseFold");
        Self::open(pp, poly, comm, point, eval, &mut transcript)
    }

    fn ni_batch_open(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[&[E]],
        evals: &[Evaluation<E>],
    ) -> Result<Self::Proof, Error> {
        let mut transcript = Transcript::<E>::new(b"BaseFold");
        Self::batch_open_vlmp(pp, polys, comms, points, evals, &mut transcript)
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
        points: &[&[E]],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let mut transcript = Transcript::<E>::new(b"BaseFold");
        Self::batch_verify_vlmp(vp, comms, points, evals, proof, &mut transcript)
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

#[doc(hidden)]
pub mod test_util {
    #[cfg(test)]
    use crate::Evaluation;
    #[cfg(test)]
    use itertools::chain;

    use crate::PolynomialCommitmentScheme;
    use ff_ext::ExtensionField;
    use itertools::Itertools;
    use multilinear_extensions::{
        mle::DenseMultilinearExtension, virtual_poly_v2::ArcMultilinearExtension,
    };
    use rand::rngs::OsRng;
    use transcript::Transcript;

    pub fn setup_pcs<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        num_vars: usize,
    ) -> (Pcs::ProverParam, Pcs::VerifierParam) {
        let poly_size = 1 << num_vars;
        let param = Pcs::setup(poly_size).unwrap();
        Pcs::trim(&param, poly_size).unwrap()
    }

    pub fn gen_rand_poly<'a, E: ExtensionField>(
        num_vars: usize,
        base: bool,
    ) -> ArcMultilinearExtension<'a, E> {
        if base {
            ArcMultilinearExtension::from(DenseMultilinearExtension::random(num_vars, &mut OsRng))
        } else {
            ArcMultilinearExtension::from(DenseMultilinearExtension::from_evaluations_ext_vec(
                num_vars,
                (0..(1 << num_vars))
                    .map(|_| E::random(&mut OsRng))
                    .collect_vec(),
            ))
        }
    }

    pub fn gen_rand_polys<'a, E: ExtensionField>(
        num_vars: impl Fn(usize) -> usize,
        batch_size: usize,
        base: bool,
    ) -> Vec<ArcMultilinearExtension<'a, E>> {
        (0..batch_size)
            .map(|i| gen_rand_poly(num_vars(i), base))
            .collect_vec()
    }

    pub fn get_point_from_challenge<E: ExtensionField>(
        num_vars: usize,
        transcript: &mut Transcript<E>,
    ) -> Vec<E> {
        (0..num_vars)
            .map(|_| transcript.get_and_append_challenge(b"Point").elements)
            .collect()
    }

    pub fn get_points_from_challenge<E: ExtensionField>(
        num_vars: impl Fn(usize) -> usize,
        num_points: usize,
        transcript: &mut Transcript<E>,
    ) -> Vec<Vec<E>> {
        (0..num_points)
            .map(|i| get_point_from_challenge(num_vars(i), transcript))
            .collect()
    }

    pub fn commit_polys_individually<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        pp: &Pcs::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        transcript: &mut Transcript<E>,
    ) -> Vec<Pcs::CommitmentWithData> {
        polys
            .iter()
            .map(|poly| Pcs::commit_and_write(&pp, &poly, transcript).unwrap())
            .collect_vec()
    }

    pub fn vecs_as_slices<'a, T>(values: &'a Vec<Vec<T>>) -> Vec<&'a [T]> {
        values.iter().map(|vec| vec.as_slice()).collect::<Vec<_>>()
    }

    #[cfg(test)]
    pub fn run_commit_open_verify<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
    ) {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            // Commit and open
            let (comm, eval, proof, challenge) = {
                let mut transcript = Transcript::new(b"BaseFold");
                let poly = gen_rand_poly(num_vars, base);
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
                let mut transcript = Transcript::new(b"BaseFold");
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
    pub fn run_batch_vlmp_commit_open_verify<E, Pcs>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let batch_size = 4;
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
                let mut transcript = Transcript::new(b"BaseFold");
                let polys = gen_rand_polys(|i| num_vars - (i >> 1), batch_size, base);

                let comms = commit_polys_individually::<E, Pcs>(&pp, &polys, &mut transcript);

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

                let proof = Pcs::batch_open_vlmp(
                    &pp,
                    &polys,
                    &comms,
                    &vecs_as_slices(&points),
                    &evals,
                    &mut transcript,
                )
                .unwrap();
                (comms, evals, proof, transcript.read_challenge())
            };
            // Batch verify
            {
                let mut transcript = Transcript::new(b"BaseFold");
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

                Pcs::batch_verify_vlmp(
                    &vp,
                    &comms,
                    &vecs_as_slices(&points),
                    &evals,
                    &proof,
                    &mut transcript,
                )
                .unwrap();
                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);
            }
        }
    }

    #[cfg(test)]
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
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let (comm, evals, proof, challenge) = {
                let mut transcript = Transcript::new(b"BaseFold");
                let polys = gen_rand_polys(|_| num_vars, batch_size, base);
                let comm = Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();
                let point = get_point_from_challenge(num_vars, &mut transcript);
                let evals = polys.iter().map(|poly| poly.evaluate(&point)).collect_vec();
                transcript.append_field_element_exts(&evals);

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
                let mut transcript = Transcript::new(b"BaseFold");
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

    #[cfg(test)]
    pub(super) fn run_batch_vlop_commit_open_verify<E, Pcs>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
        batch_size_outer: usize,
        batch_size_inner: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let (pp, vp) = setup_pcs::<E, Pcs>(num_vars);

            let (comms, evals, proof, challenge) = {
                let mut transcript = Transcript::new(b"BaseFold");
                let (polys, comms) = (0..batch_size_outer)
                    .map(|i| {
                        let polys = gen_rand_polys(|_| num_vars - i, batch_size_inner, base);
                        let comm =
                            Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();
                        (polys, comm)
                    })
                    .collect::<(Vec<_>, Vec<_>)>();

                let point = get_point_from_challenge(num_vars, &mut transcript);
                let evals = polys
                    .iter()
                    .map(|polys| {
                        let evals = polys
                            .iter()
                            .map(|poly| poly.evaluate(&point[..poly.num_vars()]))
                            .collect_vec();
                        transcript.append_field_element_exts(&evals);
                        evals
                    })
                    .collect_vec();

                let proof = Pcs::batch_open_vlop(
                    &pp,
                    &vecs_as_slices(&polys),
                    &comms,
                    &point,
                    &vecs_as_slices(&evals),
                    &mut transcript,
                )
                .unwrap();
                (
                    comms
                        .iter()
                        .map(|comm| Pcs::get_pure_commitment(comm))
                        .collect_vec(),
                    evals,
                    proof,
                    transcript.read_challenge(),
                )
            };
            // Batch verify
            {
                let mut transcript = Transcript::new(b"BaseFold");
                comms
                    .iter()
                    .for_each(|comm| Pcs::write_commitment(&comm, &mut transcript).unwrap());

                let point = get_point_from_challenge(num_vars, &mut transcript);
                evals.iter().for_each(|evals| {
                    transcript.append_field_element_exts(evals);
                });

                Pcs::batch_verify_vlop(
                    &vp,
                    &comms,
                    &point,
                    num_vars,
                    &vecs_as_slices(&evals),
                    &proof,
                    &mut transcript,
                )
                .unwrap();

                let v_challenge = transcript.read_challenge();
                assert_eq!(challenge, v_challenge);
            }
        }
    }
}
