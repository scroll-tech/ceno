use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use util::{
    hash::Digest,
    transcript::{InMemoryTranscript, PoseidonTranscript, TranscriptRead, TranscriptWrite},
};

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
    rng: &Pcs::Rng,
) -> Result<Pcs::Param, Error> {
    Pcs::setup(poly_size, rng)
}

pub fn pcs_trim<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    param: &Pcs::Param,
) -> Result<(Pcs::ProverParam, Pcs::VerifierParam), Error> {
    Pcs::trim(param)
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
    transcript: &mut impl TranscriptWrite<Pcs::CommitmentChunk, E>,
) -> Result<Pcs::CommitmentWithData, Error> {
    Pcs::commit_and_write(pp, poly, transcript)
}

pub fn pcs_batch_commit<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &Vec<DenseMultilinearExtension<E>>,
) -> Result<Vec<Pcs::CommitmentWithData>, Error> {
    Pcs::batch_commit(pp, polys)
}

pub fn pcs_batch_commit_and_write<'a, E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &Vec<DenseMultilinearExtension<E>>,
    transcript: &mut impl TranscriptWrite<Pcs::CommitmentChunk, E>,
) -> Result<Vec<Pcs::CommitmentWithData>, Error> {
    Pcs::batch_commit_and_write(pp, polys, transcript)
}

pub fn pcs_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    poly: &DenseMultilinearExtension<E>,
    comm: &Pcs::CommitmentWithData,
    point: &[E],
    eval: &E,
    transcript: &mut impl TranscriptWrite<Pcs::CommitmentChunk, E>,
) -> Result<(), Error> {
    Pcs::open(pp, poly, comm, point, eval, transcript)
}

pub fn pcs_batch_open<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    pp: &Pcs::ProverParam,
    polys: &Vec<DenseMultilinearExtension<E>>,
    comms: &Vec<Pcs::CommitmentWithData>,
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    transcript: &mut impl TranscriptWrite<Pcs::CommitmentChunk, E>,
) -> Result<(), Error> {
    Pcs::batch_open(pp, polys, comms, points, evals, transcript)
}

pub fn pcs_read_commitment<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    transcript: &mut impl TranscriptRead<Pcs::CommitmentChunk, E>,
) -> Result<Pcs::Commitment, Error> {
    let comms = Pcs::read_commitments(vp, 1, transcript)?;
    assert_eq!(comms.len(), 1);
    Ok(comms.into_iter().next().unwrap())
}

pub fn pcs_read_commitments<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    num_polys: usize,
    transcript: &mut impl TranscriptRead<Pcs::CommitmentChunk, E>,
) -> Result<Vec<Pcs::Commitment>, Error> {
    Pcs::read_commitments(vp, num_polys, transcript)
}

pub fn pcs_verify<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comm: &Pcs::Commitment,
    point: &[E],
    eval: &E,
    transcript: &mut impl TranscriptRead<Pcs::CommitmentChunk, E>,
) -> Result<(), Error> {
    Pcs::verify(vp, comm, point, eval, transcript)
}

pub fn pcs_batch_verify<'a, E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    vp: &Pcs::VerifierParam,
    comms: &Vec<Pcs::Commitment>,
    points: &[Vec<E>],
    evals: &[Evaluation<E>],
    transcript: &mut impl TranscriptRead<Pcs::CommitmentChunk, E>,
) -> Result<(), Error>
where
    Pcs::Commitment: 'a,
{
    Pcs::batch_verify(vp, comms, points, evals, transcript)
}

pub trait PolynomialCommitmentScheme<E: ExtensionField>: Clone + Debug {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type CommitmentWithData: Clone + Debug + Default + Serialize + DeserializeOwned;
    type Commitment: Clone + Debug + Default + Serialize + DeserializeOwned;
    type CommitmentChunk: Clone + Debug + Default;
    type Rng: RngCore + Clone;

    fn setup(poly_size: usize, rng: &Self::Rng) -> Result<Self::Param, Error>;

    fn trim(param: &Self::Param) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithData, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<Self::CommitmentWithData, Error>;

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error>;

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error>;

    fn open(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        eval: &E,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error>;

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
        comms: &Vec<Self::CommitmentWithData>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error>;

    fn read_commitment(
        vp: &Self::VerifierParam,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<Self::Commitment, Error> {
        let comms = Self::read_commitments(vp, 1, transcript)?;
        assert_eq!(comms.len(), 1);
        Ok(comms.into_iter().next().unwrap())
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<Vec<Self::Commitment>, Error>;

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error>;

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &Vec<Self::Commitment>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PCSProof<E: ExtensionField>(Vec<E::BaseField>)
where
    E::BaseField: Serialize + DeserializeOwned;

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
    ) -> Result<PCSProof<E>, Error> {
        let mut transcript = PoseidonTranscript::<E>::new();
        Self::open(pp, poly, comm, point, eval, &mut transcript)?;
        Ok(PCSProof(transcript.into_proof()))
    }

    fn ni_batch_open(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
        comms: &Vec<Self::CommitmentWithData>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
    ) -> Result<PCSProof<E>, Error> {
        let mut transcript = PoseidonTranscript::<E>::new();
        Self::batch_open(pp, polys, comms, points, evals, &mut transcript)?;
        Ok(PCSProof(transcript.into_proof()))
    }

    fn ni_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &PCSProof<E>,
    ) -> Result<(), Error> {
        let mut transcript = PoseidonTranscript::<E>::from_proof(proof.0.as_slice());
        Self::verify(vp, comm, point, eval, &mut transcript)
    }

    fn ni_batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: &Vec<Self::Commitment>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &PCSProof<E>,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let mut transcript = PoseidonTranscript::<E>::from_proof(proof.0.as_slice());
        Self::batch_verify(vp, comms, points, evals, &mut transcript)
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
}

mod basefold;
pub use basefold::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldDefault,
    BasefoldDefaultParams, BasefoldExtParams, BasefoldParams,
};

fn validate_input<E: ExtensionField>(
    function: &str,
    param_num_vars: usize,
    polys: &Vec<DenseMultilinearExtension<E>>,
    points: &Vec<Vec<E>>,
) -> Result<(), Error> {
    let polys = polys.into_iter().collect_vec();
    let points = points.into_iter().collect_vec();
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
    use crate::{
        util::transcript::{InMemoryTranscript, TranscriptRead, TranscriptWrite},
        Evaluation, PolynomialCommitmentScheme,
    };
    use ff_ext::ExtensionField;
    use itertools::{chain, Itertools};
    use multilinear_extensions::mle::DenseMultilinearExtension;
    use rand::{prelude::*, rngs::OsRng};
    use rand_chacha::ChaCha8Rng;

    pub fn run_commit_open_verify<E: ExtensionField, Pcs, T>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        Pcs: PolynomialCommitmentScheme<E, Rng = ChaCha8Rng>,
        T: TranscriptRead<Pcs::CommitmentChunk, E>
            + TranscriptWrite<Pcs::CommitmentChunk, E>
            + InMemoryTranscript<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            // Setup
            let (pp, vp) = {
                let rng = ChaCha8Rng::from_seed([0u8; 32]);
                let poly_size = 1 << num_vars;
                let param = Pcs::setup(poly_size, &rng).unwrap();
                Pcs::trim(&param).unwrap()
            };
            // Commit and open
            let proof = {
                let mut transcript = T::new();
                let poly = if base {
                    DenseMultilinearExtension::random(num_vars, &mut OsRng)
                } else {
                    DenseMultilinearExtension::from_evaluations_ext_vec(
                        num_vars,
                        (0..1 << num_vars).map(|_| E::random(&mut OsRng)).collect(),
                    )
                };

                let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
                let point = transcript.squeeze_challenges(num_vars);
                let eval = poly.evaluate(point.as_slice());
                transcript.write_field_element_ext(&eval).unwrap();
                Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();

                transcript.into_proof()
            };
            // Verify
            let result = {
                let mut transcript = T::from_proof(proof.as_slice());
                let result = Pcs::verify(
                    &vp,
                    &Pcs::read_commitment(&vp, &mut transcript).unwrap(),
                    &transcript.squeeze_challenges(num_vars),
                    &transcript.read_field_element_ext().unwrap(),
                    &mut transcript,
                );

                result
            };
            result.unwrap();
        }
    }

    pub fn run_batch_commit_open_verify<E, Pcs, T>(
        base: bool,
        num_vars_start: usize,
        num_vars_end: usize,
    ) where
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E, Rng = ChaCha8Rng>,
        T: TranscriptRead<Pcs::CommitmentChunk, E>
            + TranscriptWrite<Pcs::CommitmentChunk, E>
            + InMemoryTranscript<E>,
    {
        for num_vars in num_vars_start..num_vars_end {
            let batch_size = 2;
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
                let mut transcript = T::new();
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
                let comms = Pcs::batch_commit_and_write(&pp, &polys, &mut transcript).unwrap();

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
                    .write_field_elements_ext(evals.iter().map(Evaluation::value))
                    .unwrap();
                Pcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut transcript).unwrap();
                transcript.into_proof()
            };
            // Batch verify
            let result = {
                let mut transcript = T::from_proof(proof.as_slice());
                let comms = &Pcs::read_commitments(&vp, batch_size, &mut transcript).unwrap();

                let points = (0..num_points)
                    .map(|i| transcript.squeeze_challenges(num_vars - i))
                    .take(num_points)
                    .collect_vec();

                let evals2 = transcript.read_field_elements_ext(evals.len()).unwrap();

                let result = Pcs::batch_verify(
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
                );
                result
            };

            result.unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        basefold::{Basefold, BasefoldExtParams},
        util::transcript::{FieldTranscript, InMemoryTranscript, PoseidonTranscript},
        PolynomialCommitmentScheme,
    };
    use goldilocks::GoldilocksExt2;
    use multilinear_extensions::mle::DenseMultilinearExtension;
    use rand::{prelude::*, rngs::OsRng};
    use rand_chacha::ChaCha8Rng;
    #[test]
    fn test_transcript() {
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

        type Pcs = Basefold<GoldilocksExt2, Five>;
        let num_vars = 10;
        let rng = ChaCha8Rng::from_seed([0u8; 32]);
        let poly_size = 1 << num_vars;
        let mut transcript = PoseidonTranscript::new();
        let poly = DenseMultilinearExtension::random(num_vars, &mut OsRng);
        let param =
            <Pcs as PolynomialCommitmentScheme<GoldilocksExt2>>::setup(poly_size, &rng).unwrap();

        let (pp, vp) = <Pcs as PolynomialCommitmentScheme<GoldilocksExt2>>::trim(&param).unwrap();
        println!("before commit");
        let comm = <Pcs as PolynomialCommitmentScheme<GoldilocksExt2>>::commit_and_write(
            &pp,
            &poly,
            &mut transcript,
        )
        .unwrap();
        let point = transcript.squeeze_challenges(num_vars);
        let eval = poly.evaluate(point.as_slice());
        <Pcs as PolynomialCommitmentScheme<GoldilocksExt2>>::open(
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
        assert!(comm.is_base());
        let mut transcript = PoseidonTranscript::<GoldilocksExt2>::from_proof(proof.as_slice());
        let comm = <Pcs as PolynomialCommitmentScheme<GoldilocksExt2>>::read_commitment(
            &vp,
            &mut transcript,
        )
        .unwrap();
        assert!(comm.is_base());
        assert_eq!(comm.num_vars().unwrap(), num_vars);
    }

    // use gkr::structs::{Circuit, CircuitWitness, IOPProverState, IOPVerifierState};
    // use gkr::utils::MultilinearExtensionFromVectors;
    // use simple_frontend::structs::{CircuitBuilder, ConstantType};
    // use transcript::Transcript;

    // enum TableType {
    //     FakeHashTable,
    // }

    // struct AllInputIndex {
    //     // public
    //     inputs_idx: usize,

    //     // private
    //     other_x_pows_idx: usize,
    //     count_idx: usize,
    // }

    // fn construct_circuit<F: SmallField>() -> (Circuit<F>, AllInputIndex) {
    //     let mut circuit_builder = CircuitBuilder::<F>::new();
    //     let one = F::BaseField::ONE;
    //     let neg_one = -F::BaseField::ONE;

    //     let table_size = 4;
    //     let x = circuit_builder.create_constant_in(1, 2);
    //     let (other_x_pows_idx, other_pows_of_x) = circuit_builder.create_wire_in(table_size - 1);
    //     let pow_of_xs = [x, other_pows_of_x].concat();
    //     for i in 0..table_size - 1 {
    //         // circuit_builder.mul2(
    //         //     pow_of_xs[i + 1],
    //         //     pow_of_xs[i],
    //         //     pow_of_xs[i],
    //         //     Goldilocks::ONE,
    //         // );
    //         let tmp = circuit_builder.create_cell();
    //         circuit_builder.mul2(tmp, pow_of_xs[i], pow_of_xs[i], F::BaseField::ONE);
    //         let diff = circuit_builder.create_cell();
    //         circuit_builder.add(diff, pow_of_xs[i + 1], one);
    //         circuit_builder.add(diff, tmp, neg_one);
    //         circuit_builder.assert_const(diff, F::BaseField::ZERO);
    //     }

    //     let table_type = TableType::FakeHashTable as usize;
    //     let count_idx = circuit_builder.define_table_type(table_type);
    //     for i in 0..table_size {
    //         circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    //     }

    //     let (inputs_idx, inputs) = circuit_builder.create_wire_in(5);
    //     inputs.iter().for_each(|input| {
    //         circuit_builder.add_input_item(table_type, *input);
    //     });

    //     circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    //     circuit_builder.configure();
    //     // circuit_builder.print_info();
    //     (
    //         Circuit::<F>::new(&circuit_builder),
    //         AllInputIndex {
    //             other_x_pows_idx,
    //             inputs_idx,
    //             count_idx,
    //         },
    //     )
    // }

    // pub(super) fn test_with_gkr<F, Pcs, T>()
    // where
    //     F: SmallField + FromUniformBytes<64>,
    //     F::BaseField: Into<F>,
    //     Pcs: NoninteractivePCS<F, F, Polynomial = DenseMultilinearExtension<E>, Rng = ChaCha8Rng>,
    //     for<'a> &'a Pcs::CommitmentWithData: Into<Pcs::Commitment>,
    //     for<'de> <F as SmallField>::BaseField: Deserialize<'de>,
    //     T: TranscriptRead<Pcs::CommitmentChunk, F>
    //         + TranscriptWrite<Pcs::CommitmentChunk, F>
    //         + InMemoryTranscript<F>,
    // {
    //     // This test is copied from examples/fake_hash_lookup_par, which is currently
    //     // not using PCS for the check. The verifier outputs a GKRInputClaims that the
    //     // verifier is unable to check without the PCS.

    //     let rng = ChaCha8Rng::from_seed([0u8; 32]);
    //     // Setup
    //     let (pp, vp) = {
    //         let poly_size = 1 << 10;
    //         let param = Pcs::setup(poly_size, &rng).unwrap();
    //         Pcs::trim(&param).unwrap()
    //     };

    //     let (circuit, all_input_index) = construct_circuit::<F>();
    //     // println!("circuit: {:?}", circuit);
    //     let mut wires_in = vec![vec![]; circuit.n_wires_in];
    //     wires_in[all_input_index.inputs_idx] = vec![
    //         F::from(2u64),
    //         F::from(2u64),
    //         F::from(4u64),
    //         F::from(16u64),
    //         F::from(2u64),
    //     ];
    //     // x = 2, 2^2 = 4, 2^2^2 = 16, 2^2^2^2 = 256
    //     wires_in[all_input_index.other_x_pows_idx] =
    //         vec![F::from(4u64), F::from(16u64), F::from(256u64)];
    //     wires_in[all_input_index.count_idx] =
    //         vec![F::from(3u64), F::from(1u64), F::from(1u64), F::from(0u64)];

    //     let circuit_witness = {
    //         let challenge = F::from(9);
    //         let mut circuit_witness = CircuitWitness::new(&circuit, vec![challenge]);
    //         for _ in 0..4 {
    //             circuit_witness.add_instance(&circuit, &wires_in);
    //         }
    //         circuit_witness
    //     };

    //     #[cfg(feature = "sanity-check")]
    //     circuit_witness.check_correctness(&circuit);

    //     let instance_num_vars = circuit_witness.instance_num_vars();

    //     // Commit to the input wires

    //     let polys = circuit_witness
    //         .wires_in_ref()
    //         .iter()
    //         .map(|values| {
    //             MultilinearPolynomial::new(
    //                 values
    //                     .as_slice()
    //                     .mle(circuit.max_wires_in_num_vars, instance_num_vars)
    //                     .evaluations
    //                     .clone(),
    //             )
    //         })
    //         .collect_vec();
    //     println!(
    //         "Polynomial num vars: {:?}",
    //         polys.iter().map(|p| p.num_vars()).collect_vec()
    //     );
    //     let comms_with_data = Pcs::batch_commit(&pp, &polys).unwrap();
    //     let comms: Vec<Pcs::Commitment> = comms_with_data.iter().map(|cm| cm.into()).collect_vec();
    //     println!("Finish commitment");

    //     // Commitments should be part of the proof, which is not yet

    //     let (proof, output_num_vars, output_eval) = {
    //         let mut prover_transcript = Transcript::new(b"example");
    //         let output_num_vars = instance_num_vars + circuit.last_layer_ref().num_vars();

    //         let output_point = (0..output_num_vars)
    //             .map(|_| {
    //                 prover_transcript
    //                     .get_and_append_challenge(b"output point")
    //                     .elements[0]
    //             })
    //             .collect_vec();

    //         let output_eval = circuit_witness
    //             .layer_poly(0, circuit.last_layer_ref().num_vars())
    //             .evaluate(&output_point);
    //         (
    //             IOPProverState::prove_parallel(
    //                 &circuit,
    //                 &circuit_witness,
    //                 &[(output_point, output_eval)],
    //                 &[],
    //                 &mut prover_transcript,
    //             ),
    //             output_num_vars,
    //             output_eval,
    //         )
    //     };

    //     let gkr_input_claims = {
    //         let mut verifier_transcript = &mut Transcript::new(b"example");
    //         let output_point = (0..output_num_vars)
    //             .map(|_| {
    //                 verifier_transcript
    //                     .get_and_append_challenge(b"output point")
    //                     .elements[0]
    //             })
    //             .collect_vec();
    //         IOPVerifierState::verify_parallel(
    //             &circuit,
    //             circuit_witness.challenges(),
    //             &[(output_point, output_eval)],
    //             &[],
    //             &proof,
    //             instance_num_vars,
    //             &mut verifier_transcript,
    //         )
    //         .expect("verification failed")
    //     };

    //     // Generate pcs proof
    //     let expected_values = circuit_witness
    //         .wires_in_ref()
    //         .iter()
    //         .map(|witness| {
    //             witness
    //                 .as_slice()
    //                 .mle(circuit.max_wires_in_num_vars, instance_num_vars)
    //                 .evaluate(&gkr_input_claims.point)
    //         })
    //         .collect_vec();
    //     let points = vec![gkr_input_claims.point];
    //     let evals = expected_values
    //         .iter()
    //         .enumerate()
    //         .map(|(i, e)| Evaluation {
    //             poly: i,
    //             point: 0,
    //             value: *e,
    //         })
    //         .collect_vec();
    //     // This should be part of the GKR proof
    //     let pcs_proof = Pcs::ni_batch_open(&pp, &polys, &comms_with_data, &points, &evals).unwrap();
    //     println!("Finish opening");

    //     // Check outside of the GKR verifier
    //     for i in 0..gkr_input_claims.values.len() {
    //         assert_eq!(expected_values[i], gkr_input_claims.values[i]);
    //     }

    //     // This should be part of the GKR verifier
    //     let evals = gkr_input_claims
    //         .values
    //         .iter()
    //         .enumerate()
    //         .map(|(i, e)| Evaluation {
    //             poly: i,
    //             point: 0,
    //             value: *e,
    //         })
    //         .collect_vec();
    //     Pcs::ni_batch_verify(&vp, &comms, &points, &evals, &pcs_proof).unwrap();

    //     println!("verification succeeded");
    // }
}
