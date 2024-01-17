#![feature(unchecked_math)]
use ff::Field;
use goldilocks::SmallField;
use itertools::Itertools;
use poly::{Polynomial, PolynomialEvalExt};
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use util::transcript::{TranscriptRead, TranscriptWrite};

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
    type CommitmentWithData: Clone + Debug + Default + Serialize + DeserializeOwned;
    type Commitment: Clone + Debug + Default + Serialize + DeserializeOwned;
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
    ) -> Result<Self::CommitmentWithData, Error>;

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
        Self::Polynomial: 'a;

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
    Transcript(String),
}

use poly::multilinear::MultilinearPolynomial;

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
        util::transcript::{InMemoryTranscript, TranscriptRead, TranscriptWrite},
        Evaluation, PolynomialCommitmentScheme,
    };
    use goldilocks::SmallField;
    use itertools::{chain, Itertools};
    use rand::prelude::*;
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha8Rng;
    use std::time::Instant;
    #[test]
    fn test_transcript() {
        use crate::basefold::Basefold;
        use crate::basefold::BasefoldExtParams;
        use crate::util::transcript::FieldTranscript;
        use crate::util::transcript::PoseidonTranscript;
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

        type Pcs = Basefold<Fr, Five>;
        let num_vars = 10;
        let rng = ChaCha8Rng::from_seed([0u8; 32]);
        let poly_size = 1 << num_vars;
        let mut transcript = PoseidonTranscript::new();
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

    pub(super) fn run_commit_open_verify<F, PF, Pcs, T>()
    where
        F: SmallField + TryInto<PF>,
        <F as TryInto<PF>>::Error: core::fmt::Debug,
        F::BaseField: Into<F> + Into<PF>,
        PF: SmallField + Into<F>,
        Pcs: PolynomialCommitmentScheme<
            F,
            PF,
            Polynomial = MultilinearPolynomial<PF>,
            Rng = ChaCha8Rng,
        >,
        T: TranscriptRead<Pcs::CommitmentChunk, F>
            + TranscriptWrite<Pcs::CommitmentChunk, F>
            + InMemoryTranscript<F>,
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
                let mut transcript = T::new();
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
                let mut transcript = T::from_proof(proof.as_slice());
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

    pub(super) fn run_batch_commit_open_verify<F, PF, Pcs, T>()
    where
        F: SmallField + TryInto<PF>,
        <F as TryInto<PF>>::Error: core::fmt::Debug,
        F::BaseField: Into<F> + Into<PF>,
        PF: SmallField + Into<F>,
        Pcs: PolynomialCommitmentScheme<
            F,
            PF,
            Polynomial = MultilinearPolynomial<PF>,
            Rng = ChaCha8Rng,
        >,
        T: TranscriptRead<Pcs::CommitmentChunk, F>
            + TranscriptWrite<Pcs::CommitmentChunk, F>
            + InMemoryTranscript<F>,
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
                let mut transcript = T::new();
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
                let mut transcript = T::from_proof(proof.as_slice());
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

    use frontend::structs::{CircuitBuilder, ConstantType};
    use gkr::structs::{Circuit, CircuitWitness, IOPProverState, IOPVerifierState};
    use gkr::utils::MultilinearExtensionFromVectors;
    use transcript::Transcript;

    enum TableType {
        FakeHashTable,
    }

    struct AllInputIndex {
        // public
        inputs_idx: usize,

        // private
        other_x_pows_idx: usize,
        count_idx: usize,
    }

    fn construct_circuit<F: SmallField>() -> (Circuit<F>, AllInputIndex) {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let one = ConstantType::Field(F::ONE);
        let neg_one = ConstantType::Field(-F::ONE);

        let table_size = 4;
        let x = circuit_builder.create_constant_in(1, 2);
        let (other_x_pows_idx, other_pows_of_x) = circuit_builder.create_wire_in(table_size - 1);
        let pow_of_xs = [x, other_pows_of_x].concat();
        for i in 0..table_size - 1 {
            // circuit_builder.mul2(
            //     pow_of_xs[i + 1],
            //     pow_of_xs[i],
            //     pow_of_xs[i],
            //     Goldilocks::ONE,
            // );
            let tmp = circuit_builder.create_cell();
            circuit_builder.mul2(tmp, pow_of_xs[i], pow_of_xs[i], one);
            let diff = circuit_builder.create_cell();
            circuit_builder.add(diff, pow_of_xs[i + 1], one);
            circuit_builder.add(diff, tmp, neg_one);
            circuit_builder.assert_const(diff, &F::ZERO);
        }

        let table_type = TableType::FakeHashTable as usize;
        let count_idx = circuit_builder.define_table_type(table_type);
        for i in 0..table_size {
            circuit_builder.add_table_item(table_type, pow_of_xs[i]);
        }

        let (inputs_idx, inputs) = circuit_builder.create_wire_in(5);
        inputs.iter().for_each(|input| {
            circuit_builder.add_input_item(table_type, *input);
        });

        circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

        circuit_builder.configure();
        // circuit_builder.print_info();
        (
            Circuit::<F>::new(&circuit_builder),
            AllInputIndex {
                other_x_pows_idx,
                inputs_idx,
                count_idx,
            },
        )
    }

    pub(super) fn test_with_gkr<F, Pcs, T>()
    where
        F: SmallField,
        F::BaseField: Into<F>,
        Pcs: PolynomialCommitmentScheme<
            F,
            F,
            Polynomial = MultilinearPolynomial<F>,
            Rng = ChaCha8Rng,
        >,
        for<'a> &'a Pcs::CommitmentWithData: Into<Pcs::Commitment>,
        T: TranscriptRead<Pcs::CommitmentChunk, F>
            + TranscriptWrite<Pcs::CommitmentChunk, F>
            + InMemoryTranscript<F>,
    {
        // This test is copied from examples/fake_hash_lookup_par, which is currently
        // not using PCS for the check. The verifier outputs a GKRInputClaims that the
        // verifier is unable to check without the PCS.

        let rng = ChaCha8Rng::from_seed([0u8; 32]);
        // Setup
        let (pp, vp) = {
            let poly_size = 1 << 10;
            let param = Pcs::setup(poly_size, &rng).unwrap();
            Pcs::trim(&param).unwrap()
        };

        let (circuit, all_input_index) = construct_circuit::<F>();
        // println!("circuit: {:?}", circuit);
        let mut wires_in = vec![vec![]; circuit.n_wires_in];
        wires_in[all_input_index.inputs_idx] = vec![
            F::from(2u64),
            F::from(2u64),
            F::from(4u64),
            F::from(16u64),
            F::from(2u64),
        ];
        // x = 2, 2^2 = 4, 2^2^2 = 16, 2^2^2^2 = 256
        wires_in[all_input_index.other_x_pows_idx] =
            vec![F::from(4u64), F::from(16u64), F::from(256u64)];
        wires_in[all_input_index.count_idx] =
            vec![F::from(3u64), F::from(1u64), F::from(1u64), F::from(0u64)];

        let circuit_witness = {
            let challenge = F::from(9);
            let mut circuit_witness = CircuitWitness::new(&circuit, vec![challenge]);
            for _ in 0..4 {
                circuit_witness.add_instance(&circuit, &wires_in);
            }
            circuit_witness
        };

        #[cfg(feature = "sanity-check")]
        circuit_witness.check_correctness(&circuit);

        let instance_num_vars = circuit_witness.instance_num_vars();

        // Commit to the input wires

        let polys = circuit_witness
            .wires_in_ref()
            .iter()
            .map(|values| {
                MultilinearPolynomial::new(
                    values
                        .as_slice()
                        .mle(circuit.max_wires_in_num_vars, instance_num_vars)
                        .evaluations
                        .clone(),
                )
            })
            .collect_vec();
        println!(
            "Polynomial num vars: {:?}",
            polys.iter().map(|p| p.num_vars()).collect_vec()
        );
        let comms_with_data = Pcs::batch_commit(&pp, &polys).unwrap();
        let comms: Vec<Pcs::Commitment> = comms_with_data.iter().map(|cm| cm.into()).collect_vec();

        // Commitments should be part of the proof, which is not yet

        let (proof, output_num_vars, output_eval) = {
            let mut prover_transcript = Transcript::new(b"example");
            let output_num_vars = instance_num_vars + circuit.last_layer_ref().num_vars();

            let output_point = (0..output_num_vars)
                .map(|_| {
                    prover_transcript
                        .get_and_append_challenge(b"output point")
                        .elements[0]
                })
                .collect_vec();

            let output_eval = circuit_witness
                .layer_poly(0, circuit.last_layer_ref().num_vars())
                .evaluate(&output_point);
            (
                IOPProverState::prove_parallel(
                    &circuit,
                    &circuit_witness,
                    &[(output_point, output_eval)],
                    &[],
                    &mut prover_transcript,
                ),
                output_num_vars,
                output_eval,
            )
        };

        let gkr_input_claims = {
            let mut verifier_transcript = &mut Transcript::new(b"example");
            let output_point = (0..output_num_vars)
                .map(|_| {
                    verifier_transcript
                        .get_and_append_challenge(b"output point")
                        .elements[0]
                })
                .collect_vec();
            IOPVerifierState::verify_parallel(
                &circuit,
                circuit_witness.challenges(),
                &[(output_point, output_eval)],
                &[],
                &proof,
                instance_num_vars,
                &mut verifier_transcript,
            )
            .expect("verification failed")
        };

        // Generate pcs proof
        let mut transcript = T::new();
        let expected_values = circuit_witness
            .wires_in_ref()
            .iter()
            .map(|witness| {
                witness
                    .as_slice()
                    .mle(circuit.max_wires_in_num_vars, instance_num_vars)
                    .evaluate(&gkr_input_claims.point)
            })
            .collect_vec();
        let points = vec![gkr_input_claims.point];
        let evals = expected_values
            .iter()
            .enumerate()
            .map(|(i, e)| Evaluation {
                poly: i,
                point: 0,
                value: *e,
            })
            .collect_vec();
        Pcs::batch_open(
            &pp,
            &polys,
            &comms_with_data,
            &points,
            &evals,
            &mut transcript,
        )
        .unwrap();
        // This should be part of the GKR proof
        let proof = transcript.into_proof();

        // Check outside of the GKR verifier
        for i in 0..gkr_input_claims.values.len() {
            assert_eq!(expected_values[i], gkr_input_claims.values[i]);
        }

        // This should be part of the GKR verifier
        let mut transcript = T::from_proof(&proof);
        let evals = gkr_input_claims
            .values
            .iter()
            .enumerate()
            .map(|(i, e)| Evaluation {
                poly: i,
                point: 0,
                value: *e,
            })
            .collect_vec();
        Pcs::batch_verify(&vp, &comms, &points, &evals, &mut transcript).unwrap();

        println!("verification succeeded");
    }
}
