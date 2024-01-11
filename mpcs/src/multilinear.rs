use crate::{
    poly::multilinear::MultilinearPolynomial,
    util::{arithmetic::Field, Itertools},
    Error,
};

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
            arithmetic::PrimeField,
            chain,
            transcript::{InMemoryTranscript, TranscriptRead, TranscriptWrite},
            Itertools,
        },
        Evaluation, PolynomialCommitmentScheme,
    };
    use rand::prelude::*;
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha8Rng;
    use std::time::Instant;
    #[test]
    fn test_transcript() {
        use crate::multilinear::basefold::BasefoldExtParams;
        use crate::util::transcript::Blake2sTranscript;
        use crate::util::transcript::FieldTranscript;
        use crate::{multilinear::basefold::Basefold, util::hash::Blake2s};
        use halo2_curves::bn256::Fr;
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
        let param = Pcs::setup(poly_size, &rng).unwrap();

        let (pp, _) = Pcs::trim(&param).unwrap();
        println!("before commit");
        let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
        let point = transcript.squeeze_challenges(num_vars);
        let eval = poly.evaluate(point.as_slice());
        Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();
        let proof = transcript.into_proof();
        println!("transcript commit len {:?}", proof.len() * 8);
    }

    pub(super) fn run_commit_open_verify<F, Pcs, T>()
    where
        F: PrimeField,
        Pcs: PolynomialCommitmentScheme<F, Polynomial = MultilinearPolynomial<F>, Rng = ChaCha8Rng>,
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
        F: PrimeField,
        Pcs: PolynomialCommitmentScheme<F, Polynomial = MultilinearPolynomial<F>, Rng = ChaCha8Rng>,
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
