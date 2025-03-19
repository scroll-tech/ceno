use crate::crypto::{Digest, MultiPath};
use ff_ext::{ExtensionField, PoseidonField};
use p3_commit::Mmcs;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub mod batch;
pub mod committer;
pub mod fold;
pub mod fs_utils;
pub mod parameters;
pub mod prover;
pub mod verifier;

#[derive(Debug, Clone, Default)]
pub struct Statement<E> {
    pub points: Vec<Vec<E>>,
    pub evaluations: Vec<E>,
}

// Only includes the authentication paths
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct WhirProof<E: ExtensionField>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) merkle_answers: Vec<(MultiPath<E>, Vec<Vec<E>>)>,
    pub(crate) sumcheck_poly_evals: Vec<Vec<E>>,
    pub(crate) merkle_roots: Vec<Digest<E>>,
    pub(crate) ood_answers: Vec<Vec<E>>,
    pub(crate) final_poly: Vec<E>,
    pub(crate) folded_evals: Vec<E>,
}

#[cfg(test)]
mod tests {
    use ff_ext::{FromUniformBytes, GoldilocksExt2};
    use multilinear_extensions::mle::{DenseMultilinearExtension, MultilinearExtension};
    use p3_field::PrimeCharacteristicRing;
    use rand::rngs::OsRng;
    use transcript::BasicTranscript;
    use witness::RowMajorMatrix;

    use crate::{
        crypto::poseidon2_ext_merkle_tree,
        parameters::{
            FoldType, FoldingFactor, MultivariateParameters, SoundnessType, WhirParameters,
        },
        whir::{
            Statement,
            committer::Committer,
            parameters::WhirConfig,
            prover::Prover,
            verifier::{Verifier, WhirCommitmentInTranscript},
        },
    };

    type E = GoldilocksExt2;
    type T = BasicTranscript<E>;

    fn make_whir_things(
        num_variables: usize,
        folding_factor: FoldingFactor,
        num_points: usize,
        soundness_type: SoundnessType,
        pow_bits: usize,
        fold_type: FoldType,
    ) {
        let num_coeffs = 1 << num_variables;

        let mut rng = OsRng;
        let hash_params = poseidon2_ext_merkle_tree();

        let mv_params = MultivariateParameters::<E>::new(num_variables);

        let whir_params = WhirParameters::<E> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor,
            hash_params,
            soundness_type,
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<E>::new(mv_params, whir_params);

        let polynomial = DenseMultilinearExtension::from_evaluations_ext_vec(num_variables, vec![
                <E as p3_field::PrimeCharacteristicRing>::from_u64(1);
                num_coeffs
            ]);

        let points: Vec<_> = (0..num_points)
            .map(|_| E::random_vec(num_variables, rng))
            .collect();

        let statement = Statement {
            points: points.clone(),
            evaluations: points
                .iter()
                .map(|point| polynomial.evaluate(point))
                .collect(),
        };

        let mut transcript = T::new(b"test");

        let committer = Committer::new(params.clone());
        let (witness, commitment): (_, WhirCommitmentInTranscript<_>) =
            committer.commit(&mut transcript, polynomial).unwrap();

        let prover = Prover(params.clone());

        let proof = prover
            .prove(&mut transcript, statement.clone(), &witness)
            .unwrap();

        let verifier = Verifier::new(params);
        verifier
            .verify(&commitment, &mut transcript, &statement, &proof)
            .unwrap();
    }

    fn make_whir_batch_things_same_point(
        num_polynomials: usize,
        num_variables: usize,
        num_points: usize,
        folding_factor: usize,
        soundness_type: SoundnessType,
        pow_bits: usize,
        fold_type: FoldType,
    ) {
        println!(
            "NP = {num_polynomials}, NE = {num_points}, NV = {num_variables}, FOLD_TYPE = {:?}",
            fold_type
        );
        let num_coeffs = 1 << num_variables;

        let mut rng = OsRng;
        let hash_params = poseidon2_ext_merkle_tree();

        let mv_params = MultivariateParameters::<E>::new(num_variables);

        let whir_params = WhirParameters::<E> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor: FoldingFactor::Constant(folding_factor),
            hash_params,
            soundness_type,
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<E>::new(mv_params, whir_params);

        let polynomials = RowMajorMatrix::rand(&mut rng, 1 << num_variables, num_polynomials);

        let points: Vec<Vec<E>> = (0..num_points)
            .map(|_| E::random_vec(num_variables, rng))
            .collect();
        let evals_per_point: Vec<Vec<E>> = points
            .iter()
            .map(|point| {
                polynomials
                    .to_mles()
                    .iter()
                    .map(|poly| poly.evaluate(point))
                    .collect()
            })
            .collect();

        let mut transcript = T::new(b"test");

        let committer = Committer::new(params.clone());
        let (witnesses, commitment) = committer
            .batch_commit(&mut transcript, polynomials)
            .unwrap();

        let prover = Prover(params.clone());

        let proof = prover
            .simple_batch_prove(&mut transcript, &points, &evals_per_point, &witnesses)
            .unwrap();

        let verifier = Verifier::new(params);
        let mut transcript = T::new(b"test");
        verifier
            .simple_batch_verify(
                &commitment,
                &mut transcript,
                num_polynomials,
                &points,
                &evals_per_point,
                &proof,
            )
            .unwrap();
        println!("PASSED!");
    }

    fn make_whir_batch_things_diff_point(
        num_polynomials: usize,
        num_variables: usize,
        folding_factor: usize,
        soundness_type: SoundnessType,
        pow_bits: usize,
        fold_type: FoldType,
    ) {
        println!(
            "NP = {num_polynomials}, NV = {num_variables}, FOLD_TYPE = {:?}",
            fold_type
        );
        let num_coeffs = 1 << num_variables;

        let mut rng = OsRng;
        let hash_params = poseidon2_ext_merkle_tree();

        let mv_params = MultivariateParameters::<E>::new(num_variables);

        let whir_params = WhirParameters::<E> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor: FoldingFactor::Constant(folding_factor),
            hash_params,
            soundness_type,
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<E>::new(mv_params, whir_params);

        let polynomials = RowMajorMatrix::rand(&mut rng, num_coeffs, num_polynomials);

        let point_per_poly: Vec<Vec<E>> = (0..num_polynomials)
            .map(|_| E::random_vec(num_variables, rng))
            .collect();
        let eval_per_poly: Vec<E> = polynomials
            .to_mles()
            .iter()
            .zip(&point_per_poly)
            .map(|(poly, point)| poly.evaluate(point))
            .collect();

        let mut transcript = T::new(b"test");

        let committer = Committer::new(params.clone());
        let (witnesses, commitment) = committer
            .batch_commit(&mut transcript, polynomials)
            .unwrap();

        let prover = Prover(params.clone());

        let proof = prover
            .same_size_batch_prove(&mut transcript, &point_per_poly, &eval_per_poly, &witnesses)
            .unwrap();

        let verifier = Verifier::new(params);
        let mut transcript = T::new(b"test");
        verifier
            .same_size_batch_verify(
                &commitment,
                &mut transcript,
                num_polynomials,
                &point_per_poly,
                &eval_per_poly,
                &proof,
            )
            .unwrap();
        // assert!(verifier
        //     .same_size_batch_verify(&mut arthur, num_polynomials, &point_per_poly, &eval_per_poly, &proof)
        //     .is_ok());
        println!("PASSED!");
    }

    #[test]
    fn test_whir() {
        let folding_factors = [2, 3, 4, 5];
        let soundness_type = [
            SoundnessType::ConjectureList,
            SoundnessType::ProvableList,
            SoundnessType::UniqueDecoding,
        ];
        let fold_types = [FoldType::Naive, FoldType::ProverHelps];
        let num_points = [0, 1, 2];
        let num_polys = [1, 2, 3];
        let pow_bits = [0, 5, 10];

        for folding_factor in folding_factors {
            let num_variables = folding_factor - 1..=2 * folding_factor;
            for num_variables in num_variables {
                for fold_type in fold_types {
                    for num_points in num_points {
                        for soundness_type in soundness_type {
                            for pow_bits in pow_bits {
                                make_whir_things(
                                    num_variables,
                                    FoldingFactor::Constant(folding_factor),
                                    num_points,
                                    soundness_type,
                                    pow_bits,
                                    fold_type,
                                );
                            }
                        }
                    }
                }
            }
        }

        for folding_factor in folding_factors {
            let num_variables = folding_factor..=2 * folding_factor;
            for num_variables in num_variables {
                for fold_type in fold_types {
                    for num_points in num_points {
                        for num_polys in num_polys {
                            for soundness_type in soundness_type {
                                for pow_bits in pow_bits {
                                    make_whir_batch_things_same_point(
                                        num_polys,
                                        num_variables,
                                        num_points,
                                        folding_factor,
                                        soundness_type,
                                        pow_bits,
                                        fold_type,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        for folding_factor in folding_factors {
            let num_variables = folding_factor..=2 * folding_factor;
            for num_variables in num_variables {
                for fold_type in fold_types {
                    for num_polys in num_polys {
                        for soundness_type in soundness_type {
                            for pow_bits in pow_bits {
                                make_whir_batch_things_diff_point(
                                    num_polys,
                                    num_variables,
                                    folding_factor,
                                    soundness_type,
                                    pow_bits,
                                    fold_type,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
