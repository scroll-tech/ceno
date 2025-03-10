use crate::crypto::{MerkleConfig as Config, MultiPath};
use ff_ext::ExtensionField;
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
#[derive(Clone, Serialize, Deserialize)]
pub struct WhirProof<MerkleConfig, E>
where
    MerkleConfig: Config<E>,
    E: ExtensionField + Serialize + DeserializeOwned,
{
    pub(crate) merkle_answers: Vec<(MultiPath<E, MerkleConfig>, Vec<Vec<E>>)>,
    pub(crate) sumcheck_poly_evals: Vec<[E; 3]>,
}

#[cfg(test)]
mod tests {
    use multilinear_extensions::mle::DenseMultilinearExtension;
    use nimue::{DefaultHash, IOPattern};
    use nimue_pow::blake3::Blake3PoW;
    use p3_goldilocks::Goldilocks;
    use rand::rngs::OsRng;

    use crate::{
        crypto::MerkleDefaultConfig,
        parameters::{
            FoldType, FoldingFactor, MultivariateParameters, SoundnessType, WhirParameters,
        },
        whir::{
            Statement, committer::Committer, parameters::WhirConfig, prover::Prover,
            verifier::Verifier,
        },
    };

    type MerkleConfig = MerkleDefaultConfig<E>;
    type PowStrategy = Blake3PoW;
    type E = Goldilocks;

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
        let hash_params = MerkleDefaultConfig::new();

        let mv_params = MultivariateParameters::<E>::new(num_variables);

        let whir_params = WhirParameters::<E, MerkleConfig, PowStrategy> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor,
            hash_params,
            soundness_type,
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<E, MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let polynomial = DenseMultilinearExtension::new(vec![E::from(1); num_coeffs]);

        let points: Vec<_> = (0..num_points)
            .map(|_| Vec::rand(&mut rng, num_variables))
            .collect();

        let statement = Statement {
            points: points.clone(),
            evaluations: points
                .iter()
                .map(|point| polynomial.evaluate(point))
                .collect(),
        };

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&params)
            .add_whir_proof(&params)
            .clone();

        let mut merlin = io.to_merlin();

        let committer = Committer::new(params.clone());
        let witness = committer.commit(&mut merlin, polynomial).unwrap();

        let prover = Prover(params.clone());

        let proof = prover
            .prove(&mut merlin, statement.clone(), witness)
            .unwrap();

        let verifier = Verifier::new(params);
        let mut arthur = io.to_arthur(merlin.transcript());
        assert!(verifier.verify(&mut arthur, &statement, &proof).is_ok());
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
        let hash_params = MerkleDefaultConfig::new();

        let mv_params = MultivariateParameters::<E>::new(num_variables);

        let whir_params = WhirParameters::<E, MerkleConfig, PowStrategy> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor: FoldingFactor::Constant(folding_factor),
            hash_params,
            soundness_type,
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<E, MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let polynomials: Vec<DenseMultilinearExtension<E>> = (0..num_polynomials)
            .map(|i| DenseMultilinearExtension::new(vec![E::from((i + 1) as i32); num_coeffs]))
            .collect();

        let points: Vec<Vec<E>> = (0..num_points)
            .map(|_| Vec::rand(&mut rng, num_variables))
            .collect();
        let evals_per_point: Vec<Vec<E>> = points
            .iter()
            .map(|point| {
                polynomials
                    .iter()
                    .map(|poly| poly.evaluate(point))
                    .collect()
            })
            .collect();

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_batch_statement(&params, num_polynomials)
            .add_whir_batch_proof(&params, num_polynomials)
            .clone();
        let mut merlin = io.to_merlin();

        let committer = Committer::new(params.clone());
        let witnesses = committer.batch_commit(&mut merlin, &polynomials).unwrap();

        let prover = Prover(params.clone());

        let proof = prover
            .simple_batch_prove(&mut merlin, &points, &evals_per_point, &witnesses)
            .unwrap();

        let verifier = Verifier::new(params);
        let mut arthur = io.to_arthur(merlin.transcript());
        assert!(
            verifier
                .simple_batch_verify(
                    &mut arthur,
                    num_polynomials,
                    &points,
                    &evals_per_point,
                    &proof
                )
                .is_ok()
        );
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
        let hash_params = MerkleDefaultConfig::new();

        let mv_params = MultivariateParameters::<E>::new(num_variables);

        let whir_params = WhirParameters::<E, MerkleConfig, PowStrategy> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor: FoldingFactor::Constant(folding_factor),
            hash_params,
            soundness_type,
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<E, MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let polynomials: Vec<DenseMultilinearExtension<E>> = (0..num_polynomials)
            .map(|i| DenseMultilinearExtension::new(vec![E::from((i + 1) as i32); num_coeffs]))
            .collect();

        let point_per_poly: Vec<Vec<E>> = (0..num_polynomials)
            .map(|_| Vec::rand(&mut rng, num_variables))
            .collect();
        let eval_per_poly: Vec<E> = polynomials
            .iter()
            .zip(&point_per_poly)
            .map(|(poly, point)| poly.evaluate(point))
            .collect();

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_batch_statement(&params, num_polynomials)
            .add_whir_unify_proof(&params, num_polynomials)
            .add_whir_batch_proof(&params, num_polynomials)
            .clone();
        let mut merlin = io.to_merlin();

        let committer = Committer::new(params.clone());
        let witnesses = committer.batch_commit(&mut merlin, &polynomials).unwrap();

        let prover = Prover(params.clone());

        let proof = prover
            .same_size_batch_prove(&mut merlin, &point_per_poly, &eval_per_poly, &witnesses)
            .unwrap();

        let verifier = Verifier::new(params);
        let mut arthur = io.to_arthur(merlin.transcript());
        verifier
            .same_size_batch_verify(
                &mut arthur,
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
