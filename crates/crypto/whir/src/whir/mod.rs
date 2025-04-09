use ark_crypto_primitives::merkle_tree::{Config, MultiPath};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::poly_utils::MultilinearPoint;

pub mod batch;
pub mod committer;
pub mod fs_utils;
pub mod iopattern;
pub mod parameters;
pub mod prover;
pub mod verifier;

#[derive(Debug, Clone, Default)]
pub struct Statement<F> {
    pub points: Vec<MultilinearPoint<F>>,
    pub evaluations: Vec<F>,
}

// Only includes the authentication paths
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct WhirProof<MerkleConfig, F>(pub(crate) Vec<(MultiPath<MerkleConfig>, Vec<Vec<F>>)>)
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize;

pub fn whir_proof_size<MerkleConfig, F>(
    transcript: &[u8],
    whir_proof: &WhirProof<MerkleConfig, F>,
) -> usize
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    transcript.len() + whir_proof.serialized_size(ark_serialize::Compress::Yes)
}

#[cfg(test)]
mod tests {
    use nimue::{DefaultHash, IOPattern};
    use nimue_pow::blake3::Blake3PoW;

    use crate::{
        crypto::{fields::Field64, merkle_tree::blake3 as merkle_tree},
        parameters::{
            FoldType, FoldingFactor, MultivariateParameters, SoundnessType, WhirParameters,
        },
        poly_utils::{MultilinearPoint, coeffs::CoefficientList},
        whir::{
            Statement, batch::WhirBatchIOPattern, committer::Committer, iopattern::WhirIOPattern,
            parameters::WhirConfig, prover::Prover, verifier::Verifier,
        },
    };

    type MerkleConfig = merkle_tree::MerkleTreeParams<F>;
    type PowStrategy = Blake3PoW;
    type F = Field64;

    fn make_whir_things(
        num_variables: usize,
        folding_factor: FoldingFactor,
        num_points: usize,
        soundness_type: SoundnessType,
        pow_bits: usize,
        fold_type: FoldType,
    ) {
        let num_coeffs = 1 << num_variables;

        let mut rng = ark_std::test_rng();
        let (leaf_hash_params, two_to_one_params) = merkle_tree::default_config::<F>(&mut rng);

        let mv_params = MultivariateParameters::<F>::new(num_variables);

        let whir_params = WhirParameters::<MerkleConfig, PowStrategy> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor,
            leaf_hash_params,
            two_to_one_params,
            soundness_type,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<F, MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let polynomial = CoefficientList::new(vec![F::from(1); num_coeffs]);

        let points: Vec<_> = (0..num_points)
            .map(|_| MultilinearPoint::rand(&mut rng, num_variables))
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

        let mut rng = ark_std::test_rng();
        let (leaf_hash_params, two_to_one_params) = merkle_tree::default_config::<F>(&mut rng);

        let mv_params = MultivariateParameters::<F>::new(num_variables);

        let whir_params = WhirParameters::<MerkleConfig, PowStrategy> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor: FoldingFactor::Constant(folding_factor),
            leaf_hash_params,
            two_to_one_params,
            soundness_type,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<F, MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let polynomials: Vec<CoefficientList<F>> = (0..num_polynomials)
            .map(|i| CoefficientList::new(vec![F::from((i + 1) as i32); num_coeffs]))
            .collect();

        let points: Vec<MultilinearPoint<F>> = (0..num_points)
            .map(|_| MultilinearPoint::rand(&mut rng, num_variables))
            .collect();
        let evals_per_point: Vec<Vec<F>> = points
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

        let mut rng = ark_std::test_rng();
        let (leaf_hash_params, two_to_one_params) = merkle_tree::default_config::<F>(&mut rng);

        let mv_params = MultivariateParameters::<F>::new(num_variables);

        let whir_params = WhirParameters::<MerkleConfig, PowStrategy> {
            initial_statement: true,
            security_level: 32,
            pow_bits,
            folding_factor: FoldingFactor::Constant(folding_factor),
            leaf_hash_params,
            two_to_one_params,
            soundness_type,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
            fold_optimisation: fold_type,
        };

        let params = WhirConfig::<F, MerkleConfig, PowStrategy>::new(mv_params, whir_params);

        let polynomials: Vec<CoefficientList<F>> = (0..num_polynomials)
            .map(|i| CoefficientList::new(vec![F::from((i + 1) as i32); num_coeffs]))
            .collect();

        let point_per_poly: Vec<MultilinearPoint<F>> = (0..num_polynomials)
            .map(|_| MultilinearPoint::rand(&mut rng, num_variables))
            .collect();
        let eval_per_poly: Vec<F> = polynomials
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
