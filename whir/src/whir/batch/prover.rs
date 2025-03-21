use super::committer::Witnesses;
use crate::{
    crypto::{Digest, MerkleTree, MerkleTreeExt, generate_multi_proof, write_digest_to_transcript},
    end_timer,
    error::Error,
    ntt::expand_from_coeff,
    parameters::FoldType,
    start_timer,
    sumcheck::{
        prover_not_skipping::SumcheckProverNotSkipping,
        prover_not_skipping_batched::SumcheckProverNotSkippingBatched,
    },
    utils::{self, evaluate_over_hypercube, expand_randomness, interpolate_over_boolean_hypercube},
    whir::{
        WhirProof,
        batch::utils::field_type_index_ext,
        fold::{compute_fold, expand_from_univariate, restructure_evaluations},
        prover::{Prover, RoundState},
    },
};
use ff_ext::ExtensionField;
use itertools::zip_eq;
use multilinear_extensions::mle::{DenseMultilinearExtension, FieldType, MultilinearExtension};
use p3::{commit::Mmcs, matrix::dense::RowMajorMatrix};
use transcript::Transcript;

use crate::whir::fs_utils::{MmcsCommitmentWriter, get_challenge_stir_queries};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

struct RoundStateBatch<'a, E: ExtensionField> {
    round_state: RoundState<'a, E>,
    batching_randomness: Vec<E>,
    prev_merkle: &'a MerkleTreeExt<E>,
    prev_merkle_answers: &'a Vec<E>,
}

impl<E: ExtensionField> Prover<E> {
    fn validate_witnesses(&self, witness: &Witnesses<E>) -> bool {
        assert_eq!(
            witness.ood_points.len() * witness.polys.len(),
            witness.ood_answers.len()
        );
        if !self.0.initial_statement {
            assert!(witness.ood_points.is_empty());
        }
        assert!(!witness.polys.is_empty(), "Input polys cannot be empty");
        witness.polys.iter().skip(1).for_each(|poly| {
            assert_eq!(
                poly.num_vars(),
                witness.polys[0].num_vars(),
                "All polys must have the same number of variables"
            );
        });
        witness.polys[0].num_vars() == self.0.mv_parameters.num_variables
    }

    /// batch open the same points for multiple polys
    pub fn simple_batch_prove<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        points: &[Vec<E>],
        evals_per_point: &[Vec<E>], // outer loop on each point, inner loop on each poly
        witness: &Witnesses<E>,
    ) -> Result<WhirProof<E>, Error> {
        let prove_timer = start_timer!(|| "prove");
        let initial_timer = start_timer!(|| "init");
        let mut sumcheck_poly_evals = Vec::new();
        let mut merkle_roots = Vec::new();
        let mut ood_answers: Vec<Vec<E>> = Vec::new();
        assert!(self.0.initial_statement, "must be true for pcs");
        assert!(self.validate_parameters());
        assert!(self.validate_witnesses(witness));
        for point in points {
            assert_eq!(
                point.len(),
                self.0.mv_parameters.num_variables,
                "number of variables mismatch"
            );
        }
        let num_polys = witness.polys.len();
        for evals in evals_per_point {
            assert_eq!(
                evals.len(),
                num_polys,
                "number of polynomials not equal number of evaluations"
            );
        }

        let compute_dot_product =
            |evals: &[E], coeff: &[E]| -> E { zip_eq(evals, coeff).map(|(a, b)| *a * *b).sum() };
        end_timer!(initial_timer);

        let random_coeff_timer = start_timer!(|| "random coeff");
        let random_coeff =
            super::utils::generate_random_vector_batch_open(transcript, witness.polys.len())?;
        end_timer!(random_coeff_timer);

        let initial_claims_timer = start_timer!(|| "initial claims");
        let initial_claims: Vec<_> = witness
            .ood_points
            .par_iter()
            .map(|ood_point| expand_from_univariate(*ood_point, self.0.mv_parameters.num_variables))
            .chain(points.to_vec())
            .collect();
        end_timer!(initial_claims_timer);

        let ood_answers_timer = start_timer!(|| "ood answers");
        let ood_answers_round = witness
            .ood_answers
            .par_chunks_exact(witness.polys.len())
            .map(|answer| compute_dot_product(answer, &random_coeff))
            .collect::<Vec<_>>();
        end_timer!(ood_answers_timer);

        let eval_timer = start_timer!(|| "eval");
        let eval_per_point: Vec<E> = evals_per_point
            .par_iter()
            .map(|evals| compute_dot_product(evals, &random_coeff))
            .collect();
        end_timer!(eval_timer);

        let combine_timer = start_timer!(|| "Combine polynomial");
        let initial_answers: Vec<_> = ood_answers_round
            .into_iter()
            .chain(eval_per_point)
            .collect();

        let polynomial = (0..(1 << witness.polys[0].num_vars()))
            .into_par_iter()
            .map(|i| {
                witness
                    .polys
                    .iter()
                    .zip(&random_coeff)
                    .map(|(eval, coeff)| field_type_index_ext(eval.evaluations(), i) * *coeff)
                    .sum()
            })
            .collect::<Vec<_>>();
        end_timer!(combine_timer);

        let comb_timer = start_timer!(|| "combination randomness");
        let combination_randomness_gen = transcript
            .sample_and_append_challenge(b"combination_randomness")
            .elements;
        let combination_randomness =
            expand_randomness(combination_randomness_gen, initial_claims.len());
        end_timer!(comb_timer);

        let sumcheck_timer = start_timer!(|| "sumcheck");
        let mut sumcheck_prover = Some(SumcheckProverNotSkipping::new(
            DenseMultilinearExtension::from_evaluations_ext_vec(
                p3::util::log2_strict_usize(polynomial.len()),
                polynomial.clone(),
            ),
            &initial_claims,
            &combination_randomness,
            &initial_answers,
        ));
        end_timer!(sumcheck_timer);

        let sumcheck_prover_timer = start_timer!(|| "sumcheck_prover");
        let folding_randomness = sumcheck_prover
            .as_mut()
            .unwrap()
            .compute_sumcheck_polynomials::<T>(
                transcript,
                &mut sumcheck_poly_evals,
                self.0.folding_factor.at_round(0),
            )?;
        end_timer!(sumcheck_prover_timer);

        let timer = start_timer!(|| "round_batch");
        let round_state = RoundStateBatch {
            round_state: RoundState {
                domain: self.0.starting_domain.clone(),
                round: 0,
                sumcheck_prover,
                folding_randomness,
                evaluations: DenseMultilinearExtension::from_evaluations_ext_vec(
                    p3::util::log2_strict_usize(polynomial.len()),
                    polynomial,
                ),
                prev_merkle: None,
                prev_merkle_answers: Vec::new(),
                merkle_proofs: vec![],
            },
            prev_merkle: &witness.merkle_tree,
            prev_merkle_answers: &witness.merkle_leaves,
            batching_randomness: random_coeff,
        };

        let result = self.simple_round_batch(
            transcript,
            &mut sumcheck_poly_evals,
            &mut ood_answers,
            &mut merkle_roots,
            round_state,
            num_polys,
        );
        end_timer!(timer);
        end_timer!(prove_timer);

        result
    }

    fn simple_round_batch<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        sumcheck_poly_evals: &mut Vec<Vec<E>>,
        ood_answers: &mut Vec<Vec<E>>,
        merkle_roots: &mut Vec<Digest<E>>,
        round_state: RoundStateBatch<E>,
        num_polys: usize,
    ) -> Result<WhirProof<E>, Error> {
        let batching_randomness = round_state.batching_randomness;
        let prev_merkle = round_state.prev_merkle;
        let prev_merkle_answers = round_state.prev_merkle_answers;
        let mut round_state = round_state.round_state;
        // Fold the coefficients
        let folded_evaluations = round_state
            .evaluations
            .fix_variables(&round_state.folding_randomness);

        let folded_coefficients_evals = match folded_evaluations.evaluations() {
            FieldType::Ext(evals) => evals,
            _ => {
                panic!("Impossible after folding");
            }
        };
        let num_variables = self.0.mv_parameters.num_variables
            - self.0.folding_factor.total_number(round_state.round);

        // Base case
        if round_state.round == self.0.n_rounds() {
            // Coefficients of the polynomial
            transcript.append_field_element_exts(&folded_coefficients_evals);

            // Final verifier queries and answers
            let final_challenge_indexes = get_challenge_stir_queries(
                round_state.domain.size(),
                self.0.folding_factor.at_round(round_state.round),
                self.0.final_queries,
                transcript,
            )?;

            let merkle_proof =
                generate_multi_proof(&self.0.hash_params, prev_merkle, &final_challenge_indexes);
            let fold_size = 1 << self.0.folding_factor.at_round(round_state.round);
            let answers = final_challenge_indexes
                .into_par_iter()
                .map(|i| {
                    prev_merkle_answers
                        [i * (fold_size * num_polys)..(i + 1) * (fold_size * num_polys)]
                        .to_vec()
                })
                .collect();

            round_state.merkle_proofs.push((merkle_proof, answers));

            // Final sumcheck
            if self.0.final_sumcheck_rounds > 0 {
                round_state
                    .sumcheck_prover
                    .unwrap_or_else(|| {
                        SumcheckProverNotSkipping::new(folded_evaluations.clone(), &[], &[], &[])
                    })
                    .compute_sumcheck_polynomials::<T>(
                        transcript,
                        sumcheck_poly_evals,
                        self.0.final_sumcheck_rounds,
                    )?;
            }

            return Ok(WhirProof {
                merkle_answers: round_state.merkle_proofs,
                sumcheck_poly_evals: sumcheck_poly_evals.clone(),
                merkle_roots: merkle_roots.clone(),
                ood_answers: ood_answers.clone(),
                final_poly: folded_coefficients_evals.clone(),
                folded_evals: Vec::new(),
            });
        }

        let round_params = &self.0.round_parameters[round_state.round];

        // Fold the coefficients, and compute fft of polynomial (and commit)
        let new_domain = round_state.domain.scale(2);
        let expansion = new_domain.size() / folded_coefficients_evals.len();
        let mut folded_coefficients_coeffs = folded_coefficients_evals.clone();
        interpolate_over_boolean_hypercube(&mut folded_coefficients_coeffs);
        let evals = expand_from_coeff(&folded_coefficients_coeffs, expansion);
        // TODO: `stack_evaluations` and `restructure_evaluations` are really in-place algorithms.
        // They also partially overlap and undo one another. We should merge them.
        let folded_evals =
            utils::stack_evaluations(evals, self.0.folding_factor.at_round(round_state.round + 1));
        let folded_evals = restructure_evaluations(
            folded_evals,
            self.0.fold_optimisation,
            new_domain.backing_domain_group_gen(),
            new_domain.backing_domain_group_gen().inverse(),
            self.0.folding_factor.at_round(round_state.round + 1),
        );
        let (root, merkle_tree) = self.0.hash_params.commit_matrix(RowMajorMatrix::new(
            folded_evals.clone(),
            1 << self.0.folding_factor.at_round(round_state.round + 1),
        ));

        write_digest_to_transcript(&root, transcript);
        merkle_roots.push(root);

        // OOD Samples
        let (ood_points, ood_answers_round) = if round_params.ood_samples > 0 {
            let ood_points =
                transcript.sample_and_append_vec(b"ood_points", round_params.ood_samples);
            let ood_answers = ood_points
                .iter()
                .map(|ood_point| {
                    folded_evaluations.evaluate(&expand_from_univariate(*ood_point, num_variables))
                })
                .collect::<Vec<_>>();
            transcript.append_field_element_exts(&ood_answers);
            (ood_points, ood_answers)
        } else {
            (
                vec![E::ZERO; round_params.ood_samples],
                vec![E::ZERO; round_params.ood_samples],
            )
        };

        // STIR queries
        let stir_challenges_indexes = get_challenge_stir_queries(
            round_state.domain.size(),
            self.0.folding_factor.at_round(round_state.round),
            round_params.num_queries,
            transcript,
        )?;
        let domain_scaled_gen = round_state
            .domain
            .backing_domain_element_pow_of_2(self.0.folding_factor.at_round(round_state.round));
        let stir_challenges: Vec<_> = ood_points
            .into_par_iter()
            .chain(
                stir_challenges_indexes
                    .par_iter()
                    .map(|i| domain_scaled_gen.exp_u64(*i as u64)),
            )
            .map(|univariate| expand_from_univariate(univariate, num_variables))
            .collect();

        let merkle_proof_with_leaves =
            generate_multi_proof(&self.0.hash_params, &prev_merkle, &stir_challenges_indexes);
        let fold_size = (1 << self.0.folding_factor.at_round(round_state.round)) * num_polys;
        let answers = stir_challenges_indexes
            .par_iter()
            .map(|i| prev_merkle_answers[i * fold_size..(i + 1) * fold_size].to_vec())
            .collect::<Vec<_>>();
        let batched_answers = answers
            .par_iter()
            .map(|answer| {
                let chunk_size = 1 << self.0.folding_factor.at_round(round_state.round);
                let mut res = vec![E::ZERO; chunk_size];
                for i in 0..chunk_size {
                    for j in 0..num_polys {
                        res[i] += answer[i + j * chunk_size] * batching_randomness[j];
                    }
                }
                res
            })
            .collect::<Vec<_>>();
        // Evaluate answers in the folding randomness.
        let mut stir_evaluations = ood_answers_round.clone();
        match self.0.fold_optimisation {
            FoldType::Naive => {
                // See `Verifier::compute_folds_full`
                let domain_size = round_state.domain.size();
                let domain_gen = round_state.domain.backing_domain_element(1);
                let domain_gen_inv = domain_gen.inverse();
                let coset_domain_size = 1 << self.0.folding_factor.at_round(round_state.round);
                let coset_generator_inv =
                    domain_gen_inv.exp_u64((domain_size / coset_domain_size) as u64);
                stir_evaluations.extend(stir_challenges_indexes.iter().zip(&batched_answers).map(
                    |(index, batched_answers)| {
                        // The coset is w^index * <w_coset_generator>
                        // let _coset_offset = domain_gen.pow(&[*index as u64]);
                        let coset_offset_inv = domain_gen_inv.exp_u64(*index as u64);

                        let res = compute_fold(
                            batched_answers,
                            &round_state.folding_randomness,
                            coset_offset_inv,
                            coset_generator_inv,
                            E::from_u64(2).inverse(),
                            self.0.folding_factor.at_round(round_state.round),
                        );

                        res
                    },
                ))
            }
            FoldType::ProverHelps => {
                stir_evaluations.extend(batched_answers.iter().map(|batched_answers| {
                    let mut batched_answers_coeffs = batched_answers.to_vec();
                    evaluate_over_hypercube(&mut batched_answers_coeffs);
                    DenseMultilinearExtension::from_evaluations_ext_vec(
                        p3::util::log2_strict_usize(batched_answers_coeffs.len()),
                        batched_answers_coeffs.to_vec(),
                    )
                    .evaluate(&round_state.folding_randomness)
                }))
            }
        }
        round_state
            .merkle_proofs
            .push((merkle_proof_with_leaves, answers));

        // Randomness for combination
        let combination_randomness_gen = transcript
            .sample_and_append_challenge(b"combination_randomness")
            .elements;
        let combination_randomness =
            expand_randomness(combination_randomness_gen, stir_challenges.len());

        let mut sumcheck_prover = round_state
            .sumcheck_prover
            .take()
            .map(|mut sumcheck_prover| {
                sumcheck_prover.add_new_equality(
                    &stir_challenges,
                    &combination_randomness,
                    &stir_evaluations,
                );
                sumcheck_prover
            })
            .unwrap_or_else(|| {
                SumcheckProverNotSkipping::new(
                    folded_evaluations.clone(),
                    &stir_challenges,
                    &combination_randomness,
                    &stir_evaluations,
                )
            });

        let folding_randomness = sumcheck_prover.compute_sumcheck_polynomials::<T>(
            transcript,
            sumcheck_poly_evals,
            self.0.folding_factor.at_round(round_state.round + 1),
        )?;

        let round_state = RoundState {
            round: round_state.round + 1,
            domain: new_domain,
            sumcheck_prover: Some(sumcheck_prover),
            folding_randomness,
            evaluations: folded_evaluations, /* TODO: Is this redundant with `sumcheck_prover.coeff` ? */
            prev_merkle: Some(&merkle_tree),
            prev_merkle_answers: folded_evals,
            merkle_proofs: round_state.merkle_proofs,
        };
        ood_answers.push(ood_answers_round);

        self.round(
            transcript,
            sumcheck_poly_evals,
            ood_answers,
            merkle_roots,
            round_state,
        )
    }
}

impl<E: ExtensionField> Prover<E> {
    /// each poly on a different point, same size
    pub fn same_size_batch_prove<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        point_per_poly: &[Vec<E>],
        eval_per_poly: &[E],
        witness: &Witnesses<E>,
    ) -> Result<WhirProof<E>, Error> {
        let prove_timer = start_timer!(|| "prove");
        let initial_timer = start_timer!(|| "init");
        assert!(self.0.initial_statement, "must be true for pcs");
        assert!(self.validate_parameters());
        assert!(self.validate_witnesses(witness));
        for point in point_per_poly {
            assert_eq!(
                point.len(),
                self.0.mv_parameters.num_variables,
                "number of variables mismatch"
            );
        }
        let num_polys = witness.polys.len();
        assert_eq!(
            eval_per_poly.len(),
            num_polys,
            "number of polynomials not equal number of evaluations"
        );
        end_timer!(initial_timer);

        let poly_comb_randomness_timer = start_timer!(|| "poly comb randomness");
        let poly_comb_randomness =
            super::utils::generate_random_vector_batch_open(transcript, witness.polys.len())?;
        end_timer!(poly_comb_randomness_timer);

        let initial_claims_timer = start_timer!(|| "initial claims");
        let initial_eval_claims = point_per_poly;
        end_timer!(initial_claims_timer);

        let sumcheck_timer = start_timer!(|| "unifying sumcheck");
        let mut sumcheck_prover = SumcheckProverNotSkippingBatched::new(
            witness.polys.clone(),
            initial_eval_claims,
            &poly_comb_randomness,
            eval_per_poly,
        );

        let mut sumcheck_polys = Vec::new();
        // Perform the entire sumcheck
        let folded_point = sumcheck_prover.compute_sumcheck_polynomials::<T>(
            transcript,
            &mut sumcheck_polys,
            self.0.mv_parameters.num_variables,
        )?;
        let folded_evals = sumcheck_prover.get_folded_polys();
        transcript.append_field_element_exts(&folded_evals);
        end_timer!(sumcheck_timer);
        // Problem now reduced to the polys(folded_point) =?= folded_evals

        let timer = start_timer!(|| "simple_batch");
        // perform simple_batch on folded_point and folded_evals
        let mut result =
            self.simple_batch_prove(transcript, &[folded_point], &[folded_evals], witness)?;
        sumcheck_polys.extend(result.sumcheck_poly_evals);
        result.sumcheck_poly_evals = sumcheck_polys;
        end_timer!(timer);
        end_timer!(prove_timer);

        Ok(result)
    }
}
