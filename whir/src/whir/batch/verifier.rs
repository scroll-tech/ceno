use std::iter;

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use ark_std::log2;
use itertools::zip_eq;
use nimue::{
    plugins::ark::{FieldChallenges, FieldReader},
    ByteChallenges, ByteReader, ProofError, ProofResult,
};
use nimue_pow::{self, PoWChallenge};

use crate::whir::fs_utils::{get_challenge_stir_queries, DigestReader};
use crate::whir::{
    verifier::{ParsedCommitment, ParsedProof, ParsedRound, Verifier},
    Statement, WhirProof,
};
use crate::{
    poly_utils::{coeffs::CoefficientList, eq_poly_outside, MultilinearPoint},
    sumcheck::proof::SumcheckPolynomial,
    utils::expand_randomness,
};

impl<F, MerkleConfig, PowStrategy> Verifier<F, MerkleConfig, PowStrategy>
where
    F: FftField,
    MerkleConfig: Config<Leaf = [F]>,
    PowStrategy: nimue_pow::PowStrategy,
{
    // Same multiple points on each polynomial
    pub fn simple_batch_verify<Arthur>(
        &self,
        arthur: &mut Arthur,
        num_polys: usize,
        points: &[MultilinearPoint<F>],
        evals_per_point: &[Vec<F>],
        whir_proof: &WhirProof<MerkleConfig, F>,
    ) -> ProofResult<MerkleConfig::InnerDigest>
    where
        Arthur: FieldChallenges<F>
            + FieldReader<F>
            + ByteChallenges
            + ByteReader
            + PoWChallenge
            + DigestReader<MerkleConfig>,
    {
        for evals in evals_per_point {
            assert_eq!(num_polys, evals.len());
        }

        // We first do a pass in which we rederive all the FS challenges
        // Then we will check the algebraic part (so to optimise inversions)
        let parsed_commitment = self.parse_commitment_batch(arthur, num_polys)?;
        self.batch_verify_internal(arthur, num_polys, points, evals_per_point, parsed_commitment, whir_proof)
    }

    // Different points on each polynomial
    pub fn same_size_batch_verify<Arthur>(
        &self,
        arthur: &mut Arthur,
        num_polys: usize,
        point_per_poly: &Vec<MultilinearPoint<F>>,
        eval_per_poly: &Vec<F>, // evaluations of the polys on individual points
        whir_proof: &WhirProof<MerkleConfig, F>,
    ) -> ProofResult<MerkleConfig::InnerDigest>
    where
        Arthur: FieldChallenges<F>
            + FieldReader<F>
            + ByteChallenges
            + ByteReader
            + PoWChallenge
            + DigestReader<MerkleConfig>,
    {
        assert_eq!(num_polys, point_per_poly.len());
        assert_eq!(num_polys, eval_per_poly.len());

        // We first do a pass in which we rederive all the FS challenges
        // Then we will check the algebraic part (so to optimise inversions)
        let parsed_commitment = self.parse_commitment_batch(arthur, num_polys)?;

        // parse proof
        let poly_comb_randomness = super::utils::generate_random_vector_batch_verify(arthur, num_polys)?;
        let (folded_points, folded_evals) = self.parse_unify_sumcheck(arthur, point_per_poly, poly_comb_randomness)?;

        self.batch_verify_internal(arthur, num_polys, &vec![folded_points], &vec![folded_evals.clone()], parsed_commitment, whir_proof)
    }

    fn batch_verify_internal<Arthur>(
        &self,
        arthur: &mut Arthur,
        num_polys: usize,
        points: &[MultilinearPoint<F>],
        evals_per_point: &[Vec<F>],
        parsed_commitment: ParsedCommitment<F, MerkleConfig::InnerDigest>,
        whir_proof: &WhirProof<MerkleConfig, F>,
    ) -> ProofResult<MerkleConfig::InnerDigest>
    where
        Arthur: FieldChallenges<F>
            + FieldReader<F>
            + ByteChallenges
            + ByteReader
            + PoWChallenge
            + DigestReader<MerkleConfig>,
    {
        // parse proof
        let compute_dot_product =
            |evals: &[F], coeff: &[F]| -> F { zip_eq(evals, coeff).map(|(a, b)| *a * *b).sum() };

        let random_coeff = super::utils::generate_random_vector_batch_verify(arthur, num_polys)?;
        let initial_claims: Vec<_> = parsed_commitment
            .ood_points
            .clone()
            .into_iter()
            .map(|ood_point| {
                MultilinearPoint::expand_from_univariate(
                    ood_point,
                    self.params.mv_parameters.num_variables,
                )
            })
            .chain(points.to_vec())
            .collect();

        let ood_answers = parsed_commitment
            .ood_answers
            .clone()
            .chunks_exact(num_polys)
            .map(|answer| compute_dot_product(answer, &random_coeff))
            .collect::<Vec<_>>();
        let eval_per_point = evals_per_point.iter().map(|evals| compute_dot_product(evals, &random_coeff));

        let initial_answers: Vec<_> = ood_answers
            .into_iter()
            .chain(eval_per_point)
            .collect();

        let statement = Statement {
            points: initial_claims,
            evaluations: initial_answers,
        };
        let parsed = self.parse_proof_batch(
            arthur,
            &parsed_commitment,
            &statement,
            whir_proof,
            random_coeff.clone(),
            num_polys,
        )?;

        let computed_folds = self.compute_folds(&parsed);

        let mut prev: Option<(SumcheckPolynomial<F>, F)> = None;
        if let Some(round) = parsed.initial_sumcheck_rounds.first() {
            // Check the first polynomial
            let (mut prev_poly, mut randomness) = round.clone();
            if prev_poly.sum_over_hypercube()
                != statement
                    .evaluations
                    .clone()
                    .into_iter()
                    .zip(&parsed.initial_combination_randomness)
                    .map(|(ans, rand)| ans * rand)
                    .sum()
            {
                return Err(ProofError::InvalidProof);
            }

            // Check the rest of the rounds
            for (sumcheck_poly, new_randomness) in &parsed.initial_sumcheck_rounds[1..] {
                if sumcheck_poly.sum_over_hypercube()
                    != prev_poly.evaluate_at_point(&randomness.into())
                {
                    return Err(ProofError::InvalidProof);
                }
                prev_poly = sumcheck_poly.clone();
                randomness = *new_randomness;
            }

            prev = Some((prev_poly, randomness));
        }

        for (round, folds) in parsed.rounds.iter().zip(&computed_folds) {
            let (sumcheck_poly, new_randomness) = &round.sumcheck_rounds[0].clone();

            let values = round.ood_answers.iter().copied().chain(folds.clone());

            let prev_eval = if let Some((prev_poly, randomness)) = prev {
                prev_poly.evaluate_at_point(&randomness.into())
            } else {
                F::ZERO
            };
            let claimed_sum = prev_eval
                + values
                    .zip(&round.combination_randomness)
                    .map(|(val, rand)| val * rand)
                    .sum::<F>();

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(ProofError::InvalidProof);
            }

            prev = Some((sumcheck_poly.clone(), *new_randomness));

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &round.sumcheck_rounds[1..] {
                let (prev_poly, randomness) = prev.unwrap();
                if sumcheck_poly.sum_over_hypercube()
                    != prev_poly.evaluate_at_point(&randomness.into())
                {
                    return Err(ProofError::InvalidProof);
                }
                prev = Some((sumcheck_poly.clone(), *new_randomness));
            }
        }

        // Check the foldings computed from the proof match the evaluations of the polynomial
        let final_folds = &computed_folds[computed_folds.len() - 1];
        let final_evaluations = parsed
            .final_coefficients
            .evaluate_at_univariate(&parsed.final_randomness_points);
        if !final_folds
            .iter()
            .zip(final_evaluations)
            .all(|(&fold, eval)| fold == eval)
        {
            return Err(ProofError::InvalidProof);
        }

        // Check the final sumchecks
        if self.params.final_sumcheck_rounds > 0 {
            let prev_sumcheck_poly_eval = if let Some((prev_poly, randomness)) = prev {
                prev_poly.evaluate_at_point(&randomness.into())
            } else {
                F::ZERO
            };
            let (sumcheck_poly, new_randomness) = &parsed.final_sumcheck_rounds[0].clone();
            let claimed_sum = prev_sumcheck_poly_eval;

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(ProofError::InvalidProof);
            }

            prev = Some((sumcheck_poly.clone(), *new_randomness));

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &parsed.final_sumcheck_rounds[1..] {
                let (prev_poly, randomness) = prev.unwrap();
                if sumcheck_poly.sum_over_hypercube()
                    != prev_poly.evaluate_at_point(&randomness.into())
                {
                    return Err(ProofError::InvalidProof);
                }
                prev = Some((sumcheck_poly.clone(), *new_randomness));
            }
        }

        let prev_sumcheck_poly_eval = if let Some((prev_poly, randomness)) = prev {
            prev_poly.evaluate_at_point(&randomness.into())
        } else {
            F::ZERO
        };

        // Check the final sumcheck evaluation
        let evaluation_of_v_poly = self.compute_v_poly_for_batched(&statement, &parsed);

        if prev_sumcheck_poly_eval
            != evaluation_of_v_poly
                * parsed
                    .final_coefficients
                    .evaluate(&parsed.final_sumcheck_randomness)
        {
            return Err(ProofError::InvalidProof);
        }

        Ok(parsed_commitment.root)
    }

    fn parse_commitment_batch<Arthur>(
        &self,
        arthur: &mut Arthur,
        num_polys: usize,
    ) -> ProofResult<ParsedCommitment<F, MerkleConfig::InnerDigest>>
    where
        Arthur: ByteReader + FieldReader<F> + FieldChallenges<F> + DigestReader<MerkleConfig>,
    {
        let root = arthur.read_digest()?;

        let mut ood_points = vec![F::ZERO; self.params.committment_ood_samples];
        let mut ood_answers = vec![F::ZERO; self.params.committment_ood_samples * num_polys];
        if self.params.committment_ood_samples > 0 {
            arthur.fill_challenge_scalars(&mut ood_points)?;
            arthur.fill_next_scalars(&mut ood_answers)?;
        }

        Ok(ParsedCommitment {
            root,
            ood_points,
            ood_answers,
        })
    }

    fn parse_unify_sumcheck<Arthur>(
        &self,
        arthur: &mut Arthur,
        point_per_poly: &Vec<MultilinearPoint<F>>,
        poly_comb_randomness: Vec<F>,
    ) -> ProofResult<(MultilinearPoint<F>, Vec<F>)>
    where
        Arthur: FieldReader<F>
            + FieldChallenges<F>
            + PoWChallenge
            + ByteReader
            + ByteChallenges
            + DigestReader<MerkleConfig>,
    {
        let num_variables = self.params.mv_parameters.num_variables;
        let mut sumcheck_rounds = Vec::new();

        // Derive combination randomness and first sumcheck polynomial
        // let [point_comb_randomness_gen]: [F; 1] = arthur.challenge_scalars()?;
        // let point_comb_randomness = expand_randomness(point_comb_randomness_gen, num_points);

        // Unifying sumcheck
        sumcheck_rounds.reserve_exact(num_variables);
        for _ in 0..num_variables {
            let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let [folding_randomness_single] = arthur.challenge_scalars()?;
            sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

            if self.params.starting_folding_pow_bits > 0. {
                arthur.challenge_pow::<PowStrategy>(self.params.starting_folding_pow_bits)?;
            }
        }
        let folded_point = MultilinearPoint(sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect());
        let folded_eqs: Vec<F> = point_per_poly
            .iter()
            .zip(&poly_comb_randomness)
            .map(|(point, randomness)| *randomness * eq_poly_outside(&point, &folded_point))
            .collect();
        let mut folded_evals = vec![F::ZERO; point_per_poly.len()];
        arthur.fill_next_scalars(&mut folded_evals)?;
        let sumcheck_claim = sumcheck_rounds[num_variables - 1].0.evaluate_at_point(&MultilinearPoint(vec![sumcheck_rounds[num_variables - 1].1]));
        let sumcheck_expected: F = folded_evals.iter().zip(&folded_eqs).map(|(eval, eq)| *eval * *eq).sum();
        if sumcheck_claim != sumcheck_expected {
            return Err(ProofError::InvalidProof);
        }

        Ok((folded_point, folded_evals))
    }

    fn pow_with_precomputed_squares(squares: &[F], mut index: usize) -> F {
        let mut result = F::one();
        let mut i = 0;
        while index > 0 {
            if index & 1 == 1 {
                result *= squares[i];
            }
            index >>= 1;
            i += 1;
        }
        result
    }

    fn parse_proof_batch<Arthur>(
        &self,
        arthur: &mut Arthur,
        parsed_commitment: &ParsedCommitment<F, MerkleConfig::InnerDigest>,
        statement: &Statement<F>, // Will be needed later
        whir_proof: &WhirProof<MerkleConfig, F>,
        batched_randomness: Vec<F>,
        num_polys: usize,
    ) -> ProofResult<ParsedProof<F>>
    where
        Arthur: FieldReader<F>
            + FieldChallenges<F>
            + PoWChallenge
            + ByteReader
            + ByteChallenges
            + DigestReader<MerkleConfig>,
    {
        let mut sumcheck_rounds = Vec::new();
        let mut folding_randomness: MultilinearPoint<F>;
        let initial_combination_randomness;

        if self.params.initial_statement {
            // Derive combination randomness and first sumcheck polynomial
            let [combination_randomness_gen]: [F; 1] = arthur.challenge_scalars()?;
            initial_combination_randomness = expand_randomness(
                combination_randomness_gen,
                parsed_commitment.ood_points.len() + statement.points.len(),
            );

            // Initial sumcheck
            sumcheck_rounds.reserve_exact(self.params.folding_factor.at_round(0));
            for _ in 0..self.params.folding_factor.at_round(0) {
                let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
                let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
                let [folding_randomness_single] = arthur.challenge_scalars()?;
                sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

                if self.params.starting_folding_pow_bits > 0. {
                    arthur.challenge_pow::<PowStrategy>(self.params.starting_folding_pow_bits)?;
                }
            }

            folding_randomness =
                MultilinearPoint(sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect());
        } else {
            assert_eq!(parsed_commitment.ood_points.len(), 0);
            assert_eq!(statement.points.len(), 0);

            initial_combination_randomness = vec![F::ONE];

            let mut folding_randomness_vec = vec![F::ZERO; self.params.folding_factor.at_round(0)];
            arthur.fill_challenge_scalars(&mut folding_randomness_vec)?;
            folding_randomness = MultilinearPoint(folding_randomness_vec);

            // PoW
            if self.params.starting_folding_pow_bits > 0. {
                arthur.challenge_pow::<PowStrategy>(self.params.starting_folding_pow_bits)?;
            }
        };

        let mut prev_root = parsed_commitment.root.clone();
        let domain_gen = self.params.starting_domain.backing_domain.group_gen();
        // Precompute the powers of the domain generator, so that
        // we can always compute domain_gen.pow(1 << i) by domain_gen_powers[i]
        let domain_gen_powers = std::iter::successors(Some(domain_gen), |&curr| Some(curr * curr))
            .take(log2(self.params.starting_domain.size()) as usize)
            .collect::<Vec<_>>();
        // Since the generator of the domain will be repeatedly squared in
        // the future, keep track of the log of the power (i.e., how many times
        // it has been squared from domain_gen).
        // In another word, always ensure current domain generator = domain_gen_powers[log_based_on_domain_gen]
        let mut log_based_on_domain_gen: usize = 0;
        let mut domain_gen_inv = self.params.starting_domain.backing_domain.group_gen_inv();
        let mut domain_size = self.params.starting_domain.size();
        let mut rounds = vec![];

        for r in 0..self.params.n_rounds() {
            let (merkle_proof, answers) = &whir_proof.0[r];
            let round_params = &self.params.round_parameters[r];

            let new_root = arthur.read_digest()?;

            let mut ood_points = vec![F::ZERO; round_params.ood_samples];
            let mut ood_answers = vec![F::ZERO; round_params.ood_samples];
            if round_params.ood_samples > 0 {
                arthur.fill_challenge_scalars(&mut ood_points)?;
                arthur.fill_next_scalars(&mut ood_answers)?;
            }

            let stir_challenges_indexes = get_challenge_stir_queries(
                domain_size,
                self.params.folding_factor.at_round(r),
                round_params.num_queries,
                arthur,
            )?;

            let stir_challenges_points = stir_challenges_indexes
                .iter()
                .map(|index| {
                    Self::pow_with_precomputed_squares(
                        &domain_gen_powers.as_slice()
                            [log_based_on_domain_gen + self.params.folding_factor.at_round(r)..],
                        *index,
                    )
                })
                .collect();

            if !merkle_proof
                .verify(
                    &self.params.leaf_hash_params,
                    &self.params.two_to_one_params,
                    &prev_root,
                    answers.iter().map(|a| a.as_ref()),
                )
                .unwrap()
                || merkle_proof.leaf_indexes != stir_challenges_indexes
            {
                return Err(ProofError::InvalidProof);
            }

            let answers: Vec<_> = if r == 0 {
                answers
                    .into_iter()
                    .map(|raw_answer| {
                        if batched_randomness.len() > 0 {
                            let chunk_size = 1 << self.params.folding_factor.at_round(r);
                            let mut res = vec![F::ZERO; chunk_size];
                            for i in 0..chunk_size {
                                for j in 0..num_polys {
                                    res[i] +=
                                        raw_answer[i + j * chunk_size] * batched_randomness[j];
                                }
                            }
                            res
                        } else {
                            raw_answer.clone()
                        }
                    })
                    .collect()
            } else {
                answers.to_vec()
            };

            if round_params.pow_bits > 0. {
                arthur.challenge_pow::<PowStrategy>(round_params.pow_bits)?;
            }

            let [combination_randomness_gen] = arthur.challenge_scalars()?;
            let combination_randomness = expand_randomness(
                combination_randomness_gen,
                stir_challenges_indexes.len() + round_params.ood_samples,
            );

            let mut sumcheck_rounds =
                Vec::with_capacity(self.params.folding_factor.at_round(r + 1));
            for _ in 0..self.params.folding_factor.at_round(r + 1) {
                let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
                let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
                let [folding_randomness_single] = arthur.challenge_scalars()?;
                sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

                if round_params.folding_pow_bits > 0. {
                    arthur.challenge_pow::<PowStrategy>(round_params.folding_pow_bits)?;
                }
            }

            let new_folding_randomness =
                MultilinearPoint(sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect());

            rounds.push(ParsedRound {
                folding_randomness,
                ood_points,
                ood_answers,
                stir_challenges_indexes,
                stir_challenges_points,
                stir_challenges_answers: answers,
                combination_randomness,
                sumcheck_rounds,
                domain_gen_inv,
            });

            folding_randomness = new_folding_randomness;

            prev_root = new_root.clone();
            log_based_on_domain_gen += 1;
            domain_gen_inv = domain_gen_inv * domain_gen_inv;
            domain_size >>= 1;
        }

        let mut final_coefficients = vec![F::ZERO; 1 << self.params.final_sumcheck_rounds];
        arthur.fill_next_scalars(&mut final_coefficients)?;
        let final_coefficients = CoefficientList::new(final_coefficients);

        // Final queries verify
        let final_randomness_indexes = get_challenge_stir_queries(
            domain_size,
            self.params.folding_factor.at_round(self.params.n_rounds()),
            self.params.final_queries,
            arthur,
        )?;
        let final_randomness_points = final_randomness_indexes
            .iter()
            .map(|index| {
                Self::pow_with_precomputed_squares(
                    &domain_gen_powers.as_slice()[log_based_on_domain_gen
                        + self.params.folding_factor.at_round(self.params.n_rounds())..],
                    *index,
                )
            })
            .collect();

        let (final_merkle_proof, final_randomness_answers) = &whir_proof.0[whir_proof.0.len() - 1];
        if !final_merkle_proof
            .verify(
                &self.params.leaf_hash_params,
                &self.params.two_to_one_params,
                &prev_root,
                final_randomness_answers.iter().map(|a| a.as_ref()),
            )
            .unwrap()
            || final_merkle_proof.leaf_indexes != final_randomness_indexes
        {
            return Err(ProofError::InvalidProof);
        }

        let final_randomness_answers: Vec<_> = if self.params.n_rounds() == 0 {
            final_randomness_answers
                .into_iter()
                .map(|raw_answer| {
                    if batched_randomness.len() > 0 {
                        let chunk_size =
                            1 << self.params.folding_factor.at_round(self.params.n_rounds());
                        let mut res = vec![F::ZERO; chunk_size];
                        for i in 0..chunk_size {
                            for j in 0..num_polys {
                                res[i] += raw_answer[i + j * chunk_size] * batched_randomness[j];
                            }
                        }
                        res
                    } else {
                        raw_answer.clone()
                    }
                })
                .collect()
        } else {
            final_randomness_answers.to_vec()
        };

        if self.params.final_pow_bits > 0. {
            arthur.challenge_pow::<PowStrategy>(self.params.final_pow_bits)?;
        }

        let mut final_sumcheck_rounds = Vec::with_capacity(self.params.final_sumcheck_rounds);
        for _ in 0..self.params.final_sumcheck_rounds {
            let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let [folding_randomness_single] = arthur.challenge_scalars()?;
            final_sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

            if self.params.final_folding_pow_bits > 0. {
                arthur.challenge_pow::<PowStrategy>(self.params.final_folding_pow_bits)?;
            }
        }
        let final_sumcheck_randomness = MultilinearPoint(
            final_sumcheck_rounds
                .iter()
                .map(|&(_, r)| r)
                .rev()
                .collect(),
        );

        Ok(ParsedProof {
            initial_combination_randomness,
            initial_sumcheck_rounds: sumcheck_rounds,
            rounds,
            final_domain_gen_inv: domain_gen_inv,
            final_folding_randomness: folding_randomness,
            final_randomness_indexes,
            final_randomness_points,
            final_randomness_answers: final_randomness_answers.to_vec(),
            final_sumcheck_rounds,
            final_sumcheck_randomness,
            final_coefficients,
        })
    }

    /// this is copied and modified from `fn compute_v_poly`
    /// to avoid modify the original function for compatibility
    fn compute_v_poly_for_batched(&self, statement: &Statement<F>, proof: &ParsedProof<F>) -> F {
        let mut num_variables = self.params.mv_parameters.num_variables;

        let mut folding_randomness = MultilinearPoint(
            iter::once(&proof.final_sumcheck_randomness.0)
                .chain(iter::once(&proof.final_folding_randomness.0))
                .chain(proof.rounds.iter().rev().map(|r| &r.folding_randomness.0))
                .flatten()
                .copied()
                .collect(),
        );

        let mut value = statement
            .points
            .iter()
            .zip(&proof.initial_combination_randomness)
            .map(|(point, randomness)| *randomness * eq_poly_outside(&point, &folding_randomness))
            .sum();

        for (round, round_proof) in proof.rounds.iter().enumerate() {
            num_variables -= self.params.folding_factor.at_round(round);
            folding_randomness = MultilinearPoint(folding_randomness.0[..num_variables].to_vec());

            let ood_points = &round_proof.ood_points;
            let stir_challenges_points = &round_proof.stir_challenges_points;
            let stir_challenges: Vec<_> = ood_points
                .iter()
                .chain(stir_challenges_points)
                .cloned()
                .map(|univariate| {
                    MultilinearPoint::expand_from_univariate(univariate, num_variables)
                    // TODO:
                    // Maybe refactor outside
                })
                .collect();

            let sum_of_claims: F = stir_challenges
                .into_iter()
                .map(|point| eq_poly_outside(&point, &folding_randomness))
                .zip(&round_proof.combination_randomness)
                .map(|(point, rand)| point * rand)
                .sum();

            value += sum_of_claims;
        }

        value
    }
}