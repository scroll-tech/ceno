use std::iter;

use crate::{
    crypto::{
        DigestExt, MerklePathExt, MerkleTreeExt, verify_multi_proof, write_digest_to_transcript,
    },
    error::Error,
    sumcheck::proof::SumcheckPolynomial,
    utils::{evaluate_as_univariate, expand_randomness},
    whir::{
        Statement, WhirProof,
        fold::expand_from_univariate,
        fs_utils::get_challenge_stir_queries,
        verifier::{ParsedProof, ParsedRound, Verifier, WhirCommitmentInTranscript},
    },
};
use ff_ext::{ExtensionField, PoseidonField};
use itertools::zip_eq;
use multilinear_extensions::{mle::MultilinearExtension, virtual_poly::eq_eval};
use p3::{commit::Mmcs, util::log2_strict_usize};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;

impl<E: ExtensionField> Verifier<E>
where
    DigestExt<E>: IntoIterator<Item = E::BaseField> + PartialEq,
    MerklePathExt<E>: Send + Sync,
    MerkleTreeExt<E>: Send + Sync,
{
    // Same multiple points on each polynomial
    pub fn simple_batch_verify<T: Transcript<E>>(
        &self,
        commitment: &WhirCommitmentInTranscript<E>,
        transcript: &mut T,
        num_polys: usize,
        points: &[Vec<E>],
        evals_per_point: &[Vec<E>],
        whir_proof: &WhirProof<E>,
    ) -> Result<(), Error>
    where
        MerklePathExt<E>: Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
            Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
    Send + Sync,{
        let timer = entered_span!("Simple batch verify");

        for evals in evals_per_point {
            assert_eq!(num_polys, evals.len());
        }
        let parsed_commitment = commitment;
        let mut sumcheck_poly_evals_iter =
            whir_proof.sumcheck_poly_evals.iter().map(|x| x.to_vec());

        // It is possible that the committing and the opening of the polynomial
        // is separated in the protocol. So it doesn't make sense to write
        // commitment to transcript preceding the verification.
        // self.write_commitment_to_transcript(&mut parsed_commitment, transcript);

        let internal_timer = entered_span!("Internal batch verify");
        let result = self.batch_verify_internal(
            transcript,
            num_polys,
            points,
            evals_per_point,
            parsed_commitment,
            whir_proof,
            &mut sumcheck_poly_evals_iter,
        );
        exit_span!(internal_timer);

        exit_span!(timer);

        result
    }

    // Different points on each polynomial
    pub fn same_size_batch_verify<T: Transcript<E>>(
        &self,
        commitment: &WhirCommitmentInTranscript<E>,
        transcript: &mut T,
        num_polys: usize,
        point_per_poly: &[Vec<E>],
    eval_per_poly: &[E], // evaluations of the polys on individual points
        whir_proof: &WhirProof<E>,
    ) -> Result<(), Error>
    where
        MerklePathExt<E>: Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
            Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
    Send + Sync,{
        assert_eq!(num_polys, point_per_poly.len());
        assert_eq!(num_polys, eval_per_poly.len());

        let timer = entered_span!("Same size batch verify");

        let mut sumcheck_poly_evals_iter =
            whir_proof.sumcheck_poly_evals.iter().map(|x| x.to_vec());

        // It is possible that the committing and the opening of the polynomial
        // is separated in the protocol. So it doesn't make sense to write
        // commitment to transcript preceding the verification.
        let parsed_commitment = commitment;
        // self.write_commitment_to_transcript(&mut parsed_commitment, transcript);

        // parse proof
        let poly_comb_randomness =
            super::utils::generate_random_vector_batch_verify(transcript, num_polys)?;
        let (folded_points, folded_evals) = self.parse_unify_sumcheck(
            transcript,
            point_per_poly,
            poly_comb_randomness,
            whir_proof,
            &mut sumcheck_poly_evals_iter,
        )?;

        let internal_timer = entered_span!("Internal batch verify");
        let result = self.batch_verify_internal(
            transcript,
            num_polys,
            &[folded_points],
            &[folded_evals.clone()],
            parsed_commitment,
            whir_proof,
            &mut sumcheck_poly_evals_iter,
        );
        exit_span!(internal_timer);

        exit_span!(timer);

        result
    }

    #[allow(clippy::too_many_arguments)]
    fn batch_verify_internal<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        num_polys: usize,
        points: &[Vec<E>],
        evals_per_point: &[Vec<E>],
        parsed_commitment: &WhirCommitmentInTranscript<E>,
        whir_proof: &WhirProof<E>,
        sumcheck_poly_evals_iter: &mut impl Iterator<Item = Vec<E>>,
    ) -> Result<(), Error>
    where
        MerklePathExt<E>: Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
            Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
    Send + Sync,{
        // parse proof
        let compute_dot_product =
            |evals: &[E], coeff: &[E]| -> E { zip_eq(evals, coeff).map(|(a, b)| *a * *b).sum() };

        let internal_timer = entered_span!("Generate random coeff");
        let random_coeff =
            super::utils::generate_random_vector_batch_verify(transcript, num_polys)?;
        exit_span!(internal_timer);

        let internal_timer = entered_span!("Prepare initial claims");
        let initial_claims: Vec<_> = parsed_commitment
            .ood_points
            .clone()
            .into_iter()
            .map(|ood_point| {
                expand_from_univariate(ood_point, self.params.mv_parameters.num_variables)
            })
            .chain(points.to_vec())
            .collect();

        let eval_per_point = evals_per_point
            .iter()
            .map(|evals| compute_dot_product(evals, &random_coeff));
        let initial_answers = parsed_commitment
            .ood_answers
            .clone()
            .chunks_exact(num_polys)
            .map(|answer| compute_dot_product(answer, &random_coeff))
            .chain(eval_per_point)
            .collect();

        exit_span!(internal_timer);

        let internal_timer = entered_span!("Write proof to transcript batch");
        let statement = Statement {
            points: initial_claims,
            evaluations: initial_answers,
        };
        let parsed = self.write_proof_to_transcript_batch(
            transcript,
            parsed_commitment,
            &statement,
            whir_proof,
            random_coeff.clone(),
            num_polys,
            sumcheck_poly_evals_iter,
        )?;
        exit_span!(internal_timer);

        let internal_timer = entered_span!("Compute folds");
        let computed_folds = self.compute_folds(&parsed);
        exit_span!(internal_timer);

        let internal_timer = entered_span!("First round");
        let mut prev: Option<(SumcheckPolynomial<E>, E)> = None;
        if let Some(round) = parsed.initial_sumcheck_rounds.first() {
            // Check the first polynomial
            let (mut prev_poly, mut randomness) = round.clone();
            if prev_poly.sum_over_hypercube()
                != statement
                    .evaluations
                    .clone()
                    .into_iter()
                    .zip(&parsed.initial_combination_randomness)
                    .map(|(ans, rand)| ans * *rand)
                    .sum()
            {
                return Err(Error::InvalidProof(
                    "Initial sumcheck poly sum mismatched with statement rlc".to_string(),
                ));
            }

            // Check the rest of the rounds
            for (sumcheck_poly, new_randomness) in &parsed.initial_sumcheck_rounds[1..] {
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof(
                        "Initial sumcheck poly sum mismatched with prev poly eval".to_string(),
                    ));
                }
                prev_poly = sumcheck_poly.clone();
                randomness = *new_randomness;
            }

            prev = Some((prev_poly, randomness));
        }
        exit_span!(internal_timer);

        let internal_timer = entered_span!("Intermediate rounds");
        for (r, (round, folds)) in parsed.rounds.iter().zip(&computed_folds).enumerate() {
            let (sumcheck_poly, new_randomness) = &round.sumcheck_rounds[0].clone();

            let values = round.ood_answers.iter().copied().chain(folds.clone());

            let prev_eval = if let Some((prev_poly, randomness)) = prev {
                prev_poly.evaluate_at_point(&[randomness])
            } else {
                E::ZERO
            };
            let claimed_sum = prev_eval
                + values
                    .zip(&round.combination_randomness)
                    .map(|(val, rand)| val * *rand)
                    .sum::<E>();

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(Error::InvalidProof(format!(
                    "Initial sumcheck poly sum mismatched with claimed sum in round {}",
                    r
                )));
            }

            prev = Some((sumcheck_poly.clone(), *new_randomness));

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &round.sumcheck_rounds[1..] {
                let (prev_poly, randomness) = prev.unwrap();
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof(format!(
                        "Sumcheck poly sum mismatched with prev poly eval in round {}",
                        r
                    )));
                }
                prev = Some((sumcheck_poly.clone(), *new_randomness));
            }
        }
        exit_span!(internal_timer);

        // Check the foldings computed from the proof match the evaluations of the polynomial
        let internal_timer = entered_span!("Final evaluation");
        let final_folds = &computed_folds[computed_folds.len() - 1];
        let final_evaluations =
            evaluate_as_univariate(&parsed.final_evaluations, &parsed.final_randomness_points);

        for (index, (&fold, eval)) in final_folds.iter().zip(final_evaluations).enumerate() {
            if fold != eval {
                return Err(Error::InvalidProof(format!(
                    "Simple batched verifier: Final foldings mismatch with final evaluations: at {}, {} != {}",
                    index, fold, eval
                )));
            }
        }

        // Check the final sumchecks
        if self.params.final_sumcheck_rounds > 0 {
            let prev_sumcheck_poly_eval = if let Some((prev_poly, randomness)) = prev {
                prev_poly.evaluate_at_point(&[randomness])
            } else {
                E::ZERO
            };
            let (sumcheck_poly, new_randomness) = &parsed.final_sumcheck_rounds[0].clone();
            let claimed_sum = prev_sumcheck_poly_eval;

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(Error::InvalidProof(
                    "Final sumcheck poly sum mismatched with claimed sum".to_string(),
                ));
            }

            prev = Some((sumcheck_poly.clone(), *new_randomness));

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &parsed.final_sumcheck_rounds[1..] {
                let (prev_poly, randomness) = prev.unwrap();
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof(
                        "Final sumcheck poly sum mismatched with prev poly eval".to_string(),
                    ));
                }
                prev = Some((sumcheck_poly.clone(), *new_randomness));
            }
        }

        let prev_sumcheck_poly_eval = if let Some((prev_poly, randomness)) = prev {
            prev_poly.evaluate_at_point(&[randomness])
        } else {
            E::ZERO
        };
        exit_span!(internal_timer);

        // Check the final sumcheck evaluation
        let internal_timer = entered_span!("Compute v poly for batched");
        let evaluation_of_v_poly = self.compute_v_poly_for_batched(&statement, &parsed);
        exit_span!(internal_timer);

        let internal_timer = entered_span!("Final check");
        if prev_sumcheck_poly_eval
            != evaluation_of_v_poly
                * MultilinearExtension::from_evaluations_ext_vec(
                    p3::util::log2_strict_usize(parsed.final_evaluations.len()),
                    parsed.final_evaluations,
                )
                .evaluate(&parsed.final_sumcheck_randomness)
        {
            return Err(Error::InvalidProof(
                "Final sumcheck evaluation mismatched".to_string(),
            ));
        }
        exit_span!(internal_timer);

        Ok(())
    }

    fn parse_unify_sumcheck<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        point_per_poly: &[Vec<E>],
        poly_comb_randomness: Vec<E>,
        whir_proof: &WhirProof<E>,
        sumcheck_poly_evals_iter: &mut impl Iterator<Item = Vec<E>>,
    ) -> Result<(Vec<E>, Vec<E>), Error> {
        let num_variables = self.params.mv_parameters.num_variables;
        let mut sumcheck_rounds = Vec::new();

        // Derive combination randomness and first sumcheck polynomial
        // let [point_comb_randomness_gen]: [E; 1] = transcript.sample_and_append_challenge().elements;
        // let point_comb_randomness = expand_randomness(point_comb_randomness_gen, num_points);

        // Unifying sumcheck
        sumcheck_rounds.reserve_exact(num_variables);
        for _ in 0..num_variables {
            let sumcheck_poly_evals: Vec<E> = sumcheck_poly_evals_iter
                .next()
                .ok_or(Error::InvalidProof(
                    "Insufficient number of sumcheck polynomial evaluations in unify sumcheck"
                        .to_string(),
                ))?
                .clone();
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            transcript.append_field_element_exts(sumcheck_poly.evaluations());
            let folding_randomness_single = transcript
                .sample_and_append_challenge(b"folding_randomness")
                .elements;
            sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));
        }
        let folded_point: Vec<E> = sumcheck_rounds.iter().map(|&(_, r)| r).collect();
        let folded_eqs: Vec<E> = point_per_poly
            .iter()
            .zip(&poly_comb_randomness)
            .map(|(point, randomness)| *randomness * eq_eval(point, &folded_point))
            .collect();
        let folded_evals = whir_proof.folded_evals.clone();
        transcript.append_field_element_exts(&folded_evals);
        let sumcheck_claim = sumcheck_rounds[num_variables - 1]
            .0
            .evaluate_at_point(&[sumcheck_rounds[num_variables - 1].1]);
        let sumcheck_expected: E = folded_evals
            .iter()
            .zip(&folded_eqs)
            .map(|(eval, eq)| *eval * *eq)
            .sum();
        if sumcheck_claim != sumcheck_expected {
            return Err(Error::InvalidProof(format!(
                "Sumcheck mismatch with claimed in parse unify sumcheck: {} != {}",
                sumcheck_claim, sumcheck_expected
            )));
        }

        Ok((folded_point, folded_evals))
    }

    fn pow_with_precomputed_squares(squares: &[E], mut index: usize) -> E {
        let mut result = E::ONE;
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

    #[allow(clippy::too_many_arguments)]
    fn write_proof_to_transcript_batch<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        parsed_commitment: &WhirCommitmentInTranscript<E>,
    statement: &Statement<E>, // Will be needed later
        whir_proof: &WhirProof<E>,
        batched_randomness: Vec<E>,
        num_polys: usize,
        sumcheck_poly_evals_iter: &mut impl Iterator<Item = Vec<E>>,
    ) -> Result<ParsedProof<E>, Error>
    where
        MerklePathExt<E>: Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
            Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
    Send + Sync,{
        let internal_timer = entered_span!("Preamble");

        let mut initial_sumcheck_rounds = Vec::new();
        let mut folding_randomness: Vec<E>;

        assert!(self.params.initial_statement, "must be true for pcs");
        // Derive combination randomness and first sumcheck polynomial
        let combination_randomness_gen = transcript
            .sample_and_append_challenge(b"combination_randomness")
            .elements;
        let initial_combination_randomness = expand_randomness(
            combination_randomness_gen,
            parsed_commitment.ood_points.len() + statement.points.len(),
        );

        // Initial sumcheck
        initial_sumcheck_rounds.reserve_exact(self.params.folding_factor.at_round(0));
        for _ in 0..self.params.folding_factor.at_round(0) {
            let sumcheck_poly_evals: Vec<E> = sumcheck_poly_evals_iter
                .next()
                .ok_or(Error::InvalidProof(
                    "Insufficient number of sumcheck polynomial evaluations".to_string(),
                ))?
                .clone();
            transcript.append_field_element_exts(&sumcheck_poly_evals);
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let folding_randomness_single = transcript
                .sample_and_append_challenge(b"folding_randomness")
                .elements;
            initial_sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));
        }

        folding_randomness = initial_sumcheck_rounds.iter().map(|&(_, r)| r).collect();

        let mut prev_root = parsed_commitment.root.clone();
        let domain_gen = self.params.starting_domain.backing_domain_group_gen();
        // Precompute the powers of the domain generator, so that
        // we can always compute domain_gen.pow(1 << i) by domain_gen_powers[i]
        let domain_gen_powers = std::iter::successors(Some(domain_gen), |&curr| Some(curr * curr))
            .take(log2_strict_usize(self.params.starting_domain.size()))
            .collect::<Vec<_>>();
        // Since the generator of the domain will be repeatedly squared in
        // the future, keep track of the log of the power (i.e., how many times
        // it has been squared from domain_gen).
        // In another word, always ensure current domain generator = domain_gen_powers[log_based_on_domain_gen]
        let mut log_based_on_domain_gen: usize = 0;
        let mut domain_gen_inv = self
            .params
            .starting_domain
            .backing_domain_group_gen()
            .inverse();
        let mut domain_size = self.params.starting_domain.size();
        let mut rounds = vec![];
        exit_span!(internal_timer);

        let internal_timer = entered_span!("Rounds");
        for r in 0..self.params.n_rounds() {
            let merkle_proof_with_answers = &whir_proof.merkle_answers[r];
            let round_params = &self.params.round_parameters[r];

            let new_root = whir_proof.merkle_roots[r].clone();

            write_digest_to_transcript(&new_root, transcript);

            let (ood_points, ood_answers) = if round_params.ood_samples > 0 {
                let ood_points =
                    transcript.sample_and_append_vec(b"ood_points", round_params.ood_samples);
                let ood_answers = whir_proof.ood_answers[r].clone();
                transcript.append_field_element_exts(&ood_answers);
                (ood_points, ood_answers)
            } else {
                (
                    vec![E::ZERO; round_params.ood_samples],
                    vec![E::ZERO; round_params.ood_samples],
                )
            };

            let stir_challenges_indexes = get_challenge_stir_queries(
                domain_size,
                self.params.folding_factor.at_round(r),
                round_params.num_queries,
                transcript,
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

            let fold_size = 1 << self.params.folding_factor.at_round(r);
            let internal_timer = entered_span!("Merkle proof verification");
            verify_multi_proof(
                &self.params.hash_params,
                &prev_root,
                &stir_challenges_indexes,
                merkle_proof_with_answers,
                p3::util::log2_strict_usize(domain_size / fold_size),
            )
            .map_err(|e| Error::InvalidProof(format!("Merkle proof failed: {:?}", e)))?;
            exit_span!(internal_timer);

            let answers: Vec<_> = if r == 0 {
                merkle_proof_with_answers
                    .answers_ext()
                    .par_iter()
                    .map(|raw_answer| {
                        if !batched_randomness.is_empty() {
                            let fold_size = 1 << self.params.folding_factor.at_round(r);
                            let mut res = vec![E::ZERO; fold_size];
                            for (i, s) in res.iter_mut().enumerate().take(fold_size) {
                                for (j, r) in batched_randomness.iter().enumerate().take(num_polys)
                                {
                                    *s += raw_answer[0][i * num_polys + j] * *r;
                                }
                            }
                            res
                        } else {
                            raw_answer[0].clone()
                        }
                    })
                    .collect()
            } else {
                merkle_proof_with_answers
                    .answers_ext()
                    .par_iter()
                    .map(|raw_answer| raw_answer[0].clone())
                    .collect()
            };

            let combination_randomness_gen = transcript
                .sample_and_append_challenge(b"combination_randomness")
                .elements;
            let combination_randomness = expand_randomness(
                combination_randomness_gen,
                stir_challenges_indexes.len() + round_params.ood_samples,
            );

            let mut sumcheck_rounds =
                Vec::with_capacity(self.params.folding_factor.at_round(r + 1));
            for _ in 0..self.params.folding_factor.at_round(r + 1) {
                let sumcheck_poly_evals: Vec<E> = sumcheck_poly_evals_iter
                    .next()
                    .ok_or(Error::InvalidProof(
                        "Insufficient number of sumcheck polynomial evaluations".to_string(),
                    ))?
                    .clone();
                let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
                transcript.append_field_element_exts(sumcheck_poly.evaluations());
                let folding_randomness_single = transcript
                    .sample_and_append_challenge(b"folding_randomness")
                    .elements;
                sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));
            }

            let new_folding_randomness = sumcheck_rounds.iter().map(|&(_, r)| r).collect();

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
        exit_span!(internal_timer);

        let internal_timer = entered_span!("Final");
        let final_evaluations = whir_proof.final_poly.clone();
        transcript.append_field_element_exts(&final_evaluations);

        // Final queries verify
        let final_randomness_indexes = get_challenge_stir_queries(
            domain_size,
            self.params.folding_factor.at_round(self.params.n_rounds()),
            self.params.final_queries,
            transcript,
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

        let final_merkle_proof = &whir_proof.merkle_answers[whir_proof.merkle_answers.len() - 1];

        let fold_size = 1 << self.params.folding_factor.at_round(self.params.n_rounds());
        verify_multi_proof(
            &self.params.hash_params,
            &prev_root,
            &final_randomness_indexes,
            final_merkle_proof,
            p3::util::log2_strict_usize(domain_size / fold_size),
        )
        .map_err(|e| Error::InvalidProof(format!("Final Merkle proof failed: {:?}", e)))?;

        let final_randomness_answers: Vec<_> = if self.params.n_rounds() == 0 {
            final_merkle_proof
                .answers_ext()
                .par_iter()
                .map(|raw_answer| {
                    if !batched_randomness.is_empty() {
                        let fold_size = 1 << self.params.folding_factor.at_round(0);
                        let mut res = vec![E::ZERO; fold_size];
                        for (i, s) in res.iter_mut().enumerate().take(fold_size) {
                            for (j, r) in batched_randomness.iter().enumerate().take(num_polys) {
                                *s += raw_answer[0][i * num_polys + j] * *r;
                            }
                        }
                        res
                    } else {
                        raw_answer[0].clone()
                    }
                })
                .collect()
        } else {
            final_merkle_proof
                .answers_ext()
                .par_iter()
                .map(|raw_answer| raw_answer[0].clone())
                .collect()
        };

        let mut final_sumcheck_rounds = Vec::with_capacity(self.params.final_sumcheck_rounds);
        for _ in 0..self.params.final_sumcheck_rounds {
            let sumcheck_poly_evals: Vec<E> = sumcheck_poly_evals_iter
                .next()
                .ok_or(Error::InvalidProof(
                    "Insufficient number of sumcheck polynomial evaluation for final rounds"
                        .to_string(),
                ))?
                .clone();
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            transcript.append_field_element_exts(sumcheck_poly.evaluations());
            let folding_randomness_single = transcript
                .sample_and_append_challenge(b"folding_randomness")
                .elements;
            final_sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));
        }
        let final_sumcheck_randomness = final_sumcheck_rounds.iter().map(|&(_, r)| r).collect();
        exit_span!(internal_timer);

        Ok(ParsedProof {
            initial_combination_randomness,
            initial_sumcheck_rounds,
            rounds,
            final_domain_gen_inv: domain_gen_inv,
            final_folding_randomness: folding_randomness,
            final_randomness_indexes,
            final_randomness_points,
            final_randomness_answers,
            final_sumcheck_rounds,
            final_sumcheck_randomness,
            final_evaluations,
        })
    }

    /// this is copied and modified from `fn compute_v_poly`
    /// to avoid modify the original function for compatibility
    fn compute_v_poly_for_batched(&self, statement: &Statement<E>, proof: &ParsedProof<E>) -> E {
        let mut num_variables = self.params.mv_parameters.num_variables;

        let mut folding_randomness = proof
            .rounds
            .iter()
            .map(|r| &r.folding_randomness)
            .chain(iter::once(&proof.final_folding_randomness))
            .chain(iter::once(&proof.final_sumcheck_randomness))
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        let mut value = statement
            .points
            .iter()
            .zip(&proof.initial_combination_randomness)
            .map(|(point, randomness)| *randomness * eq_eval(point, &folding_randomness))
            .sum();

        for (round, round_proof) in proof.rounds.iter().enumerate() {
            num_variables -= self.params.folding_factor.at_round(round);
            folding_randomness =
                folding_randomness[self.params.folding_factor.at_round(round)..].to_vec();

            let ood_points = &round_proof.ood_points;
            let stir_challenges_points = &round_proof.stir_challenges_points;
            let sum_of_claims: E = ood_points
                .iter()
                .chain(stir_challenges_points)
                .cloned()
                .map(|univariate| {
                    expand_from_univariate(univariate, num_variables)
                    // TODO:
                    // Maybe refactor outside
                })
                .map(|point| eq_eval(&point, &folding_randomness))
                .zip(&round_proof.combination_randomness)
                .map(|(point, rand)| point * *rand)
                .sum();

            value += sum_of_claims;
        }

        value
    }
}
