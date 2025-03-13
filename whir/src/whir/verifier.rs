use std::iter;

use crate::crypto::{Digest, verify_multi_proof};
use ff_ext::{ExtensionField, PoseidonField};
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::eq_eval,
};
use p3_field::{Field, PrimeCharacteristicRing};
use transcript::Transcript;

use super::{Statement, WhirProof, fold::expand_from_univariate, parameters::WhirConfig};
use crate::{
    error::Error,
    parameters::FoldType,
    sumcheck::proof::SumcheckPolynomial,
    utils::expand_randomness,
    whir::{fold::compute_fold, fs_utils::get_challenge_stir_queries},
};

pub struct Verifier<E: ExtensionField> {
    pub(crate) params: WhirConfig<E>,
    pub(crate) two_inv: E::BaseField,
}

#[derive(Clone)]
pub(crate) struct WhirCommitmentInTranscript<E: ExtensionField> {
    pub(crate) root: Digest<E>,
    pub(crate) ood_points: Vec<E>,
    pub(crate) ood_answers: Vec<E>,
}

#[derive(Clone)]
pub(crate) struct ParsedProof<E: ExtensionField> {
    pub(crate) initial_combination_randomness: Vec<E>,
    pub(crate) initial_sumcheck_rounds: Vec<(SumcheckPolynomial<E>, E)>,
    pub(crate) rounds: Vec<ParsedRound<E>>,
    pub(crate) final_domain_gen_inv: E,
    pub(crate) final_randomness_indexes: Vec<usize>,
    pub(crate) final_randomness_points: Vec<E>,
    pub(crate) final_randomness_answers: Vec<Vec<E>>,
    pub(crate) final_folding_randomness: Vec<E>,
    pub(crate) final_sumcheck_rounds: Vec<(SumcheckPolynomial<E>, E)>,
    pub(crate) final_sumcheck_randomness: Vec<E>,
    pub(crate) final_coefficients: DenseMultilinearExtension<E>,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedRound<E> {
    pub(crate) folding_randomness: Vec<E>,
    pub(crate) ood_points: Vec<E>,
    pub(crate) ood_answers: Vec<E>,
    pub(crate) stir_challenges_indexes: Vec<usize>,
    pub(crate) stir_challenges_points: Vec<E>,
    pub(crate) stir_challenges_answers: Vec<Vec<E>>,
    pub(crate) combination_randomness: Vec<E>,
    pub(crate) sumcheck_rounds: Vec<(SumcheckPolynomial<E>, E)>,
    pub(crate) domain_gen_inv: E,
}

impl<E: ExtensionField> Verifier<E> {
    pub fn new(params: WhirConfig<E>) -> Self {
        Verifier {
            params,
            two_inv: E::BaseField::from_u64(2).inverse(), // The only inverse in the entire code :)
        }
    }

    fn write_commitment_to_transcript<T: Transcript<E>>(
        &self,
        commitment: &mut WhirCommitmentInTranscript<E>,
        transcript: &mut T,
    ) {
        if self.params.committment_ood_samples > 0 {
            commitment.ood_points = (0..self.params.committment_ood_samples)
                .map(|_| transcript.read_challenge().elements)
                .collect::<Vec<_>>();
            transcript.append_field_element_exts(&commitment.ood_answers);
        }
    }

    fn write_proof_to_transcript<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        parsed_commitment: &WhirCommitmentInTranscript<E>,
        statement: &Statement<E>, // Will be needed later
        whir_proof: &WhirProof<E>,
    ) -> Result<ParsedProof<E>, Error> {
        let mut sumcheck_rounds = Vec::new();
        let mut folding_randomness: Vec<E>;
        let initial_combination_randomness;
        let mut sumcheck_poly_evals_iter = whir_proof.sumcheck_poly_evals.iter();
        if self.params.initial_statement {
            // Derive combination randomness and first sumcheck polynomial
            let combination_randomness_gen = transcript.read_challenge().elements;
            initial_combination_randomness = expand_randomness(
                combination_randomness_gen,
                parsed_commitment.ood_points.len() + statement.points.len(),
            );

            // Initial sumcheck
            sumcheck_rounds.reserve_exact(self.params.folding_factor.at_round(0));
            for _ in 0..self.params.folding_factor.at_round(0) {
                let sumcheck_poly_evals: [E; 3] = sumcheck_poly_evals_iter
                    .next()
                    .ok_or(Error::InvalidProof(
                        "Insufficient number of sumcheck polynomial evaluations".to_string(),
                    ))?
                    .clone();
                transcript.append_field_element_exts(&sumcheck_poly_evals);
                let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
                let folding_randomness_single = transcript.read_challenge().elements;
                sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));
            }

            folding_randomness = sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect();
        } else {
            assert_eq!(parsed_commitment.ood_points.len(), 0);
            assert_eq!(statement.points.len(), 0);

            initial_combination_randomness = vec![E::ONE];

            folding_randomness = (0..self.params.folding_factor.at_round(0))
                .map(|_| transcript.read_challenge().elements)
                .collect();
        };

        let mut prev_root = parsed_commitment.root.clone();
        let mut domain_gen = self.params.starting_domain.backing_domain_group_gen();
        let mut exp_domain_gen = domain_gen.exp_power_of_2(self.params.folding_factor.at_round(0));
        let mut domain_gen_inv = self
            .params
            .starting_domain
            .backing_domain_group_gen()
            .inverse();
        let mut domain_size = self.params.starting_domain.size();
        let mut rounds = vec![];

        for r in 0..self.params.n_rounds() {
            let (merkle_proof_with_answers, answers) = &whir_proof.merkle_answers[r];
            let round_params = &self.params.round_parameters[r];

            let new_root = whir_proof.merkle_roots[r].clone();

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
                .map(|index| exp_domain_gen.exp_u64(*index as u64))
                .collect();

            if !verify_multi_proof(
                &self.params.hash_params,
                &prev_root,
                &stir_challenges_indexes,
                answers
                    .iter()
                    .map(|a| a.clone())
                    .collect::<Vec<Vec<E>>>()
                    .as_slice(),
                merkle_proof_with_answers,
                1,
                p3_util::log2_strict_usize(domain_size),
            )
            .is_ok()
            {
                return Err(Error::InvalidProof("Merkle proof failed".to_string()));
            }

            let combination_randomness_gen = transcript.read_challenge().elements;
            let combination_randomness = expand_randomness(
                combination_randomness_gen,
                stir_challenges_indexes.len() + round_params.ood_samples,
            );

            let mut sumcheck_rounds =
                Vec::with_capacity(self.params.folding_factor.at_round(r + 1));
            for _ in 0..self.params.folding_factor.at_round(r + 1) {
                let sumcheck_poly_evals: [E; 3] = sumcheck_poly_evals_iter
                    .next()
                    .ok_or(Error::InvalidProof(
                        "Insufficient number of sumcheck polynomial evaluations".to_string(),
                    ))?
                    .clone();
                let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
                let folding_randomness_single = transcript
                    .sample_and_append_challenge(b"folding_randomness")
                    .elements;
                sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));
            }

            let new_folding_randomness = sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect();

            rounds.push(ParsedRound {
                folding_randomness,
                ood_points,
                ood_answers,
                stir_challenges_indexes,
                stir_challenges_points,
                stir_challenges_answers: answers.to_vec(),
                combination_randomness,
                sumcheck_rounds,
                domain_gen_inv,
            });

            folding_randomness = new_folding_randomness;

            prev_root = new_root.clone();
            domain_gen = domain_gen * domain_gen;
            exp_domain_gen = domain_gen.exp_power_of_2(self.params.folding_factor.at_round(r + 1));
            domain_gen_inv = domain_gen_inv * domain_gen_inv;
            domain_size /= 2;
        }

        let final_coefficients = whir_proof.final_poly.clone();
        let final_coefficients = DenseMultilinearExtension::from_evaluations_ext_vec(
            self.params.final_sumcheck_rounds,
            final_coefficients,
        );

        // Final queries verify
        let final_randomness_indexes = get_challenge_stir_queries(
            domain_size,
            self.params.folding_factor.at_round(self.params.n_rounds()),
            self.params.final_queries,
            transcript,
        )?;
        let final_randomness_points = final_randomness_indexes
            .iter()
            .map(|index| exp_domain_gen.exp_u64(*index as u64))
            .collect();

        let (final_merkle_proof, final_randomness_answers) =
            &whir_proof.merkle_answers[whir_proof.merkle_answers.len() - 1];
        if !verify_multi_proof(
            &self.params.hash_params,
            &prev_root,
            &final_randomness_indexes,
            final_randomness_answers
                .iter()
                .map(|a| a.clone())
                .collect::<Vec<_>>()
                .as_slice(),
            final_merkle_proof,
            1,
            p3_util::log2_strict_usize(domain_size),
        )
        .is_ok()
        {
            return Err(Error::InvalidProof("Final Merkle proof failed".to_string()));
        }

        let mut final_sumcheck_rounds = Vec::with_capacity(self.params.final_sumcheck_rounds);
        for _ in 0..self.params.final_sumcheck_rounds {
            let sumcheck_poly_evals: [E; 3] = sumcheck_poly_evals_iter
                .next()
                .ok_or(Error::InvalidProof(
                    "Final sumcheck polynomial evaluations insufficient".to_string(),
                ))?
                .clone();
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let folding_randomness_single = transcript
                .sample_and_append_challenge(b"folding_randomness")
                .elements;
            final_sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));
        }
        let final_sumcheck_randomness = final_sumcheck_rounds
            .iter()
            .map(|&(_, r)| r)
            .rev()
            .collect();

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

    fn compute_v_poly(
        &self,
        parsed_commitment: &WhirCommitmentInTranscript<E>,
        statement: &Statement<E>,
        proof: &ParsedProof<E>,
    ) -> E {
        let mut num_variables = self.params.mv_parameters.num_variables;

        let mut folding_randomness = iter::once(&proof.final_sumcheck_randomness)
            .chain(iter::once(&proof.final_folding_randomness))
            .chain(proof.rounds.iter().rev().map(|r| &r.folding_randomness))
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        let statement_points: Vec<Vec<E>> = statement
            .points
            .clone()
            .into_iter()
            .map(|mut p| {
                while p.len() < (1 << self.params.folding_factor.at_round(0)) {
                    p.insert(0, E::ONE);
                }
                p
            })
            .collect();
        let mut value = parsed_commitment
            .ood_points
            .iter()
            .map(|ood_point| expand_from_univariate(*ood_point, num_variables))
            .chain(statement_points)
            .zip(&proof.initial_combination_randomness)
            .map(|(point, randomness)| *randomness * eq_eval(&point, &folding_randomness))
            .sum();

        for (round, round_proof) in proof.rounds.iter().enumerate() {
            num_variables -= self.params.folding_factor.at_round(round);
            folding_randomness = folding_randomness[..num_variables].to_vec();

            let ood_points = &round_proof.ood_points;
            let stir_challenges_points = &round_proof.stir_challenges_points;
            let stir_challenges: Vec<_> = ood_points
                .iter()
                .chain(stir_challenges_points)
                .cloned()
                .map(|univariate| {
                    expand_from_univariate(univariate, num_variables)
                    // TODO:
                    // Maybe refactor outside
                })
                .collect();

            let sum_of_claims: E = stir_challenges
                .into_iter()
                .map(|point| eq_eval(&point, &folding_randomness))
                .zip(&round_proof.combination_randomness)
                .map(|(point, rand)| point * *rand)
                .sum();

            value += sum_of_claims;
        }

        value
    }

    pub(crate) fn compute_folds(&self, parsed: &ParsedProof<E>) -> Vec<Vec<E>> {
        match self.params.fold_optimisation {
            FoldType::Naive => self.compute_folds_full(parsed),
            FoldType::ProverHelps => self.compute_folds_helped(parsed),
        }
    }

    fn compute_folds_full(&self, parsed: &ParsedProof<E>) -> Vec<Vec<E>> {
        let mut domain_size = self.params.starting_domain.size();

        let mut result = Vec::new();

        for (round_index, round) in parsed.rounds.iter().enumerate() {
            let coset_domain_size = 1 << self.params.folding_factor.at_round(round_index);
            // This is such that coset_generator^coset_domain_size = E::ONE
            // let _coset_generator = domain_gen.pow(&[(domain_size / coset_domain_size) as u64]);
            let coset_generator_inv = round
                .domain_gen_inv
                .exp_u64((domain_size / coset_domain_size) as u64);

            let evaluations: Vec<_> = round
                .stir_challenges_indexes
                .iter()
                .zip(&round.stir_challenges_answers)
                .map(|(index, answers)| {
                    // The coset is w^index * <w_coset_generator>
                    // let _coset_offset = domain_gen.pow(&[*index as u64]);
                    let coset_offset_inv = round.domain_gen_inv.exp_u64(*index as u64);

                    compute_fold(
                        answers,
                        &round.folding_randomness,
                        coset_offset_inv,
                        coset_generator_inv,
                        E::from_bases(&[self.two_inv]),
                        self.params.folding_factor.at_round(round_index),
                    )
                })
                .collect();
            result.push(evaluations);
            domain_size /= 2;
        }

        let coset_domain_size = 1 << self.params.folding_factor.at_round(parsed.rounds.len());
        let domain_gen_inv = parsed.final_domain_gen_inv;

        // Final round
        let coset_generator_inv = domain_gen_inv.exp_u64((domain_size / coset_domain_size) as u64);
        let evaluations: Vec<_> = parsed
            .final_randomness_indexes
            .iter()
            .zip(&parsed.final_randomness_answers)
            .map(|(index, answers)| {
                // The coset is w^index * <w_coset_generator>
                // let _coset_offset = domain_gen.pow(&[*index as u64]);
                let coset_offset_inv = domain_gen_inv.exp_u64(*index as u64);

                compute_fold(
                    answers,
                    &parsed.final_folding_randomness,
                    coset_offset_inv,
                    coset_generator_inv,
                    E::from_bases(&[self.two_inv]),
                    self.params.folding_factor.at_round(parsed.rounds.len()),
                )
            })
            .collect();
        result.push(evaluations);

        result
    }

    fn compute_folds_helped(&self, parsed: &ParsedProof<E>) -> Vec<Vec<E>> {
        let mut result = Vec::new();

        for round in &parsed.rounds {
            let evaluations: Vec<_> = round
                .stir_challenges_answers
                .iter()
                .map(|answers| {
                    DenseMultilinearExtension::from_evaluations_ext_vec(
                        p3_util::log2_strict_usize(answers.len()),
                        answers.to_vec(),
                    )
                    .evaluate(&round.folding_randomness)
                })
                .collect();
            result.push(evaluations);
        }

        // Final round
        let evaluations: Vec<_> = parsed
            .final_randomness_answers
            .iter()
            .map(|answers| {
                DenseMultilinearExtension::from_evaluations_ext_vec(
                    p3_util::log2_strict_usize(answers.len()),
                    answers.to_vec(),
                )
                .evaluate(&parsed.final_folding_randomness)
            })
            .collect();
        result.push(evaluations);

        result
    }

    pub fn verify<T: Transcript<E>>(
        &self,
        commitment: &WhirCommitmentInTranscript<E>,
        transcript: &mut T,
        statement: &Statement<E>,
        whir_proof: &WhirProof<E>,
    ) -> Result<(), Error> {
        let mut parsed_commitment = commitment.clone();
        self.write_commitment_to_transcript(&mut parsed_commitment, transcript);
        let parsed =
            self.write_proof_to_transcript(transcript, &parsed_commitment, statement, whir_proof)?;

        let computed_folds = self.compute_folds(&parsed);

        let mut prev: Option<(SumcheckPolynomial<E>, E)> = None;
        if let Some(round) = parsed.initial_sumcheck_rounds.first() {
            // Check the first polynomial
            let (mut prev_poly, mut randomness) = round.clone();
            if prev_poly.sum_over_hypercube()
                != parsed_commitment
                    .ood_answers
                    .iter()
                    .copied()
                    .chain(statement.evaluations.clone())
                    .zip(&parsed.initial_combination_randomness)
                    .map(|(ans, rand)| ans * *rand)
                    .sum()
            {
                return Err(Error::InvalidProof("Initial sumcheck failed".to_string()));
            }

            // Check the rest of the rounds
            for (sumcheck_poly, new_randomness) in &parsed.initial_sumcheck_rounds[1..] {
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof("Invalid initial sumcheck".to_string()));
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
                return Err(Error::InvalidProof(
                    "Sumcheck poly sum over hypercube mismatch with claimed sum".to_string(),
                ));
            }

            prev = Some((sumcheck_poly.clone(), *new_randomness));

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &round.sumcheck_rounds[1..] {
                let (prev_poly, randomness) = prev.unwrap();
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof(
                        "Sumcheck poly sum over hypercube mismatch with prev poly eval at point"
                            .to_string(),
                    ));
                }
                prev = Some((sumcheck_poly.clone(), *new_randomness));
            }
        }

        // Check the foldings computed from the proof match the evaluations of the polynomial
        let final_folds = &computed_folds[computed_folds.len() - 1];
        let final_evaluations = parsed
            .final_coefficients
            .evaluate_as_univariate(&parsed.final_randomness_points);
        if !final_folds
            .iter()
            .zip(final_evaluations)
            .all(|(&fold, eval)| fold == eval)
        {
            return Err(Error::InvalidProof(
                "Final foldings mismatch with final evaluations".to_string(),
            ));
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
                    "Final sumcheck poly sum over hypercube mismatch with claimed sum".to_string(),
                ));
            }

            prev = Some((sumcheck_poly.clone(), *new_randomness));

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &parsed.final_sumcheck_rounds[1..] {
                let (prev_poly, randomness) = prev.unwrap();
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof(
                        "Final sumcheck poly sum over hypercube mismatch with prev poly eval at point".to_string(),
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

        // Check the final sumcheck evaluation
        let evaluation_of_v_poly = self.compute_v_poly(&parsed_commitment, statement, &parsed);

        if prev_sumcheck_poly_eval
            != evaluation_of_v_poly
                * parsed
                    .final_coefficients
                    .evaluate(&parsed.final_sumcheck_randomness)
        {
            return Err(Error::InvalidProof(
                "Final sumcheck evaluation mismatch".to_string(),
            ));
        }

        Ok(())
    }
}
