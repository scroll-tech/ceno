use crate::{
    crypto::{Digest, DigestExt, MerklePathExt, verify_multi_proof, write_digest_to_transcript},
    utils::{evaluate_as_multilinear_coeffs, evaluate_as_univariate},
};
use ff_ext::{ExtensionField, PoseidonField};
use multilinear_extensions::{mle::MultilinearExtension, virtual_poly::eq_eval};
use p3::{
    commit::Mmcs,
    field::{Field, FieldAlgebra},
};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::iter;
use sumcheck::macros::{entered_span, exit_span};
use transcript::{BasicTranscript, Transcript};

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

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct WhirCommitmentInTranscript<E: ExtensionField> {
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
    pub(crate) final_evaluations: Vec<E>,
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

impl<E: ExtensionField> Verifier<E>
where
    DigestExt<E>: IntoIterator<Item = E::BaseField> + PartialEq,
{
    pub fn new(params: WhirConfig<E>) -> Self {
        Verifier {
            params,
            two_inv: E::BaseField::from_canonical_u64(2).inverse(), /* The only inverse in the entire code :) */
        }
    }

    pub fn write_commitment_to_transcript<T: Transcript<E>>(
        &self,
        commitment: &WhirCommitmentInTranscript<E>,
        transcript: &mut T,
    ) {
        write_digest_to_transcript(&commitment.root, transcript);

        // Now check the ood points and ood answers, because they
        // are sampled using a separate transcript.
        let mut local_transcript = BasicTranscript::<E>::new(b"commitment");
        write_digest_to_transcript(&commitment.root, &mut local_transcript);
        if self.params.committment_ood_samples > 0 {
            assert_eq!(
                commitment.ood_points,
                local_transcript
                    .sample_and_append_vec(b"ood_points", self.params.committment_ood_samples)
            );
            local_transcript.append_field_element_exts(&commitment.ood_answers);
        }
    }

    fn write_proof_to_transcript<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        parsed_commitment: &WhirCommitmentInTranscript<E>,
    statement: &Statement<E>, // Will be needed later
        whir_proof: &WhirProof<E>,
    ) -> Result<ParsedProof<E>, Error>
    where
        MerklePathExt<E>: Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
            Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
    Send + Sync,{
        let mut initial_sumcheck_rounds = Vec::new();
        let mut folding_randomness: Vec<E>;
        let initial_combination_randomness;
        let mut sumcheck_poly_evals_iter = whir_proof.sumcheck_poly_evals.iter();
        if self.params.initial_statement {
            // Derive combination randomness and first sumcheck polynomial
            let combination_randomness_gen = transcript
                .sample_and_append_challenge(b"combination_randomness")
                .elements;
            initial_combination_randomness = expand_randomness(
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
        } else {
            assert_eq!(parsed_commitment.ood_points.len(), 0);
            assert_eq!(statement.points.len(), 0);

            initial_combination_randomness = vec![E::ONE];

            folding_randomness = (0..self.params.folding_factor.at_round(0))
                .map(|_| {
                    transcript
                        .sample_and_append_challenge(b"folding_randomness")
                        .elements
                })
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

        let rounds_timer = entered_span!("Rounds");
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

            let internal_timer = entered_span!("Compute sitr challenge points");
            let stir_challenges_points = stir_challenges_indexes
                .iter()
                .map(|index| exp_domain_gen.exp_u64(*index as u64))
                .collect();
            exit_span!(internal_timer);

            let internal_timer = entered_span!("Verify multi proof");
            let fold_size = 1 << self.params.folding_factor.at_round(r);
            if verify_multi_proof(
                &self.params.hash_params,
                &prev_root,
                &stir_challenges_indexes,
                merkle_proof_with_answers,
                p3::util::log2_strict_usize(domain_size / fold_size),
            )
            .is_err()
            {
                return Err(Error::InvalidProof("Merkle proof failed".to_string()));
            }
            exit_span!(internal_timer);

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
                stir_challenges_answers: merkle_proof_with_answers
                    .answers_ext()
                    .iter()
                    .map(|answers| answers[0].clone())
                    .collect(),
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
        exit_span!(rounds_timer);

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
            .map(|index| exp_domain_gen.exp_u64(*index as u64))
            .collect();

        let final_merkle_proof = &whir_proof.merkle_answers[whir_proof.merkle_answers.len() - 1];
        let internal_timer = entered_span!("Final merkle proof verify");
        let fold_size = 1 << self.params.folding_factor.at_round(self.params.n_rounds());
        verify_multi_proof(
            &self.params.hash_params,
            &prev_root,
            &final_randomness_indexes,
            final_merkle_proof,
            p3::util::log2_strict_usize(domain_size / fold_size),
        )
        .map_err(|e| Error::InvalidProof(format!("Final Merkle proof failed: {:?}", e)))?;
        exit_span!(internal_timer);

        let mut final_sumcheck_rounds = Vec::with_capacity(self.params.final_sumcheck_rounds);
        for _ in 0..self.params.final_sumcheck_rounds {
            let sumcheck_poly_evals: Vec<E> = sumcheck_poly_evals_iter
                .next()
                .ok_or(Error::InvalidProof(
                    "Final sumcheck polynomial evaluations insufficient".to_string(),
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

        Ok(ParsedProof {
            initial_combination_randomness,
            initial_sumcheck_rounds,
            rounds,
            final_domain_gen_inv: domain_gen_inv,
            final_folding_randomness: folding_randomness,
            final_randomness_indexes,
            final_randomness_points,
            final_randomness_answers: final_merkle_proof
                .answers_ext()
                .iter()
                .map(|answers| answers[0].clone())
                .collect(),
            final_sumcheck_rounds,
            final_sumcheck_randomness,
            final_evaluations,
        })
    }

    fn compute_v_poly(
        &self,
        parsed_commitment: &WhirCommitmentInTranscript<E>,
        statement: &Statement<E>,
        proof: &ParsedProof<E>,
    ) -> E {
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

        let statement_points: Vec<Vec<E>> = statement
            .points
            .clone()
            .into_iter()
            .map(|mut p| {
                while p.len() < self.params.folding_factor.at_round(0) {
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
                        E::from_ref_base(&self.two_inv),
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
            .par_iter()
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
                    E::from_ref_base(&self.two_inv),
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
                .par_iter()
                .map(|answers| evaluate_as_multilinear_coeffs(answers, &round.folding_randomness))
                .collect();
            result.push(evaluations);
        }

        // Final round
        let evaluations: Vec<_> = parsed
            .final_randomness_answers
            .par_iter()
            .map(|answers| {
                evaluate_as_multilinear_coeffs(answers, &parsed.final_folding_randomness)
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
    ) -> Result<(), Error>
    where
        MerklePathExt<E>: Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
            Send + Sync,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
    Send + Sync,{
        let timer = entered_span!("Whir verify");

        let parsed_commitment = commitment;

        // It is possible that the committing and the opening of the polynomial
        // is separated in the protocol. So it doesn't make sense to write
        // commitment to transcript preceding the verification.
        // self.write_commitment_to_transcript(&mut parsed_commitment, transcript);

        let internal_timer = entered_span!("Write proof to transcript");
        let parsed =
            self.write_proof_to_transcript(transcript, parsed_commitment, statement, whir_proof)?;
        exit_span!(internal_timer);

        let internal_timer = entered_span!("Compute folds");
        let computed_folds = self.compute_folds(&parsed);
        exit_span!(internal_timer);

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
            for (index, (sumcheck_poly, new_randomness)) in
                parsed.initial_sumcheck_rounds[1..].iter().enumerate()
            {
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof(format!(
                        "Invalid initial sumcheck at round {}: {} != {}",
                        index + 1,
                        sumcheck_poly.sum_over_hypercube(),
                        prev_poly.evaluate_at_point(&[randomness])
                    )));
                }
                prev_poly = sumcheck_poly.clone();
                randomness = *new_randomness;
            }

            prev = Some((prev_poly, randomness));
        }

        for (round_index, (round, folds)) in parsed.rounds.iter().zip(&computed_folds).enumerate() {
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
                    "Sumcheck poly sum over hypercube mismatch with claimed sum in round {}: {} != {}",
                    round_index,
                    sumcheck_poly.sum_over_hypercube(),
                    claimed_sum
                )));
            }

            prev = Some((sumcheck_poly.clone(), *new_randomness));

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &round.sumcheck_rounds[1..] {
                let (prev_poly, randomness) = prev.unwrap();
                if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&[randomness])
                {
                    return Err(Error::InvalidProof(format!(
                        "Sumcheck poly sum over hypercube mismatch with prev poly eval at point at round {}: {} != {}",
                        round_index,
                        sumcheck_poly.sum_over_hypercube(),
                        prev_poly.evaluate_at_point(&[randomness])
                    )));
                }
                prev = Some((sumcheck_poly.clone(), *new_randomness));
            }
        }

        // Check the foldings computed from the proof match the evaluations of the polynomial
        let final_folds = &computed_folds[computed_folds.len() - 1];
        let final_evaluations =
            evaluate_as_univariate(&parsed.final_evaluations, &parsed.final_randomness_points);

        for (index, (&fold, eval)) in final_folds.iter().zip(final_evaluations).enumerate() {
            if fold != eval {
                return Err(Error::InvalidProof(format!(
                    "Final foldings mismatch with final evaluations: at {}, {} != {}",
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
        let evaluation_of_v_poly = self.compute_v_poly(parsed_commitment, statement, &parsed);

        let expected_sumcheck_poly_eval = evaluation_of_v_poly
            * MultilinearExtension::from_evaluations_ext_vec(
                p3::util::log2_strict_usize(parsed.final_evaluations.len()),
                parsed.final_evaluations,
            )
            .evaluate(&parsed.final_sumcheck_randomness);
        if prev_sumcheck_poly_eval != expected_sumcheck_poly_eval {
            return Err(Error::InvalidProof(format!(
                "Final sumcheck evaluation mismatch: {} != {}",
                prev_sumcheck_poly_eval, expected_sumcheck_poly_eval
            )));
        }
        exit_span!(timer);

        Ok(())
    }
}
