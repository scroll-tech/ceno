use super::{Statement, WhirProof, batch::Witnesses, parameters::WhirConfig};
use crate::{
    crypto::{
        Digest, DigestExt, MerklePathBase, MerklePathExt, MerkleTree, MerkleTreeBase,
        MerkleTreeExt, MultiPath, generate_multi_proof, write_digest_to_transcript,
    },
    domain::Domain,
    error::Error,
    ntt::expand_from_coeff,
    parameters::FoldType,
    sumcheck::prover_not_skipping::SumcheckProverNotSkipping,
    utils::{self, evaluate_over_hypercube, expand_randomness, interpolate_over_boolean_hypercube},
    whir::fold::{compute_fold, expand_from_univariate, restructure_evaluations},
};
use ff_ext::ExtensionField;
use multilinear_extensions::mle::{FieldType, MultilinearExtension};
use p3::matrix::dense::RowMajorMatrix;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;

use crate::whir::fs_utils::get_challenge_stir_queries;

pub struct Prover<E: ExtensionField>(pub WhirConfig<E>);

impl<E: ExtensionField> Prover<E>
where
    DigestExt<E>: IntoIterator<Item = E::BaseField> + PartialEq,
    MerklePathBase<E>: Send + Sync,
    MerkleTreeBase<E>: Send + Sync,
    MerklePathExt<E>: Send + Sync,
    MerkleTreeExt<E>: Send + Sync,
{
    pub(crate) fn validate_parameters(&self) -> bool {
        self.0.mv_parameters.num_variables
            == self.0.folding_factor.total_number(self.0.n_rounds()) + self.0.final_sumcheck_rounds
    }

    fn validate_statement(&self, statement: &Statement<E>) -> bool {
        assert_eq!(statement.points.len(), statement.evaluations.len());
        statement
            .points
            .iter()
            .for_each(|point| assert_eq!(point.len(), self.0.mv_parameters.num_variables));
        assert!(self.0.initial_statement || statement.points.is_empty());
        true
    }

    fn validate_witness(&self, witness: &Witnesses<E>) {
        assert_eq!(witness.ood_points.len(), witness.ood_answers.len());
        if !self.0.initial_statement {
            assert!(witness.ood_points.is_empty());
        }
        assert_eq!(
            witness.polys[0].len(),
            1 << self.0.mv_parameters.num_variables
        );
    }

    pub fn prove<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        mut statement: Statement<E>,
        witness: &Witnesses<E>,
    ) -> Result<WhirProof<E>, Error> {
        // If any evaluation point is shorter than the folding factor, pad with 0 in front
        let mut sumcheck_poly_evals = Vec::new();
        let mut ood_answers = Vec::new();
        let mut merkle_roots = Vec::new();
        for p in statement.points.iter_mut() {
            while p.len() < self.0.folding_factor.at_round(0) {
                p.insert(0, E::ONE);
            }
        }

        assert!(self.validate_parameters());
        self.validate_statement(&statement);
        self.validate_witness(witness);

        let timer = entered_span!("Single Prover");
        let initial_claims: Vec<_> = witness
            .ood_points
            .iter()
            .copied()
            .map(|ood_point| expand_from_univariate(ood_point, self.0.mv_parameters.num_variables))
            .chain(statement.points)
            .collect();
        let initial_answers: Vec<_> = witness
            .ood_answers
            .iter()
            .chain(statement.evaluations.iter())
            .copied()
            .collect();

        if !self.0.initial_statement {
            // It is ensured that if there is no initial statement, the
            // number of ood samples is also zero.
            assert!(
                initial_answers.is_empty(),
                "Can not have initial answers without initial statement"
            );
        }

        let mut sumcheck_prover = None;
        let folding_randomness = if self.0.initial_statement {
            // If there is initial statement, then we run the sum-check for
            // this initial statement.
            let combination_randomness_gen = transcript
                .sample_and_append_challenge(b"combination_randomness")
                .elements;
            let combination_randomness =
                expand_randomness(combination_randomness_gen, initial_claims.len());

            sumcheck_prover = Some(SumcheckProverNotSkipping::new(
                witness.polys[0]
                    .par_iter()
                    .map(|x| E::from_ref_base(x))
                    .collect(),
                &initial_claims,
                &combination_randomness,
                &initial_answers,
            ));

            sumcheck_prover
                .as_mut()
                .unwrap()
                .compute_sumcheck_polynomials::<T>(
                    transcript,
                    &mut sumcheck_poly_evals,
                    self.0.folding_factor.at_round(0),
                )?
        } else {
            // If there is no initial statement, there is no need to run the
            // initial rounds of the sum-check, and the verifier directly sends
            // the initial folding randomnesses.
            (0..self.0.folding_factor.at_round(0))
                .map(|_| {
                    transcript
                        .sample_and_append_challenge(b"folding_randomness")
                        .elements
                })
                .collect()
        };

        let round_state = RoundState {
            domain: self.0.starting_domain.clone(),
            round: 0,
            sumcheck_prover,
            folding_randomness,
            evaluations: MultilinearExtension::from_evaluations_ext_vec(
                self.0.mv_parameters.num_variables,
                witness.polys[0]
                    .par_iter()
                    .map(|x| E::from_ref_base(x))
                    .collect(),
            ),
            prev_merkle: Some(&witness.merkle_tree),
            merkle_proofs: vec![],
        };

        let round_timer = entered_span!("Single Round");
        let result = self.round(
            transcript,
            &mut sumcheck_poly_evals,
            &mut ood_answers,
            &mut merkle_roots,
            round_state,
        );
        exit_span!(round_timer);

        exit_span!(timer);

        result
    }

    pub(crate) fn round<T: Transcript<E>>(
        &self,
        transcript: &mut T,
        sumcheck_poly_evals: &mut Vec<Vec<E>>,
        ood_answers: &mut Vec<Vec<E>>,
        merkle_roots: &mut Vec<Digest<E>>,
        mut round_state: RoundState<E>,
    ) -> Result<WhirProof<E>, Error> {
        // Fold the coefficients
        let folded_evaluations = round_state
            .evaluations
            .fix_variables(&round_state.folding_randomness);
        let folded_evaluations_values = match folded_evaluations.evaluations() {
            FieldType::Ext(evals) => evals,
            _ => {
                panic!("Impossible after folding");
            }
        };

        let num_variables = self.0.mv_parameters.num_variables
            - self.0.folding_factor.total_number(round_state.round);
        // num_variables should match the folded_coefficients here.
        assert_eq!(1 << num_variables, folded_evaluations_values.len());

        // Base case
        if round_state.round == self.0.n_rounds() {
            // Directly send coefficients of the polynomial to the verifier.
            transcript.append_field_element_exts(folded_evaluations_values);

            // Final verifier queries and answers. The indices are over the
            // *folded* domain.
            let final_challenge_indexes = get_challenge_stir_queries(
                round_state.domain.size(), // The size of the *original* domain before folding
                self.0.folding_factor.at_round(round_state.round), /* The folding factor we used to fold the previous polynomial */
                self.0.final_queries,
                transcript,
            )?;

            let merkle_proof_with_leaves = generate_multi_proof(
                &self.0.hash_params,
                round_state.prev_merkle.unwrap(),
                &final_challenge_indexes,
            );
            round_state.merkle_proofs.push(merkle_proof_with_leaves);

            // Final sumcheck
            if self.0.final_sumcheck_rounds > 0 {
                round_state
                    .sumcheck_prover
                    .unwrap_or_else(|| {
                        SumcheckProverNotSkipping::new(
                            folded_evaluations_values.to_vec(),
                            &[],
                            &[],
                            &[],
                        )
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
                final_poly: folded_evaluations_values.to_vec(),
                folded_evals: Vec::new(),
            });
        }

        let round_params = &self.0.round_parameters[round_state.round];

        // Fold the coefficients, and compute fft of polynomial (and commit)
        let new_domain = round_state.domain.scale(2);
        let expansion = new_domain.size() / folded_evaluations_values.len();
        let mut folded_coeffs = folded_evaluations_values.to_vec();
        interpolate_over_boolean_hypercube(&mut folded_coeffs);
        let evals = expand_from_coeff(&folded_coeffs, expansion);
        // Group the evaluations into leaves by the *next* round folding factor
        // TODO: `stack_evaluations` and `restructure_evaluations` are really in-place algorithms.
        // They also partially overlap and undo one another. We should merge them.
        let folded_evals = utils::stack_evaluations(
            evals,
            self.0.folding_factor.at_round(round_state.round + 1), // Next round fold factor
        );
        let folded_evals = restructure_evaluations(
            folded_evals,
            self.0.fold_optimisation,
            new_domain.backing_domain_group_gen().inverse(),
            self.0.folding_factor.at_round(round_state.round + 1),
        );

        let (root, merkle_tree) = self.0.hash_params.commit_matrix_ext(RowMajorMatrix::new(
            folded_evals.clone(),
            1 << self.0.folding_factor.at_round(round_state.round + 1),
        ));

        write_digest_to_transcript(&root, transcript);
        merkle_roots.push(root);

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
            round_state.domain.size(), // Current domain size *before* folding
            self.0.folding_factor.at_round(round_state.round), // Current fold factor
            round_params.num_queries,
            transcript,
        )?;
        // Compute the generator of the folded domain, in the extension field
        let domain_scaled_gen = round_state
            .domain
            .backing_domain_element_pow_of_2(self.0.folding_factor.at_round(round_state.round));
        let stir_challenges: Vec<_> = ood_points
            .into_iter()
            .chain(
                stir_challenges_indexes
                    .iter()
                    .map(|i| domain_scaled_gen.exp_u64(*i as u64)),
            )
            .map(|univariate| expand_from_univariate(univariate, num_variables))
            .collect();

        let merkle_proof_with_leaves = generate_multi_proof(
            &self.0.hash_params,
            round_state.prev_merkle.unwrap(),
            &stir_challenges_indexes,
        );
        let answers: Vec<_> = merkle_proof_with_leaves
            .answers_ext()
            .iter()
            .map(|answers| answers[0].clone())
            .collect();
        // Evaluate answers in the folding randomness.
        let mut stir_evaluations = ood_answers_round.clone();
        match self.0.fold_optimisation {
            FoldType::Naive => {
                // See `Verifier::compute_folds_full`
                let domain_size = round_state.domain.size();
                let domain_gen = round_state.domain.backing_domain_group_gen();
                let domain_gen_inv = domain_gen.inverse();
                let coset_domain_size = 1 << self.0.folding_factor.at_round(round_state.round);
                // The domain (before folding) is split into cosets of size
                // `coset_domain_size` (which is just `fold_size`). Each coset
                // is generated by powers of `coset_generator` (which is just the
                // `fold_size`-root of unity) multiplied by a different
                // `coset_offset`.
                // For example, if `fold_size = 16`, and the domain size is N, then
                // the domain is (1, w, w^2, ..., w^(N-1)), the domain generator
                // is w, and the coset generator is w^(N/16).
                // The first coset is (1, w^(N/16), w^(2N/16), ..., w^(15N/16))
                // which is also a subgroup <w^(N/16)> itself (the coset_offset is 1).
                // The second coset would be w * <w^(N/16)>, the third coset would be
                // w^2 * <w^(N/16)>, and so on. Until w^(N/16-1) * <w^(N/16)>.
                let coset_generator_inv =
                    domain_gen_inv.exp_u64((domain_size / coset_domain_size) as u64);
                stir_evaluations.extend(stir_challenges_indexes.iter().zip(&answers).map(
                    |(index, answers)| {
                        // The coset is w^index * <w_coset_generator>
                        // let _coset_offset = domain_gen.pow(&[*index as u64]);
                        let coset_offset_inv = domain_gen_inv.exp_u64(*index as u64);

                        // In the Naive mode, the oracle consists directly of the
                        // evaluations of E over the domain. We leverage an
                        // algorithm to compute the evaluations of the folded E
                        // at the corresponding point in folded domain (which is
                        // coset_offset^fold_size).
                        compute_fold(
                            answers,
                            &round_state.folding_randomness,
                            coset_offset_inv,
                            coset_generator_inv,
                            E::from_canonical_u64(2).inverse(),
                            self.0.folding_factor.at_round(round_state.round),
                        )
                    },
                ))
            }
            FoldType::ProverHelps => stir_evaluations.extend(answers.iter().map(|answers| {
                // In the ProverHelps mode, the oracle values have been linearly
                // transformed such that they are exactly the coefficients of the
                // multilinear polynomial whose evaluation at the folding randomness
                // is just the folding of E evaluated at the folded point.
                let mut answers_coeffs = answers.to_vec();
                evaluate_over_hypercube(&mut answers_coeffs);
                MultilinearExtension::from_evaluations_ext_vec(
                    p3::util::log2_strict_usize(answers_coeffs.len()),
                    answers_coeffs.to_vec(),
                )
                .evaluate(&round_state.folding_randomness)
            })),
        }
        round_state.merkle_proofs.push(merkle_proof_with_leaves);

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
                    folded_evaluations_values.to_vec(),
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

pub(crate) struct RoundState<'a, E: ExtensionField> {
    pub(crate) round: usize,
    pub(crate) domain: Domain<E>,
    pub(crate) sumcheck_prover: Option<SumcheckProverNotSkipping<E>>,
    pub(crate) folding_randomness: Vec<E>,
    pub(crate) evaluations: MultilinearExtension<'a, E>,
    pub(crate) prev_merkle: Option<&'a MerkleTree<E>>,
    pub(crate) merkle_proofs: Vec<MultiPath<E>>,
}
