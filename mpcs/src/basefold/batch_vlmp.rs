use std::{
    borrow::{BorrowMut, Cow},
    ops::Deref,
};

use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType, MultilinearExtension},
    virtual_poly::build_eq_x_r_vec,
};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use transcript::Transcript;

use crate::{
    sum_check::{eq_xy_eval, SumCheck as _, VirtualPolynomial},
    util::{
        add_polynomial_with_coeff,
        arithmetic::{
            degree_2_eval, degree_2_zero_plus_one, inner_product, interpolate2_weights,
            interpolate_over_boolean_hypercube,
        },
        expression::{Expression, Query, Rotation},
        ext_to_usize, field_type_index_ext, field_type_iter_ext,
        hash::{new_hasher, write_digest_to_transcript, Digest, Hasher},
        log2_strict,
        merkle_tree::MerkleTree,
        multiply_poly,
        plonky2_util::reverse_index_bits_in_place,
        poly_index_ext, poly_iter_ext,
    },
    validate_input, Error, Evaluation,
};

use super::{
    commit_phase::basefold_one_round_by_interpolation_weights,
    inner_product_three,
    query_phase::{
        CodewordSingleQueryResult, CommitmentsQueryResult, CommitmentsQueryResultWithMerklePath,
        ListQueryResultWithMerklePath, OracleListQueryResult, OracleListQueryResultWithMerklePath,
    },
    structure::{BasefoldCommitPhaseProof, BasefoldProof, ProofQueriesResultWithMerklePath},
    sumcheck::{sum_check_challenge_round, sum_check_first_round, sum_check_last_round},
    Basefold, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldVerifierParams, EncodingScheme, SumCheck,
};
use rand_chacha::rand_core::RngCore;

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore + std::fmt::Debug>
    Basefold<E, Spec, Rng>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn batch_open_vlmp_inner(
        pp: &BasefoldProverParams<E, Spec>,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[BasefoldCommitmentWithData<E>],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E>, Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::batch_open_vlmp");
        let num_vars = polys.iter().map(|poly| poly.num_vars).max().unwrap();
        let min_num_vars = polys.iter().map(|p| p.num_vars).min().unwrap();
        assert!(min_num_vars >= Spec::get_basecode_msg_size_log());

        comms.iter().for_each(|comm| {
            assert!(comm.num_polys == 1);
            assert!(!comm.is_trivial::<Spec>());
        });

        if cfg!(feature = "sanity-check") {
            evals.iter().for_each(|eval| {
                assert_eq!(
                    &polys[eval.poly()].evaluate(&points[eval.point()]),
                    eval.value(),
                )
            })
        }

        validate_input("batch open", pp.get_max_message_size_log(), polys, points)?;

        let sumcheck_timer = start_timer!(|| "Basefold::batch_open::initial sumcheck");
        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt =
            DenseMultilinearExtension::<E>::from_evaluations_ext_vec(t.len(), build_eq_x_r_vec(&t));
        // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
        let target_sum = inner_product_three(
            evals.iter().map(Evaluation::value),
            &evals
                .iter()
                .map(|eval| E::from(1 << (num_vars - points[eval.point()].len())))
                .collect_vec(),
            &poly_iter_ext(&eq_xt).take(evals.len()).collect_vec(),
        );

        // Merge the polynomials for every point. One merged polynomial for each point.
        let merged_polys = evals.iter().zip(poly_iter_ext(&eq_xt)).fold(
            // This folding will generate a vector of |points| pairs of (scalar, polynomial)
            // The polynomials are initialized to zero, and the scalars are initialized to one
            vec![(E::ONE, Cow::<DenseMultilinearExtension<E>>::default()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                // For each polynomial to open, eval.point() specifies which point it is to be opened at.
                if merged_polys[eval.point()].1.num_vars == 0 {
                    // If the accumulator for this point is still the zero polynomial,
                    // directly assign the random coefficient and the polynomial to open to
                    // this accumulator
                    merged_polys[eval.point()] = (eq_xt_i, Cow::Borrowed(&polys[eval.poly()]));
                } else {
                    // If the accumulator is unempty now, first force its scalar to 1, i.e.,
                    // make (scalar, polynomial) to (1, scalar * polynomial)
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != E::ONE {
                        merged_polys[eval.point()].0 = E::ONE;
                        multiply_poly(merged_polys[eval.point()].1.to_mut().borrow_mut(), &coeff);
                    }
                    // Equivalent to merged_poly += poly * batch_coeff. Note that
                    // add_assign_mixed_with_coeff allows adding two polynomials with
                    // different variables, and the result has the same number of vars
                    // with the larger one of the two added polynomials.
                    add_polynomial_with_coeff(
                        merged_polys[eval.point()].1.to_mut().borrow_mut(),
                        &polys[eval.poly()],
                        &eq_xt_i,
                    );

                    // Note that once the scalar in the accumulator becomes ONE, it will remain
                    // to be ONE forever.
                }
                merged_polys
            },
        );

        let points = points.to_vec();
        if cfg!(feature = "sanity-check") {
            let expected_sum = merged_polys
                .iter()
                .zip(&points)
                .map(|((scalar, poly), point)| {
                    inner_product(
                        &poly_iter_ext(poly).collect_vec(),
                        build_eq_x_r_vec(point).iter(),
                    ) * scalar
                        * E::from(1 << (num_vars - poly.num_vars))
                    // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
                })
                .sum::<E>();
            assert_eq!(expected_sum, target_sum);

            merged_polys.iter().enumerate().for_each(|(i, (_, poly))| {
                assert_eq!(points[i].len(), poly.num_vars);
            });
        }

        let expression = merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (scalar, _))| {
                Expression::<E>::eq_xy(idx)
                    * Expression::Polynomial(Query::new(idx, Rotation::cur()))
                    * scalar
            })
            .sum();
        let sumcheck_polys: Vec<&DenseMultilinearExtension<E>> = merged_polys
            .iter()
            .map(|(_, poly)| poly.deref())
            .collect_vec();
        let virtual_poly =
            VirtualPolynomial::new(&expression, sumcheck_polys, &[], points.as_slice());

        let (challenges, merged_poly_evals, sumcheck_proof) =
            SumCheck::prove(&(), num_vars, virtual_poly, target_sum, transcript)?;

        end_timer!(sumcheck_timer);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients, and is able to evaluate eq_xy(point) for each poly to open.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&challenges[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; comms.len()];
        evals.iter().enumerate().for_each(|(i, eval)| {
            coeffs[eval.poly()] += eq_xy_evals[eval.point()] * poly_index_ext(&eq_xt, i);
        });

        if cfg!(feature = "sanity-check") {
            let poly_evals = polys
                .iter()
                .map(|poly| poly.evaluate(&challenges[..poly.num_vars]))
                .collect_vec();
            let new_target_sum = inner_product(&poly_evals, &coeffs);
            let desired_sum = merged_polys
                .iter()
                .zip(points)
                .zip(merged_poly_evals)
                .map(|(((scalar, poly), point), evals_from_sum_check)| {
                    assert_eq!(
                        evals_from_sum_check,
                        poly.evaluate(&challenges[..poly.num_vars])
                    );
                    *scalar
                        * evals_from_sum_check
                        * eq_xy_eval(point.as_slice(), &challenges[0..point.len()])
                })
                .sum::<E>();
            assert_eq!(new_target_sum, desired_sum);
        }
        // Note that the verifier can also compute these coeffs locally, so no need to pass
        // them to the transcript.

        let point = challenges;

        let (trees, commit_phase_proof) = batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            &point,
            comms,
            transcript,
            num_vars,
            num_vars - Spec::get_basecode_msg_size_log(),
            coeffs.as_slice(),
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::batch_open query phase");
        let query_result = batch_prover_query_phase(
            transcript,
            1 << (num_vars + Spec::get_rate_log()),
            comms,
            &trees,
            Spec::get_number_queries(),
        );
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::batch_open build query result");
        let query_result_with_merkle_path =
            BatchedQueriesResultWithMerklePath::from_batched_query_result(
                query_result,
                &trees,
                comms,
            );
        end_timer!(query_timer);
        end_timer!(timer);

        Ok(BasefoldProof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            roots: commit_phase_proof.roots,
            final_message: commit_phase_proof.final_message,
            query_result_with_merkle_path: ProofQueriesResultWithMerklePath::Batched(
                query_result_with_merkle_path,
            ),
            sumcheck_proof: Some(sumcheck_proof),
            trivial_proof: vec![],
        })
    }

    pub(crate) fn batch_verify_vlmp_inner(
        vp: &BasefoldVerifierParams<E, Spec>,
        comms: &[BasefoldCommitment<E>],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::batch_verify");
        // 	let key = "RAYON_NUM_THREADS";
        // 	env::set_var(key, "32");
        let hasher = new_hasher::<E::BaseField>();
        let comms = comms.iter().collect_vec();
        let num_vars = points.iter().map(|point| point.len()).max().unwrap();
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();
        validate_input("batch verify", num_vars, &[], points)?;
        let poly_num_vars = comms.iter().map(|c| c.num_vars().unwrap()).collect_vec();
        evals.iter().for_each(|eval| {
            assert_eq!(
                points[eval.point()].len(),
                comms[eval.poly()].num_vars().unwrap()
            );
        });
        assert!(poly_num_vars.iter().min().unwrap() >= &Spec::get_basecode_msg_size_log());
        assert!(!proof.is_trivial());

        let sumcheck_timer = start_timer!(|| "Basefold::batch_verify::initial sumcheck");
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        let eq_xt =
            DenseMultilinearExtension::from_evaluations_ext_vec(t.len(), build_eq_x_r_vec(&t));
        let target_sum = inner_product_three(
            evals.iter().map(Evaluation::value),
            &evals
                .iter()
                .map(|eval| E::from(1 << (num_vars - points[eval.point()].len())))
                .collect_vec(),
            &poly_iter_ext(&eq_xt).take(evals.len()).collect_vec(),
        );

        let (new_target_sum, verify_point) = SumCheck::verify(
            &(),
            num_vars,
            2,
            target_sum,
            proof.sumcheck_proof.as_ref().unwrap(),
            transcript,
        )?;
        end_timer!(sumcheck_timer);

        // Now the goal is to use the BaseFold to check the new target sum. Note that this time
        // we only have one eq polynomial in the sum-check.
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&verify_point[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; comms.len()];
        evals.iter().enumerate().for_each(|(i, eval)| {
            coeffs[eval.poly()] += eq_xy_evals[eval.point()] * poly_index_ext(&eq_xt, i)
        });

        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_vars);
        let roots = &proof.roots;
        let sumcheck_messages = &proof.sumcheck_messages;
        for i in 0..num_rounds {
            transcript.append_field_element_exts(sumcheck_messages[i].as_slice());
            fold_challenges.push(
                transcript
                    .get_and_append_challenge(b"commit round")
                    .elements,
            );
            if i < num_rounds - 1 {
                write_digest_to_transcript(&roots[i], transcript);
            }
        }
        let final_message = &proof.final_message;
        transcript.append_field_element_exts(final_message.as_slice());

        let queries: Vec<_> = (0..Spec::get_number_queries())
            .map(|_| {
                ext_to_usize(
                    &transcript
                        .get_and_append_challenge(b"query indices")
                        .elements,
                ) % (1 << (num_vars + Spec::get_rate_log()))
            })
            .collect();
        let query_result_with_merkle_path = proof.query_result_with_merkle_path.as_batched();

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &verify_point.as_slice()[verify_point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(
            &verify_point.as_slice()[..verify_point.len() - fold_challenges.len()],
        );
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        batch_verifier_query_phase::<E, Spec>(
            queries.as_slice(),
            &vp.encoding_params,
            query_result_with_merkle_path,
            sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            final_message,
            roots,
            &comms,
            &coeffs,
            eq.as_slice(),
            &new_target_sum,
            &hasher,
        );
        end_timer!(timer);
        Ok(())
    }
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
#[allow(clippy::too_many_arguments)]
fn batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    comms: &[BasefoldCommitmentWithData<E>],
    transcript: &mut Transcript<E>,
    num_vars: usize,
    num_rounds: usize,
    coeffs: &[E],
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Batch Commit phase");
    assert_eq!(point.len(), num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = vec![E::ZERO; 1 << (num_vars + Spec::get_rate_log())];

    let build_oracle_timer = start_timer!(|| "Basefold build initial oracle");
    // Before the interaction, collect all the polynomials whose num variables match the
    // max num variables
    let running_oracle_len = running_oracle.len();
    comms
        .iter()
        .enumerate()
        .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
        .for_each(|(index, comm)| {
            running_oracle
                .iter_mut()
                .zip_eq(field_type_iter_ext(&comm.get_codewords()[0]))
                .for_each(|(r, a)| *r += a * coeffs[index]);
        });
    end_timer!(build_oracle_timer);

    let build_oracle_timer = start_timer!(|| "Basefold build initial sumcheck evals");
    // Unlike the FRI part, the sum-check part still follows the original procedure,
    // and linearly combine all the polynomials once for all
    let mut sum_of_all_evals_for_sumcheck = vec![E::ZERO; 1 << num_vars];
    comms.iter().enumerate().for_each(|(index, comm)| {
        sum_of_all_evals_for_sumcheck
            .par_iter_mut()
            .enumerate()
            .for_each(|(pos, r)| {
                // Evaluating the multilinear polynomial outside of its interpolation hypercube
                // is equivalent to repeating each element in place.
                // Here is the tricky part: the bh_evals are stored in big endian, but we want
                // to align the polynomials to the variable with index 0 before adding them
                // together. So each element is repeated by
                // sum_of_all_evals_for_sumcheck.len() / bh_evals.len() times
                *r += field_type_index_ext(
                    &comm.polynomials_bh_evals[0],
                    pos >> (num_vars - log2_strict(comm.polynomials_bh_evals[0].len())),
                ) * coeffs[index]
            });
    });
    end_timer!(build_oracle_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let mut eq = build_eq_x_r_vec(point);
    reverse_index_bits_in_place(&mut eq);

    let sumcheck_timer = start_timer!(|| "Basefold first round");
    let mut sumcheck_messages = Vec::with_capacity(num_rounds + 1);
    let mut last_sumcheck_message =
        sum_check_first_round(&mut eq, &mut sum_of_all_evals_for_sumcheck);
    sumcheck_messages.push(last_sumcheck_message.clone());
    end_timer!(sumcheck_timer);

    let mut roots = Vec::with_capacity(num_rounds - 1);
    let mut final_message = Vec::new();
    let mut running_tree_inner = Vec::new();
    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Batch basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.append_field_element_exts(&last_sumcheck_message);

        let challenge = transcript
            .get_and_append_challenge(b"commit round")
            .elements;

        // Fold the current oracle for FRI
        let mut new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
            pp,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );

        if i > 0 {
            let running_tree = MerkleTree::<E>::from_inner_leaves(
                running_tree_inner,
                FieldType::Ext(running_oracle),
            );
            trees.push(running_tree);
        }

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            sumcheck_messages.push(last_sumcheck_message.clone());
            running_tree_inner = MerkleTree::<E>::compute_inner_ext(&new_running_oracle, hasher);
            let running_root = MerkleTree::<E>::root_from_inner(&running_tree_inner);
            write_digest_to_transcript(&running_root, transcript);
            roots.push(running_root);

            // Then merge the rest polynomials whose sizes match the current running oracle
            let running_oracle_len = new_running_oracle.len();
            comms
                .iter()
                .enumerate()
                .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
                .for_each(|(index, comm)| {
                    new_running_oracle
                        .iter_mut()
                        .zip_eq(field_type_iter_ext(&comm.get_codewords()[0]))
                        .for_each(|(r, a)| *r += a * coeffs[index]);
                });
            running_oracle = new_running_oracle;
        } else {
            // Clear the value so the compiler does not think they are moved
            running_oracle = Vec::new();
            running_tree_inner = Vec::new();
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // sum_of_all_evals_for_sumcheck is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut sum_of_all_evals_for_sumcheck);
            transcript.append_field_element_exts(&sum_of_all_evals_for_sumcheck);
            final_message = sum_of_all_evals_for_sumcheck;
            // To prevent the compiler from complaining that the value is moved
            sum_of_all_evals_for_sumcheck = Vec::new();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.

                let mut coeffs = final_message.clone();
                if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
                    reverse_index_bits_in_place(&mut coeffs);
                }
                interpolate_over_boolean_hypercube(&mut coeffs);
                let basecode = <Spec::EncodingScheme as EncodingScheme<E>>::encode(
                    pp,
                    &FieldType::Ext(coeffs),
                );
                let basecode = match basecode {
                    FieldType::Ext(x) => x,
                    _ => panic!("Expected ext field"),
                };

                reverse_index_bits_in_place(&mut new_running_oracle);
                assert_eq!(basecode, new_running_oracle);
            }
        }
        end_timer!(sumcheck_timer);
    }
    end_timer!(timer);
    (
        trees,
        BasefoldCommitPhaseProof {
            sumcheck_messages,
            roots,
            final_message,
        },
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchedSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitments_query: CommitmentsQueryResult<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchedQueriesResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, BatchedSingleQueryResultWithMerklePath<E>)>,
}

impl<E: ExtensionField> BatchedQueriesResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_batched_query_result(
        batched_query_result: BatchedQueriesResult<E>,
        oracle_trees: &[MerkleTree<E>],
        commitments: &[BasefoldCommitmentWithData<E>],
    ) -> Self {
        Self {
            inner: batched_query_result
                .inner
                .into_iter()
                .map(|(i, q)| {
                    (
                        i,
                        BatchedSingleQueryResultWithMerklePath::from_batched_single_query_result(
                            q,
                            oracle_trees,
                            commitments,
                        ),
                    )
                })
                .collect(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn check<Spec: BasefoldSpec<E>>(
        &self,
        indices: &[usize],
        vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
        fold_challenges: &[E],
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comms: &[&BasefoldCommitment<E>],
        coeffs: &[E],
        hasher: &Hasher<E::BaseField>,
    ) {
        let timer = start_timer!(|| "BatchedQueriesResult::check");
        self.inner.par_iter().zip(indices.par_iter()).for_each(
            |((index, query), index_in_proof)| {
                assert_eq!(index, index_in_proof);
                query.check::<Spec>(
                    vp,
                    fold_challenges,
                    num_rounds,
                    num_vars,
                    final_codeword,
                    roots,
                    comms,
                    coeffs,
                    *index,
                    hasher,
                );
            },
        );
        end_timer!(timer);
    }
}

pub struct BatchedQueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, BatchedSingleQueryResult<E>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchedSingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResultWithMerklePath<E>,
    commitments_query: CommitmentsQueryResultWithMerklePath<E>,
}

impl<E: ExtensionField> BatchedSingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_batched_single_query_result(
        batched_single_query_result: BatchedSingleQueryResult<E>,
        oracle_trees: &[MerkleTree<E>],
        commitments: &[BasefoldCommitmentWithData<E>],
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::from_query_and_trees(
                batched_single_query_result.oracle_query,
                |i, j| oracle_trees[i].merkle_path_without_leaf_sibling_or_root(j),
            ),
            commitments_query: CommitmentsQueryResultWithMerklePath::from_query_and_trees(
                batched_single_query_result.commitments_query,
                |i, j| {
                    commitments[i]
                        .codeword_tree
                        .merkle_path_without_leaf_sibling_or_root(j)
                },
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn check<Spec: BasefoldSpec<E>>(
        &self,
        vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
        fold_challenges: &[E],
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comms: &[&BasefoldCommitment<E>],
        coeffs: &[E],
        index: usize,
        hasher: &Hasher<E::BaseField>,
    ) {
        self.oracle_query.check_merkle_paths(roots, hasher);
        self.commitments_query.check_merkle_paths(
            comms
                .iter()
                .map(|comm| comm.root())
                .collect_vec()
                .as_slice(),
            hasher,
        );
        // end_timer!(commit_timer);

        let mut curr_left = E::ZERO;
        let mut curr_right = E::ZERO;

        let mut right_index = index | 1;
        let mut left_index = right_index - 1;

        for (i, fold_challenge) in fold_challenges.iter().enumerate().take(num_rounds) {
            // let round_timer = start_timer!(|| format!("BatchedSingleQueryResult::round {}", i));
            let matching_comms = comms
                .iter()
                .enumerate()
                .filter(|(_, comm)| comm.num_vars().unwrap() == num_vars - i)
                .map(|(index, _)| index)
                .collect_vec();

            matching_comms.iter().for_each(|index| {
                let query = self.commitments_query.get_inner()[*index].query;
                assert_eq!(query.index >> 1, left_index >> 1);
                curr_left += query.left_ext() * coeffs[*index];
                curr_right += query.right_ext() * coeffs[*index];
            });

            let (x0, x1, w) = <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs(
                vp,
                num_vars + Spec::get_rate_log() - i - 1,
                left_index >> 1,
            );

            let mut res =
                interpolate2_weights([(x0, curr_left), (x1, curr_right)], w, *fold_challenge);

            let next_index = right_index >> 1;

            let next_oracle_value = if i < num_rounds - 1 {
                right_index = next_index | 1;
                left_index = right_index - 1;
                let next_oracle_query = &self.oracle_query.get_inner()[i];
                curr_left = next_oracle_query.query.left_ext();
                curr_right = next_oracle_query.query.right_ext();
                if next_index & 1 == 0 {
                    curr_left
                } else {
                    curr_right
                }
            } else {
                // Note that in the last round, res is folded to an element in the final
                // codeword, but has not yet added the committed polynomial evaluations
                // at this position.
                // So we need to repeat the finding and adding procedure here.
                // The reason for the existence of one extra find-and-add is that the number
                // of different polynomial number of variables is one more than the number of
                // rounds.

                let matching_comms = comms
                    .iter()
                    .enumerate()
                    .filter(|(_, comm)| comm.num_vars().unwrap() == num_vars - i - 1)
                    .map(|(index, _)| index)
                    .collect_vec();

                matching_comms.iter().for_each(|index| {
                    let query: CodewordSingleQueryResult<E> =
                        self.commitments_query.get_inner()[*index].query;
                    assert_eq!(query.index >> 1, next_index >> 1);
                    if next_index & 1 == 0 {
                        res += query.left_ext() * coeffs[*index];
                    } else {
                        res += query.right_ext() * coeffs[*index];
                    }
                });

                // Note that final_codeword has been bit-reversed, so no need to bit-reverse
                // next_index here.
                final_codeword[next_index]
            };
            assert_eq!(res, next_oracle_value, "Failed at round {}", i);
            // end_timer!(round_timer);
        }
        // end_timer!(timer);
    }
}

pub fn batch_prover_query_phase<E: ExtensionField>(
    transcript: &mut Transcript<E>,
    codeword_size: usize,
    comms: &[BasefoldCommitmentWithData<E>],
    trees: &[MerkleTree<E>],
    num_verifier_queries: usize,
) -> BatchedQueriesResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let queries: Vec<_> = (0..num_verifier_queries)
        .map(|_| {
            transcript
                .get_and_append_challenge(b"query indices")
                .elements
        })
        .collect();

    // Transform the challenge queries from field elements into integers
    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| ext_to_usize(x_index) % codeword_size)
        .collect_vec();

    BatchedQueriesResult {
        inner: queries_usize
            .par_iter()
            .map(|x_index| {
                (
                    *x_index,
                    batch_basefold_get_query::<E>(comms, trees, codeword_size, *x_index),
                )
            })
            .collect(),
    }
}

fn batch_basefold_get_query<E: ExtensionField>(
    comms: &[BasefoldCommitmentWithData<E>],
    trees: &[MerkleTree<E>],
    codeword_size: usize,
    x_index: usize,
) -> BatchedSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut oracle_list_queries = Vec::with_capacity(trees.len());

    let mut index = x_index;
    index >>= 1;
    for tree in trees {
        let p1 = index | 1;
        let p0 = p1 - 1;
        oracle_list_queries.push(CodewordSingleQueryResult::<E>::new_ext(
            tree.get_leaf_as_extension(p0)[0],
            tree.get_leaf_as_extension(p1)[0],
            p0,
        ));
        index >>= 1;
    }
    let oracle_query = OracleListQueryResult {
        inner: oracle_list_queries,
    };

    let comm_queries = comms
        .iter()
        .map(|comm| {
            let x_index = x_index >> (log2_strict(codeword_size) - comm.codeword_size_log());
            let p1 = x_index | 1;
            let p0 = p1 - 1;
            match &comm.get_codewords()[0] {
                FieldType::Ext(poly_codeword) => {
                    CodewordSingleQueryResult::new_ext(poly_codeword[p0], poly_codeword[p1], p0)
                }
                FieldType::Base(poly_codeword) => {
                    CodewordSingleQueryResult::new_base(poly_codeword[p0], poly_codeword[p1], p0)
                }
                _ => unreachable!(),
            }
        })
        .collect_vec();

    let commitments_query = CommitmentsQueryResult {
        inner: comm_queries,
    };

    BatchedSingleQueryResult {
        oracle_query,
        commitments_query,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn batch_verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    indices: &[usize],
    vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    queries: &BatchedQueriesResultWithMerklePath<E>,
    sum_check_messages: &[Vec<E>],
    fold_challenges: &[E],
    num_rounds: usize,
    num_vars: usize,
    final_message: &[E],
    roots: &[Digest<E::BaseField>],
    comms: &[&BasefoldCommitment<E>],
    coeffs: &[E],
    partial_eq: &[E],
    eval: &E,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier batch query phase");
    let encode_timer = start_timer!(|| "Encode final codeword");
    let mut message = final_message.to_vec();
    if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
        reverse_index_bits_in_place(&mut message);
    }
    interpolate_over_boolean_hypercube(&mut message);
    let final_codeword =
        <Spec::EncodingScheme as EncodingScheme<E>>::encode_small(vp, &FieldType::Ext(message));
    let mut final_codeword = match final_codeword {
        FieldType::Ext(final_codeword) => final_codeword,
        _ => panic!("Final codeword must be extension field"),
    };
    reverse_index_bits_in_place(&mut final_codeword);
    end_timer!(encode_timer);

    // For computing the weights on the fly, because the verifier is incapable of storing
    // the weights.

    let queries_timer = start_timer!(|| format!("Check {} queries", indices.len()));
    queries.check::<Spec>(
        indices,
        vp,
        fold_challenges,
        num_rounds,
        num_vars,
        &final_codeword,
        roots,
        comms,
        coeffs,
        hasher,
    );
    end_timer!(queries_timer);

    #[allow(unused)]
    let final_timer = start_timer!(|| "Final checks");
    assert_eq!(eval, &degree_2_zero_plus_one(&sum_check_messages[0]));

    // The sum-check part of the protocol
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sum_check_messages[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sum_check_messages[i + 1])
        );
    }

    // Finally, the last sumcheck poly evaluation should be the same as the sum of the polynomial
    // sent from the prover
    assert_eq!(
        degree_2_eval(
            &sum_check_messages[fold_challenges.len() - 1],
            fold_challenges[fold_challenges.len() - 1]
        ),
        inner_product(final_message, partial_eq)
    );
    end_timer!(final_timer);
    end_timer!(timer);
}
