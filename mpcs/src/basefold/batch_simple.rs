use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::FieldType, virtual_poly::build_eq_x_r_vec, virtual_poly_v2::ArcMultilinearExtension,
};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use transcript::Transcript;

use crate::{
    sum_check::eq_xy_eval,
    util::{
        arithmetic::{
            degree_2_eval, degree_2_zero_plus_one, inner_product, interpolate2_weights,
            interpolate_over_boolean_hypercube,
        },
        ext_to_usize, field_type_index_base, field_type_index_ext,
        hash::{new_hasher, write_digest_to_transcript, Digest, Hasher},
        log2_strict,
        merkle_tree::{MerklePathWithoutLeafOrRoot, MerkleTree},
        plonky2_util::reverse_index_bits_in_place,
    },
    Error,
};

use super::{
    commit_phase::basefold_one_round_by_interpolation_weights,
    query_phase::{
        CodewordSingleQueryResult, ListQueryResultWithMerklePath, OracleListQueryResult,
        OracleListQueryResultWithMerklePath,
    },
    structure::{BasefoldCommitPhaseProof, BasefoldProof, ProofQueriesResultWithMerklePath},
    sumcheck::{sum_check_challenge_round, sum_check_first_round, sum_check_last_round},
    Basefold, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec,
    BasefoldVerifierParams, EncodingScheme,
};
use rand_chacha::rand_core::RngCore;

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore + std::fmt::Debug>
    Basefold<E, Spec, Rng>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn simple_batch_open_inner(
        pp: &BasefoldProverParams<E, Spec>,
        polys: &[ArcMultilinearExtension<E>],
        comm: &BasefoldCommitmentWithData<E>,
        point: &[E],
        evals: &[E],
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E>, Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys[0].num_vars();

        if comm.is_trivial::<Spec>() {
            return Ok(BasefoldProof::trivial(comm.polynomials_bh_evals.clone()));
        }

        polys
            .iter()
            .for_each(|poly| assert_eq!(poly.num_vars(), num_vars));
        assert!(num_vars >= Spec::get_basecode_msg_size_log());
        assert_eq!(comm.num_polys, polys.len());
        assert_eq!(comm.num_polys, evals.len());

        if cfg!(feature = "sanity-check") {
            evals
                .iter()
                .zip(polys)
                .for_each(|(eval, poly)| assert_eq!(&poly.evaluate(point), eval))
        }
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
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();
        let _target_sum = inner_product(evals, &eq_xt);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let (trees, commit_phase_proof) = simple_batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            point,
            &eq_xt,
            comm,
            transcript,
            num_vars,
            num_vars - Spec::get_basecode_msg_size_log(),
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let queries =
            simple_batch_prover_query_phase(transcript, comm, &trees, Spec::get_number_queries());
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::build_query_result");

        let queries_with_merkle_path =
            SimpleBatchQueriesResultWithMerklePath::from_query_result(queries, &trees, comm);
        end_timer!(query_timer);

        end_timer!(timer);

        Ok(BasefoldProof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            roots: commit_phase_proof.roots,
            final_message: commit_phase_proof.final_message,
            query_result_with_merkle_path: ProofQueriesResultWithMerklePath::SimpleBatched(
                queries_with_merkle_path,
            ),
            sumcheck_proof: None,
            trivial_proof: vec![],
        })
    }

    pub(crate) fn simple_batch_verify_inner(
        vp: &BasefoldVerifierParams<E, Spec>,
        comm: &BasefoldCommitment<E>,
        point: &[E],
        evals: &[E],
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::simple batch verify");
        let batch_size = evals.len();
        if let Some(num_polys) = comm.num_polys {
            assert_eq!(num_polys, batch_size);
        }
        let hasher = new_hasher::<E::BaseField>();

        if proof.is_trivial() {
            let trivial_proof = &proof.trivial_proof;
            let merkle_tree = MerkleTree::from_batch_leaves(trivial_proof.clone(), &hasher);
            if comm.root() == merkle_tree.root() {
                return Ok(());
            } else {
                return Err(Error::MerkleRootMismatch);
            }
        }

        let num_vars = point.len();
        if let Some(comm_num_vars) = comm.num_vars() {
            assert_eq!(num_vars, comm_num_vars);
            assert!(num_vars >= Spec::get_basecode_msg_size_log());
        }
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();

        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();

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
        let query_result_with_merkle_path = proof.query_result_with_merkle_path.as_simple_batched();

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &point[point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(&point[..point.len() - fold_challenges.len()]);
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        simple_batch_verifier_query_phase::<E, Spec>(
            queries.as_slice(),
            &vp.encoding_params,
            query_result_with_merkle_path,
            sumcheck_messages,
            &fold_challenges,
            &eq_xt,
            num_rounds,
            num_vars,
            final_message,
            roots,
            comm,
            eq.as_slice(),
            evals,
            &hasher,
        );
        end_timer!(timer);

        Ok(())
    }
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
#[allow(clippy::too_many_arguments)]
pub fn simple_batch_commit_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    pp: &<Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    point: &[E],
    batch_coeffs: &[E],
    comm: &BasefoldCommitmentWithData<E>,
    transcript: &mut Transcript<E>,
    num_vars: usize,
    num_rounds: usize,
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, BasefoldCommitPhaseProof<E>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Simple batch commit phase");
    assert_eq!(point.len(), num_vars);
    assert_eq!(comm.num_polys, batch_coeffs.len());
    let prepare_timer = start_timer!(|| "Prepare");
    let mut trees = Vec::with_capacity(num_vars);
    let batch_codewords_timer = start_timer!(|| "Batch codewords");
    let mut running_oracle = comm.batch_codewords(batch_coeffs);
    end_timer!(batch_codewords_timer);
    let mut running_evals = (0..(1 << num_vars))
        .into_par_iter()
        .map(|i| {
            comm.polynomials_bh_evals
                .iter()
                .zip(batch_coeffs)
                .map(|(eval, coeff)| field_type_index_ext(eval, i) * *coeff)
                .sum()
        })
        .collect();
    end_timer!(prepare_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_timer = start_timer!(|| "Basefold::build eq");
    let mut eq = build_eq_x_r_vec(point);
    end_timer!(build_eq_timer);

    let reverse_bits_timer = start_timer!(|| "Basefold::reverse bits");
    reverse_index_bits_in_place(&mut eq);
    end_timer!(reverse_bits_timer);

    let sumcheck_timer = start_timer!(|| "Basefold sumcheck first round");
    let mut last_sumcheck_message = sum_check_first_round(&mut eq, &mut running_evals);
    end_timer!(sumcheck_timer);

    let mut sumcheck_messages = Vec::with_capacity(num_rounds);
    let mut roots = Vec::with_capacity(num_rounds - 1);
    let mut final_message = Vec::new();
    let mut running_tree_inner = Vec::new();
    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.append_field_element_exts(&last_sumcheck_message);
        sumcheck_messages.push(last_sumcheck_message);

        let challenge = transcript
            .get_and_append_challenge(b"commit round")
            .elements;

        // Fold the current oracle for FRI
        let new_running_oracle = basefold_one_round_by_interpolation_weights::<E, Spec>(
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
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge);
            running_tree_inner = MerkleTree::<E>::compute_inner_ext(&new_running_oracle, hasher);
            let running_root = MerkleTree::<E>::root_from_inner(&running_tree_inner);
            write_digest_to_transcript(&running_root, transcript);
            roots.push(running_root);
            running_oracle = new_running_oracle;
        } else {
            // Assign a new value to the old running vars so that the compiler
            // knows the old value is safe to move.
            last_sumcheck_message = Vec::new();
            running_oracle = Vec::new();
            running_tree_inner = Vec::new();
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // running_evals is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut running_evals, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut running_evals);
            transcript.append_field_element_exts(&running_evals);
            final_message = running_evals;
            // To avoid the compiler complaining that running_evals is moved.
            running_evals = Vec::new();

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
                    FieldType::Ext(basecode) => basecode,
                    _ => panic!("Should be ext field"),
                };

                let mut new_running_oracle = new_running_oracle;
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

pub fn simple_batch_prover_query_phase<E: ExtensionField>(
    transcript: &mut Transcript<E>,
    comm: &BasefoldCommitmentWithData<E>,
    trees: &[MerkleTree<E>],
    num_verifier_queries: usize,
) -> SimpleBatchQueriesResult<E>
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
        .map(|x_index| ext_to_usize(x_index) % comm.codeword_size())
        .collect_vec();

    SimpleBatchQueriesResult {
        inner: queries_usize
            .par_iter()
            .map(|x_index| {
                (
                    *x_index,
                    simple_batch_basefold_get_query::<E>(comm.get_codewords(), trees, *x_index),
                )
            })
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn simple_batch_verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    indices: &[usize],
    vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    queries: &SimpleBatchQueriesResultWithMerklePath<E>,
    sum_check_messages: &[Vec<E>],
    fold_challenges: &[E],
    batch_coeffs: &[E],
    num_rounds: usize,
    num_vars: usize,
    final_message: &[E],
    roots: &[Digest<E::BaseField>],
    comm: &BasefoldCommitment<E>,
    partial_eq: &[E],
    evals: &[E],
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier query phase");

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
        batch_coeffs,
        num_rounds,
        num_vars,
        &final_codeword,
        roots,
        comm,
        hasher,
    );
    end_timer!(queries_timer);

    let final_timer = start_timer!(|| "Final checks");
    assert_eq!(
        &inner_product(batch_coeffs, evals),
        &degree_2_zero_plus_one(&sum_check_messages[0])
    );

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

fn simple_batch_basefold_get_query<E: ExtensionField>(
    poly_codewords: &[FieldType<E>],
    trees: &[MerkleTree<E>],
    x_index: usize,
) -> SimpleBatchSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut index = x_index;
    let p1 = index | 1;
    let p0 = p1 - 1;

    let commitment_query = match poly_codewords[0] {
        FieldType::Ext(_) => SimpleBatchCommitmentSingleQueryResult::new_ext(
            poly_codewords
                .iter()
                .map(|c| field_type_index_ext(c, p0))
                .collect(),
            poly_codewords
                .iter()
                .map(|c| field_type_index_ext(c, p1))
                .collect(),
            p0,
        ),
        FieldType::Base(_) => SimpleBatchCommitmentSingleQueryResult::new_base(
            poly_codewords
                .iter()
                .map(|c| field_type_index_base(c, p0))
                .collect(),
            poly_codewords
                .iter()
                .map(|c| field_type_index_base(c, p1))
                .collect(),
            p0,
        ),
        _ => unreachable!(),
    };
    index >>= 1;

    let mut oracle_queries = Vec::with_capacity(trees.len() + 1);
    for tree in trees {
        let p1 = index | 1;
        let p0 = p1 - 1;

        oracle_queries.push(CodewordSingleQueryResult::new_ext(
            tree.get_leaf_as_extension(p0)[0],
            tree.get_leaf_as_extension(p1)[0],
            p0,
        ));
        index >>= 1;
    }

    let oracle_query = OracleListQueryResult {
        inner: oracle_queries,
    };

    SimpleBatchSingleQueryResult {
        oracle_query,
        commitment_query,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SimpleBatchLeavesPair<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    Ext(Vec<(E, E)>),
    Base(Vec<(E::BaseField, E::BaseField)>),
}

impl<E: ExtensionField> SimpleBatchLeavesPair<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    #[allow(unused)]
    pub fn as_ext(&self) -> Vec<(E, E)> {
        match self {
            SimpleBatchLeavesPair::Ext(x) => x.clone(),
            SimpleBatchLeavesPair::Base(x) => {
                x.iter().map(|(x, y)| ((*x).into(), (*y).into())).collect()
            }
        }
    }

    pub fn batch(&self, coeffs: &[E]) -> (E, E) {
        match self {
            SimpleBatchLeavesPair::Ext(x) => {
                let mut result = (E::ZERO, E::ZERO);
                for (i, (x, y)) in x.iter().enumerate() {
                    result.0 += coeffs[i] * *x;
                    result.1 += coeffs[i] * *y;
                }
                result
            }
            SimpleBatchLeavesPair::Base(x) => {
                let mut result = (E::ZERO, E::ZERO);
                for (i, (x, y)) in x.iter().enumerate() {
                    result.0 += coeffs[i] * *x;
                    result.1 += coeffs[i] * *y;
                }
                result
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimpleBatchSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitment_query: SimpleBatchCommitmentSingleQueryResult<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimpleBatchSingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResultWithMerklePath<E>,
    commitment_query: SimpleBatchCommitmentSingleQueryResultWithMerklePath<E>,
}

impl<E: ExtensionField> SimpleBatchSingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_single_query_result(
        single_query_result: SimpleBatchSingleQueryResult<E>,
        oracle_trees: &[MerkleTree<E>],
        commitment: &BasefoldCommitmentWithData<E>,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::from_query_and_trees(
                single_query_result.oracle_query,
                |i, j| oracle_trees[i].merkle_path_without_leaf_sibling_or_root(j),
            ),
            commitment_query: SimpleBatchCommitmentSingleQueryResultWithMerklePath {
                query: single_query_result.commitment_query.clone(),
                merkle_path: commitment
                    .codeword_tree
                    .merkle_path_without_leaf_sibling_or_root(
                        single_query_result.commitment_query.index,
                    ),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn check<Spec: BasefoldSpec<E>>(
        &self,
        vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
        fold_challenges: &[E],
        batch_coeffs: &[E],
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comm: &BasefoldCommitment<E>,
        index: usize,
        hasher: &Hasher<E::BaseField>,
    ) {
        self.oracle_query.check_merkle_paths(roots, hasher);
        self.commitment_query
            .check_merkle_path(&Digest(comm.root().0), hasher);

        let (mut curr_left, mut curr_right) =
            self.commitment_query.query.leaves.batch(batch_coeffs);

        let mut right_index = index | 1;
        let mut left_index = right_index - 1;

        for (i, fold_challenge) in fold_challenges.iter().enumerate().take(num_rounds) {
            // let round_timer = start_timer!(|| format!("SingleQueryResult::round {}", i));

            let (x0, x1, w) = <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs(
                vp,
                num_vars + Spec::get_rate_log() - i - 1,
                left_index >> 1,
            );

            let res = interpolate2_weights([(x0, curr_left), (x1, curr_right)], w, *fold_challenge);

            let next_index = right_index >> 1;
            let next_oracle_value = if i < num_rounds - 1 {
                right_index = next_index | 1;
                left_index = right_index - 1;
                let next_oracle_query = self.oracle_query.get_inner()[i].clone();
                (curr_left, curr_right) = next_oracle_query.query.codepoints.as_ext();
                if next_index & 1 == 0 {
                    curr_left
                } else {
                    curr_right
                }
            } else {
                // Note that final_codeword has been bit-reversed, so no need to bit-reverse
                // next_index here.
                final_codeword[next_index]
            };
            assert_eq!(res, next_oracle_value, "Failed at round {}", i);
            // end_timer!(round_timer);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimpleBatchCommitmentSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    leaves: SimpleBatchLeavesPair<E>,
    index: usize,
}

impl<E: ExtensionField> SimpleBatchCommitmentSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn new_ext(left: Vec<E>, right: Vec<E>, index: usize) -> Self {
        Self {
            leaves: SimpleBatchLeavesPair::Ext(left.into_iter().zip(right).collect()),
            index,
        }
    }

    fn new_base(left: Vec<E::BaseField>, right: Vec<E::BaseField>, index: usize) -> Self {
        Self {
            leaves: SimpleBatchLeavesPair::Base(left.into_iter().zip(right).collect()),
            index,
        }
    }

    #[allow(unused)]
    fn left_ext(&self) -> Vec<E> {
        match &self.leaves {
            SimpleBatchLeavesPair::Ext(x) => x.iter().map(|(x, _)| *x).collect(),
            SimpleBatchLeavesPair::Base(x) => x.iter().map(|(x, _)| E::from(*x)).collect(),
        }
    }

    #[allow(unused)]
    fn right_ext(&self) -> Vec<E> {
        match &self.leaves {
            SimpleBatchLeavesPair::Ext(x) => x.iter().map(|(_, x)| *x).collect(),
            SimpleBatchLeavesPair::Base(x) => x.iter().map(|(_, x)| E::from(*x)).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimpleBatchCommitmentSingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    query: SimpleBatchCommitmentSingleQueryResult<E>,
    merkle_path: MerklePathWithoutLeafOrRoot<E>,
}

impl<E: ExtensionField> SimpleBatchCommitmentSingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn check_merkle_path(&self, root: &Digest<E::BaseField>, hasher: &Hasher<E::BaseField>) {
        // let timer = start_timer!(|| "CodewordSingleQuery::Check Merkle Path");
        match &self.query.leaves {
            SimpleBatchLeavesPair::Ext(inner) => {
                self.merkle_path.authenticate_batch_leaves_root_ext(
                    inner.iter().map(|(x, _)| *x).collect(),
                    inner.iter().map(|(_, x)| *x).collect(),
                    self.query.index,
                    root,
                    hasher,
                );
            }
            SimpleBatchLeavesPair::Base(inner) => {
                self.merkle_path.authenticate_batch_leaves_root_base(
                    inner.iter().map(|(x, _)| *x).collect(),
                    inner.iter().map(|(_, x)| *x).collect(),
                    self.query.index,
                    root,
                    hasher,
                );
            }
        }
        // end_timer!(timer);
    }
}

pub struct SimpleBatchQueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SimpleBatchSingleQueryResult<E>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleBatchQueriesResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SimpleBatchSingleQueryResultWithMerklePath<E>)>,
}

impl<E: ExtensionField> SimpleBatchQueriesResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_query_result(
        query_result: SimpleBatchQueriesResult<E>,
        oracle_trees: &[MerkleTree<E>],
        commitment: &BasefoldCommitmentWithData<E>,
    ) -> Self {
        Self {
            inner: query_result
                .inner
                .into_iter()
                .map(|(i, q)| {
                    (
                        i,
                        SimpleBatchSingleQueryResultWithMerklePath::from_single_query_result(
                            q,
                            oracle_trees,
                            commitment,
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
        batch_coeffs: &[E],
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comm: &BasefoldCommitment<E>,
        hasher: &Hasher<E::BaseField>,
    ) {
        self.inner.par_iter().zip(indices.par_iter()).for_each(
            |((index, query), index_in_proof)| {
                assert_eq!(index, index_in_proof);
                query.check::<Spec>(
                    vp,
                    fold_challenges,
                    batch_coeffs,
                    num_rounds,
                    num_vars,
                    final_codeword,
                    roots,
                    comm,
                    *index,
                    hasher,
                );
            },
        );
    }
}
