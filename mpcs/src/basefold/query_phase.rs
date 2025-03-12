use crate::{
    basefold::structure::MerkleTreeExt,
    util::{
        arithmetic::{
            degree_2_eval, degree_2_zero_plus_one, inner_product,
            interpolate_over_boolean_hypercube, interpolate2_weights,
        },
        ext_to_usize,
        merkle_tree::poseidon2_merkle_tree,
    },
};
use ark_std::{end_timer, start_timer};
use core::fmt::Debug;
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_matrix::Matrix;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use transcript::Transcript;

use crate::basefold::structure::QueryOpeningProofs;
use multilinear_extensions::mle::FieldType;

use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldSpec},
};
use crate::util::plonky2_util::reverse_index_bits_in_place;
use rayon::prelude::ParallelIterator;

pub fn simple_batch_prover_query_phase<E: ExtensionField>(
    transcript: &mut impl Transcript<E>,
    comm: &BasefoldCommitmentWithWitness<E>,
    trees: &[MerkleTreeExt<E>],
    num_verifier_queries: usize,
) -> QueryOpeningProofs<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let queries: Vec<_> = transcript.sample_and_append_vec(b"query indices", num_verifier_queries);

    let mmcs_ext = ExtensionMmcs::<E::BaseField, E, _>::new(poseidon2_merkle_tree::<E>());
    let mmcs = poseidon2_merkle_tree::<E>();

    // Transform the challenge queries from field elements into integers
    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| ext_to_usize(x_index) % comm.codeword_size())
        .collect_vec();

    queries_usize
        .iter()
        .map(|idx| {
            let odd = idx | 1;
            let even = odd - 1;

            let opening = {
                let (mut values, proof) = mmcs.open_batch(even, &comm.codeword);
                let leafs = values.pop().unwrap();
                // leaf length equal to number of polynomial
                debug_assert_eq!(leafs.len(), mmcs.get_matrices(&comm.codeword)[0].width());
                (leafs, proof)
            };
            let (_, opening_ext) =
                trees
                    .iter()
                    .fold((idx >> 1, vec![]), |(idx, mut proofs), tree| {
                        let odd = idx | 1;
                        let even = odd - 1;
                        let (mut values, proof) = mmcs_ext.open_batch(even, tree);
                        let leafs = values.pop().unwrap();
                        debug_assert_eq!(leafs.len(), 2);
                        // TODO we can keep only one of the leafs, as the other can be interpolate from previous layer
                        proofs.push((leafs, proof));
                        (idx >> 1, proofs)
                    });
            (opening, opening_ext)
        })
        .collect_vec()
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
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier query phase");

    let encode_timer = start_timer!(|| "Encode final codeword");
    let mut message = final_message.to_vec();
    if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_left_and_right_folding() {
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

impl<E: ExtensionField> ListQueryResult<E> for CommitmentsQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResult<E>> {
        &self.inner
    }

    fn get_inner_into(self) -> Vec<CodewordSingleQueryResult<E>> {
        self.inner
    }
}

impl<E: ExtensionField> ListQueryResultWithMerklePath<E> for OracleListQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResultWithMerklePath<E>> {
        &self.inner
    }

    fn new(inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>) -> Self {
        Self { inner }
    }
}

impl<E: ExtensionField> ListQueryResultWithMerklePath<E> for CommitmentsQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResultWithMerklePath<E>> {
        &self.inner
    }

    fn new(inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>) -> Self {
        Self { inner }
    }
}

trait ListQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResult<E>>;

    fn get_inner_into(self) -> Vec<CodewordSingleQueryResult<E>>;

    fn merkle_path(
        &self,
        path: impl Fn(usize, usize) -> MerklePathWithoutLeafOrRoot<E>,
    ) -> Vec<MerklePathWithoutLeafOrRoot<E>> {
        let ret = self
            .get_inner()
            .iter()
            .enumerate()
            .map(|(i, query_result)| path(i, query_result.index))
            .collect_vec();
        ret
    }
}

trait ListQueryResultWithMerklePath<E: ExtensionField>: Sized
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn new(inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>) -> Self;

    fn get_inner(&self) -> &Vec<CodewordSingleQueryResultWithMerklePath<E>>;

    fn from_query_and_trees<LQR: ListQueryResult<E>>(
        query_result: LQR,
        path: impl Fn(usize, usize) -> MerklePathWithoutLeafOrRoot<E>,
    ) -> Self {
        Self::new(
            query_result
                .merkle_path(path)
                .into_iter()
                .zip(query_result.get_inner_into())
                .map(
                    |(path, codeword_result)| CodewordSingleQueryResultWithMerklePath {
                        query: codeword_result,
                        merkle_path: path,
                    },
                )
                .collect_vec(),
        )
    }

    fn check_merkle_paths(&self, roots: &[Digest<E::BaseField>]) {
        // let timer = start_timer!(|| "ListQuery::Check Merkle Path");
        self.get_inner()
            .iter()
            .zip(roots.iter())
            .for_each(|(q, root)| {
                q.check_merkle_path(root);
            });
        // end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
struct SingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitment_query: CodewordSingleQueryResult<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
struct SingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResultWithMerklePath<E>,
    commitment_query: CodewordSingleQueryResultWithMerklePath<E>,
}

impl<E: ExtensionField> SingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_single_query_result(
        single_query_result: SingleQueryResult<E>,
        oracle_trees: &[MerkleTree<E>],
        commitment: &BasefoldCommitmentWithWitness<E>,
    ) -> Self {
        assert!(commitment.codeword_tree.height() > 0);
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::from_query_and_trees(
                single_query_result.oracle_query,
                |i, j| oracle_trees[i].merkle_path_without_leaf_sibling_or_root(j),
            ),
            commitment_query: CodewordSingleQueryResultWithMerklePath {
                query: single_query_result.commitment_query,
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
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comm: &BasefoldCommitment<E>,
        index: usize,
    ) {
        // let timer = start_timer!(|| "Checking codeword single query");
        self.oracle_query.check_merkle_paths(roots);
        self.commitment_query
            .check_merkle_path(&Digest(comm.root().0));

        let (mut curr_left, mut curr_right) = self.commitment_query.query.codepoints.as_ext();

        let mut right_index = index | 1;
        let mut left_index = right_index - 1;

        for (i, fold_challenge) in fold_challenges.iter().enumerate().take(num_rounds) {
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
        // end_timer!(timer);
    }
}

pub struct QueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SingleQueryResult<E>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct QueriesResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SingleQueryResultWithMerklePath<E>)>,
}

impl<E: ExtensionField> QueriesResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn empty() -> Self {
        Self { inner: vec![] }
    }

    pub fn from_query_result(
        query_result: QueriesResult<E>,
        oracle_trees: &[MerkleTree<E>],
        commitment: &BasefoldCommitmentWithWitness<E>,
    ) -> Self {
        Self {
            inner: query_result
                .inner
                .into_iter()
                .map(|(i, q)| {
                    (
                        i,
                        SingleQueryResultWithMerklePath::from_single_query_result(
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
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comm: &BasefoldCommitment<E>,
    ) {
        self.inner
            .iter()
            .zip(indices.iter())
            .for_each(|((index, query), index_in_proof)| {
                assert_eq!(index_in_proof, index);
                query.check::<Spec>(
                    vp,
                    fold_challenges,
                    num_rounds,
                    num_vars,
                    final_codeword,
                    roots,
                    comm,
                    *index,
                );
            });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
struct BatchedSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitments_query: CommitmentsQueryResult<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
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
    ) {
        self.oracle_query.check_merkle_paths(roots);
        self.commitments_query.check_merkle_paths(
            comms
                .iter()
                .map(|comm| comm.root())
                .collect_vec()
                .as_slice(),
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

            let (x0, x1, w) = Spec::EncodingScheme::verifier_folding_coeffs(
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
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
    ) {
        let timer = start_timer!(|| "BatchedQueriesResult::check");
        self.inner
            .iter()
            .zip(indices.iter())
            .for_each(|((index, query), index_in_proof)| {
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
                );
            });
        end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
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
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
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
    pub fn check_merkle_path(&self, root: &Digest<E::BaseField>) {
        // let timer = start_timer!(|| "CodewordSingleQuery::Check Merkle Path");
        match &self.query.leaves {
            SimpleBatchLeavesPair::Ext(inner) => {
                self.merkle_path.authenticate_batch_leaves_root_ext(
                    inner.iter().map(|(x, _)| *x).collect(),
                    inner.iter().map(|(_, x)| *x).collect(),
                    self.query.index,
                    root,
                );
            }
            SimpleBatchLeavesPair::Base(inner) => {
                self.merkle_path.authenticate_batch_leaves_root_base(
                    inner.iter().map(|(x, _)| *x).collect(),
                    inner.iter().map(|(_, x)| *x).collect(),
                    self.query.index,
                    root,
                );
            }
        }
        // end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
struct SimpleBatchSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitment_query: SimpleBatchCommitmentSingleQueryResult<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
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
        commitment: &BasefoldCommitmentWithWitness<E>,
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
    ) {
        self.oracle_query.check_merkle_paths(roots);
        self.commitment_query
            .check_merkle_path(&Digest(comm.root().0));

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

pub struct SimpleBatchQueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SimpleBatchSingleQueryResult<E>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
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
        commitment: &BasefoldCommitmentWithWitness<E>,
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
    ) {
        self.inner
            .iter()
            .zip(indices.iter())
            .for_each(|((index, query), index_in_proof)| {
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
                );
            });
    }
}
