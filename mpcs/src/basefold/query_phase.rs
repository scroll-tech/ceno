use crate::util::{
    arithmetic::{
        degree_2_eval, degree_2_zero_plus_one, inner_product, interpolate2_weights,
        interpolate_over_boolean_hypercube,
    },
    ext_to_usize,
    hash::{Digest, Hasher},
    merkle_tree::{MerklePathWithoutLeafOrRoot, MerkleTree},
};
use ark_std::{end_timer, start_timer};
use core::fmt::Debug;
use ff_ext::ExtensionField;
use itertools::Itertools;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use transcript::Transcript;

use multilinear_extensions::mle::FieldType;

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rayon::{
    iter::IndexedParallelIterator,
    prelude::{IntoParallelRefIterator, ParallelIterator},
};

use super::{
    encoding::EncodingScheme,
    structure::{BasefoldCommitment, BasefoldCommitmentWithData, BasefoldSpec},
};

pub fn prover_query_phase<E: ExtensionField>(
    transcript: &mut Transcript<E>,
    comm: &BasefoldCommitmentWithData<E>,
    trees: &[MerkleTree<E>],
    num_verifier_queries: usize,
) -> QueriesResult<E>
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

    QueriesResult {
        inner: queries_usize
            .par_iter()
            .map(|x_index| {
                (
                    *x_index,
                    basefold_get_query::<E>(&comm.get_codewords()[0], trees, *x_index),
                )
            })
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    indices: &[usize],
    vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    queries: &QueriesResultWithMerklePath<E>,
    sum_check_messages: &[Vec<E>],
    fold_challenges: &[E],
    num_rounds: usize,
    num_vars: usize,
    final_message: &[E],
    roots: &[Digest<E::BaseField>],
    comm: &BasefoldCommitment<E>,
    partial_eq: &[E],
    eval: &E,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier query phase");

    let encode_timer = start_timer!(|| "Encode final codeword");
    let mut message = final_message.to_vec();
    interpolate_over_boolean_hypercube(&mut message);
    if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
        reverse_index_bits_in_place(&mut message);
    }
    let final_codeword =
        <Spec::EncodingScheme as EncodingScheme<E>>::encode_small(vp, &FieldType::Ext(message));
    let mut final_codeword = match final_codeword {
        FieldType::Ext(final_codeword) => final_codeword,
        _ => panic!("Final codeword must be extension field"),
    };
    reverse_index_bits_in_place(&mut final_codeword);
    end_timer!(encode_timer);

    let queries_timer = start_timer!(|| format!("Check {} queries", indices.len()));
    queries.check::<Spec>(
        indices,
        vp,
        fold_challenges,
        num_rounds,
        num_vars,
        &final_codeword,
        roots,
        comm,
        hasher,
    );
    end_timer!(queries_timer);

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

fn basefold_get_query<E: ExtensionField>(
    poly_codeword: &FieldType<E>,
    trees: &[MerkleTree<E>],
    x_index: usize,
) -> SingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut index = x_index;
    let p1 = index | 1;
    let p0 = p1 - 1;

    let commitment_query = match poly_codeword {
        FieldType::Ext(poly_codeword) => {
            CodewordSingleQueryResult::new_ext(poly_codeword[p0], poly_codeword[p1], p0)
        }
        FieldType::Base(poly_codeword) => {
            CodewordSingleQueryResult::new_base(poly_codeword[p0], poly_codeword[p1], p0)
        }
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

    SingleQueryResult {
        oracle_query,
        commitment_query,
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub(crate) enum CodewordPointPair<E: ExtensionField> {
    Ext(E, E),
    Base(E::BaseField, E::BaseField),
}

impl<E: ExtensionField> CodewordPointPair<E> {
    pub fn as_ext(&self) -> (E, E) {
        match self {
            CodewordPointPair::Ext(x, y) => (*x, *y),
            CodewordPointPair::Base(x, y) => (E::from(*x), E::from(*y)),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub(crate) struct CodewordSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) codepoints: CodewordPointPair<E>,
    pub(crate) index: usize,
}

impl<E: ExtensionField> CodewordSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn new_ext(left: E, right: E, index: usize) -> Self {
        Self {
            codepoints: CodewordPointPair::Ext(left, right),
            index,
        }
    }

    pub(crate) fn new_base(left: E::BaseField, right: E::BaseField, index: usize) -> Self {
        Self {
            codepoints: CodewordPointPair::Base(left, right),
            index,
        }
    }

    pub(crate) fn left_ext(&self) -> E {
        match &self.codepoints {
            CodewordPointPair::Ext(x, _) => *x,
            CodewordPointPair::Base(x, _) => E::from(*x),
        }
    }

    pub(crate) fn right_ext(&self) -> E {
        match &self.codepoints {
            CodewordPointPair::Ext(_, y) => *y,
            CodewordPointPair::Base(_, y) => E::from(*y),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CodewordSingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) query: CodewordSingleQueryResult<E>,
    pub(crate) merkle_path: MerklePathWithoutLeafOrRoot<E>,
}

impl<E: ExtensionField> CodewordSingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn check_merkle_path(&self, root: &Digest<E::BaseField>, hasher: &Hasher<E::BaseField>) {
        // let timer = start_timer!(|| "CodewordSingleQuery::Check Merkle Path");
        match self.query.codepoints {
            CodewordPointPair::Ext(left, right) => {
                self.merkle_path.authenticate_leaves_root_ext(
                    left,
                    right,
                    self.query.index,
                    root,
                    hasher,
                );
            }
            CodewordPointPair::Base(left, right) => {
                self.merkle_path.authenticate_leaves_root_base(
                    left,
                    right,
                    self.query.index,
                    root,
                    hasher,
                );
            }
        }
        // end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleListQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) inner: Vec<CodewordSingleQueryResult<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CommitmentsQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) inner: Vec<CodewordSingleQueryResult<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleListQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CommitmentsQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>,
}

impl<E: ExtensionField> ListQueryResult<E> for OracleListQueryResult<E>
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

pub(crate) trait ListQueryResult<E: ExtensionField>
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

pub(crate) trait ListQueryResultWithMerklePath<E: ExtensionField>: Sized
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

    fn check_merkle_paths(&self, roots: &[Digest<E::BaseField>], hasher: &Hasher<E::BaseField>) {
        // let timer = start_timer!(|| "ListQuery::Check Merkle Path");
        self.get_inner()
            .iter()
            .zip(roots.iter())
            .for_each(|(q, root)| {
                q.check_merkle_path(root, hasher);
            });
        // end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitment_query: CodewordSingleQueryResult<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        commitment: &BasefoldCommitmentWithData<E>,
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
        hasher: &Hasher<E::BaseField>,
    ) {
        // let timer = start_timer!(|| "Checking codeword single query");
        self.oracle_query.check_merkle_paths(roots, hasher);
        self.commitment_query
            .check_merkle_path(&Digest(comm.root().0), hasher);

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
        commitment: &BasefoldCommitmentWithData<E>,
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
        hasher: &Hasher<E::BaseField>,
    ) {
        self.inner.par_iter().zip(indices.par_iter()).for_each(
            |((index, query), index_in_proof)| {
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
                    hasher,
                );
            },
        );
    }
}
