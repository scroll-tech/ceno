use crate::util::{
    arithmetic::{
        degree_2_eval, degree_2_zero_plus_one, inner_product, interpolate_over_boolean_hypercube,
        interpolate2_weights,
    },
    ext_to_usize,
    hash::Digest,
    merkle_tree::{BatchLeavesPair, MerklePathWithoutLeafOrRoot, MerkleTree, SingleLeavesGroup},
};
use ark_std::{end_timer, start_timer};
use core::fmt::Debug;
use ff_ext::ExtensionField;
use itertools::Itertools;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
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

pub fn prover_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>>(
    transcript: &mut Transcript<E>,
    comms: &[BasefoldCommitmentWithData<E>],
    trees: &[MerkleTree<E>],
    num_verifier_queries: usize,
) -> BasefoldQueriesResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let num_vars = comms.iter().map(|c| c.num_vars).max().unwrap();
    let codeword_size = 1 << (num_vars + Spec::get_rate_log());
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

    BasefoldQueriesResult::get_queries_result(queries_usize.as_slice(), comms, trees, codeword_size)
}

#[allow(clippy::too_many_arguments)]
pub fn verifier_query_phase<E: ExtensionField, Spec: BasefoldSpec<E>, QCS: QueryCheckStrategy<E>>(
    indices: &[usize],
    vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    queries: &BasefoldQueriesResult<E>,
    sumcheck_messages: &[Vec<E>],
    fold_challenges: &[E],
    coeffs_outer: &[E],
    coeffs_inner: &[E],
    num_rounds: usize,
    num_vars: usize,
    final_message: &[E],
    roots: &[Digest<E::BaseField>],
    comms: &[BasefoldCommitment<E>],
    partial_eq: &[E],
    eval: &E,
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
    queries.check::<Spec, QCS>(
        indices,
        vp,
        fold_challenges,
        coeffs_outer,
        coeffs_inner,
        num_rounds,
        num_vars,
        &final_codeword,
        roots,
        comms,
    );
    end_timer!(queries_timer);

    let final_timer = start_timer!(|| "Final checks");
    assert_eq!(eval, &degree_2_zero_plus_one(&sumcheck_messages[0]));

    // The sum-check part of the protocol
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sumcheck_messages[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sumcheck_messages[i + 1])
        );
    }

    // Finally, the last sumcheck poly evaluation should be the same as the sum of the polynomial
    // sent from the prover
    assert_eq!(
        degree_2_eval(
            &sumcheck_messages[fold_challenges.len() - 1],
            fold_challenges[fold_challenges.len() - 1]
        ),
        inner_product(final_message, partial_eq)
    );
    end_timer!(final_timer);

    end_timer!(timer);
}

//////// -------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BasefoldQueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, BasefoldQueryResult<E>)>,
    _marker: PhantomData<E>,
}

impl<E: ExtensionField> BasefoldQueriesResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_queries_result(
        indices: &[usize],
        comms: &[BasefoldCommitmentWithData<E>],
        trees: &[MerkleTree<E>],
        codeword_size: usize,
    ) -> Self {
        BasefoldQueriesResult::<E> {
            inner: indices
                .par_iter()
                .map(|x_index| {
                    (
                        *x_index,
                        BasefoldQueryResult::get_query_result(
                            comms,
                            trees,
                            codeword_size,
                            *x_index,
                        ),
                    )
                })
                .collect(),
            _marker: PhantomData,
        }
    }

    pub fn empty() -> Self {
        Self {
            inner: vec![],
            _marker: PhantomData,
        }
    }

    pub fn check<Spec: BasefoldSpec<E>, QCS: QueryCheckStrategy<E>>(
        &self,
        indices: &[usize],
        vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
        fold_challenges: &[E],
        coeffs_outer: &[E],
        coeffs_inner: &[E],
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comms: &[BasefoldCommitment<E>],
    ) {
        self.inner.par_iter().zip(indices.par_iter()).for_each(
            |((index, query), index_in_proof)| {
                assert_eq!(index_in_proof, index);
                query.check::<Spec, QCS>(
                    vp,
                    fold_challenges,
                    coeffs_outer,
                    coeffs_inner,
                    num_rounds,
                    num_vars,
                    final_codeword,
                    roots,
                    comms,
                    *index,
                );
            },
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: SingleLeavesGroup<E>,
    merkle_path: MerklePathWithoutLeafOrRoot<E>,
}

impl<E: ExtensionField> OracleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn get_query_result(
        tree: &MerkleTree<E>,
        x_index: usize,
        full_codeword_size: usize,
    ) -> Self {
        let (leaves_width, leaves_num) = tree.leaves_size();
        let group_size = tree.leaf_group_size();
        let group_num = tree.leaf_group_num();
        let leaf_index = x_index / (full_codeword_size / leaves_num);
        let group_index = x_index / (full_codeword_size / group_num);

        if cfg!(feature = "sanity-check") {
            assert_eq!(leaves_width, 1);
            assert_eq!(full_codeword_size % leaves_num, 0);
            assert_eq!(group_size * group_num, leaves_num);
        }

        OracleQueryResult::<E> {
            inner: SingleLeavesGroup::from_all_leaves(group_index, group_size, &tree.leaves()[0]),
            merkle_path: tree.merkle_path_without_leaf_sibling_or_root(leaf_index),
        }
    }

    pub fn check_merkle_path(
        &self,
        root: &Digest<E::BaseField>,
        index: usize,
        full_codeword_size: usize,
    ) {
        let group_num = self.merkle_path.group_num();
        assert_eq!(full_codeword_size % group_num, 0);
        let group_index = index / (full_codeword_size / group_num);
        self.merkle_path
            .authenticate_leaves_group(&self.inner, group_index, root);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OraclesQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<OracleQueryResult<E>>,
}

impl<E: ExtensionField> OraclesQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn get_query_result(
        trees: &[MerkleTree<E>],
        full_codeword_size: usize,
        x_index: usize,
    ) -> Self {
        if cfg!(feature = "sanity-check") {
            assert!(x_index < full_codeword_size);
        }
        Self {
            inner: trees
                .iter()
                .map(|tree| OracleQueryResult::get_query_result(tree, x_index, full_codeword_size))
                .collect(),
        }
    }

    pub fn check_merkle_paths(
        &self,
        roots: &[Digest<E::BaseField>],
        index: usize,
        full_codeword_size: usize,
    ) {
        self.inner
            .par_iter()
            .zip(roots)
            .for_each(|(query, root)| query.check_merkle_path(root, index, full_codeword_size));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CommitmentQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: BatchLeavesPair<E>,
    merkle_path: MerklePathWithoutLeafOrRoot<E>,
}

impl<E: ExtensionField> CommitmentQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn height(&self) -> usize {
        self.merkle_path.height()
    }

    #[allow(unused)]
    pub fn group_num(&self) -> usize {
        1 << self.merkle_path.len()
    }

    #[allow(unused)]
    pub fn codeword_size(&self) -> usize {
        1 << self.codeword_size_log()
    }

    pub fn codeword_size_log(&self) -> usize {
        // The group size is guaranteed to be 2 for Merkle trees in commitments.
        // So the number of leaves is exactly 2^(merkle height)
        self.height()
    }

    pub fn get_query_result(
        comm: &BasefoldCommitmentWithData<E>,
        x_index: usize,
        full_codeword_size: usize,
    ) -> Self {
        let tree = &comm.codeword_tree;
        let (_, leaves_num) = tree.leaves_size();
        let group_size = tree.leaf_group_size();
        let group_num = tree.leaf_group_num();
        let leaf_index = x_index / (full_codeword_size / leaves_num);
        let group_index = x_index / (full_codeword_size / group_num);

        if cfg!(feature = "sanity-check") {
            assert_eq!(group_size, 2);
            assert_eq!(full_codeword_size % leaves_num, 0);
            assert_eq!(group_size * group_num, leaves_num);
        }

        Self {
            inner: BatchLeavesPair::from_all_leaves(
                group_index,
                tree.leaves().iter().collect::<Vec<_>>().as_slice(),
            ),
            merkle_path: tree.merkle_path_without_leaf_sibling_or_root(leaf_index),
        }
    }

    pub fn check_merkle_path(
        &self,
        comm: &BasefoldCommitment<E>,
        index: usize,
        full_codeword_size: usize,
    ) {
        let group_num = self.merkle_path.group_num();
        assert_eq!(full_codeword_size % group_num, 0);
        let group_index = index / (full_codeword_size / group_num);
        self.merkle_path
            .authenticate_batch_leaves_pair(&self.inner, group_index, comm.root_ref());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CommitmentsQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CommitmentQueryResult<E>>,
}

impl<E: ExtensionField> CommitmentsQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn get_query_result(
        comms: &[BasefoldCommitmentWithData<E>],
        full_codeword_size: usize,
        x_index: usize,
    ) -> Self {
        if cfg!(feature = "sanity-check") {
            assert!(x_index < full_codeword_size);
        }
        Self {
            inner: comms
                .iter()
                .map(|comm| {
                    CommitmentQueryResult::get_query_result(comm, x_index, full_codeword_size)
                })
                .collect(),
        }
    }

    pub fn check_merkle_paths(
        &self,
        comms: &[BasefoldCommitment<E>],
        index: usize,
        full_codeword_size: usize,
    ) {
        self.inner
            .par_iter()
            .zip(comms)
            .for_each(|(query, comm)| query.check_merkle_path(comm, index, full_codeword_size));
    }
}

pub(crate) trait QueryCheckStrategy<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_values(
        query_result: &BasefoldQueryResult<E>,
        coeffs_outer: &[E],
        coeffs_inner: &[E],
    ) -> Vec<E>;

    fn pre_update_values(
        query_result: &BasefoldQueryResult<E>,
        coeffs_outer: &[E],
        coeffs_inner: &[E],
        codeword_size_log: usize,
    ) -> Option<Vec<E>>;

    fn has_update_value_at_first_round() -> bool {
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BasefoldQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracles_query_result: OraclesQueryResult<E>,
    commitments_query_result: CommitmentsQueryResult<E>,
}

impl<E: ExtensionField> BasefoldQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    #[allow(unused)]
    pub fn get_commitments_query(&self) -> Vec<BatchLeavesPair<E>> {
        self.commitments_query_result
            .inner
            .iter()
            .map(|pair| pair.inner.clone())
            .collect()
    }

    #[allow(unused)]
    pub fn get_commitments_query_at(&self, index: usize) -> BatchLeavesPair<E> {
        self.commitments_query_result.inner[index].inner.clone()
    }

    pub fn get_commitments_query_matching_size_log(
        &self,
        codeword_size_log: usize,
    ) -> Vec<(usize, BatchLeavesPair<E>)> {
        self.commitments_query_result
            .inner
            .iter()
            .enumerate()
            .filter_map(|(index, pair)| {
                (pair.codeword_size_log() == codeword_size_log).then(|| (index, pair.inner.clone()))
            })
            .collect()
    }

    pub fn get_single_commitments_query(&self) -> BatchLeavesPair<E> {
        assert_eq!(self.commitments_query_result.inner.len(), 1);
        self.commitments_query_result
            .inner
            .first()
            .unwrap()
            .inner
            .clone()
    }

    #[allow(unused)]
    pub fn get_single_commitments_query_single_leave(&self) -> (E, E) {
        assert_eq!(self.commitments_query_result.inner.len(), 1);
        self.commitments_query_result
            .inner
            .first()
            .unwrap()
            .inner
            .clone()
            .single_leave_ext()
    }

    pub fn get_query_result(
        comms: &[BasefoldCommitmentWithData<E>],
        trees: &[MerkleTree<E>],
        codeword_size: usize,
        x_index: usize,
    ) -> Self {
        Self {
            oracles_query_result: OraclesQueryResult::get_query_result(
                trees,
                codeword_size,
                x_index,
            ),
            commitments_query_result: CommitmentsQueryResult::get_query_result(
                comms,
                codeword_size,
                x_index,
            ),
        }
    }

    pub fn check<Spec: BasefoldSpec<E>, QCS: QueryCheckStrategy<E>>(
        &self,
        vp: &<Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
        fold_challenges: &[E],
        coeffs_outer: &[E],
        coeffs_inner: &[E],
        num_rounds: usize,
        num_vars: usize,
        final_codeword: &[E],
        roots: &[Digest<E::BaseField>],
        comms: &[BasefoldCommitment<E>],
        index: usize,
    ) {
        let full_codeword_size_log = num_vars + Spec::get_rate_log();
        let full_codeword_size = 1 << full_codeword_size_log;
        self.oracles_query_result
            .check_merkle_paths(roots, index, full_codeword_size);
        self.commitments_query_result
            .check_merkle_paths(comms, index, full_codeword_size);

        // All the query checking algorithms (batched or not) have the same
        // pattern.
        // - Initialize the current values to fold (should always be 2 to start)
        // - For each round:
        //   - Update the current values somehow (needed when different poly
        //     sizes are there)
        //   - Fold the current values
        //   - If only one value left in the current values, it should be exactly
        //     the round for the next oracle. In this case, compare the folded
        //     value with the value opened in the oracle. Then replace the current
        //     values with the opened values in the oracle.
        //   - In the last round, the current values must be exactly folded to one
        //     value. Compare it with the corresponding entry in the final
        //     codeword.
        //   - The details of the above procedure are different for different
        //     opening algorithms, and are specified by the `QueryCheckStrategy`
        //     trait.

        let mut current_values = QCS::initial_values(self, coeffs_outer, coeffs_inner);
        let mut oracle_query_result = self
            .oracles_query_result
            .inner
            .iter()
            .map(|query| &query.inner);

        for (i, fold_challenge) in fold_challenges.iter().enumerate().take(num_rounds) {
            // let current_codeword_size = full_codeword_size >> i;
            let current_codeword_size_log = full_codeword_size_log - i;

            if let Some(update_values) =
                QCS::pre_update_values(self, coeffs_outer, coeffs_inner, current_codeword_size_log)
            {
                assert_eq!(
                    update_values.len(),
                    current_values.len(),
                    "There is something wrong with the round schedule. Trying to update the current value with mismatching size"
                );
                current_values
                    .iter_mut()
                    .zip(update_values)
                    .for_each(|(a, b)| *a += b);
            } else if i == 0 && QCS::has_update_value_at_first_round() {
                panic!("The first round should have an update value");
            }

            // Where are the current values in the current codeword?
            // let current_value_starting_index = index >> i;
            // Where are the folded values going to be in the next codeword?
            let next_value_starting_index = index >> (i + 1);

            // It is ensured that current_values.len() is always greater than 1
            // If it is folded into one value, then it will be compared against
            // the next oracle and immediately replaced with the opened values
            // in the next oracle.
            current_values = current_values
                .chunks_exact(2)
                .enumerate()
                .map(|(j, chunk)| {
                    // The position of this folded value in the next codeword
                    let index = next_value_starting_index + j;

                    let (x0, x1, w) =
                        <Spec::EncodingScheme as EncodingScheme<E>>::verifier_folding_coeffs(
                            vp,
                            num_vars + Spec::get_rate_log() - i - 1,
                            index,
                        );

                    interpolate2_weights([(x0, chunk[0]), (x1, chunk[1])], w, *fold_challenge)
                })
                .collect();

            // The next values are now current values
            let current_value_starting_index = next_value_starting_index;
            let current_codeword_size_log = current_codeword_size_log - 1;
            // let current_codeword_size = full_codeword_size >> (i + 1);
            if current_values.len() == 1 {
                // Time for the next oracle to come, which is possibly the
                // final codeword sent in clear.
                let oracle_query_result = oracle_query_result.next();
                if i < num_rounds - 1 {
                    // The next oracle is not the final codeword, so it must be
                    // opened.
                    let oracle_query_result = oracle_query_result
                        .expect("Something wrong with the oracle schedule, too few oracles");
                    assert_eq!(
                        current_values[0],
                        oracle_query_result
                            .get_ext(current_value_starting_index % oracle_query_result.len()),
                        "Current value different from what's read from the oracle"
                    );
                    current_values = oracle_query_result.as_ext();
                } else {
                    // Note that in the last round, res is folded to an element in the final
                    // codeword, but has not yet added the committed polynomial evaluations
                    // at this position.
                    // So we need to repeat the finding and adding procedure here.
                    // The reason for the existence of one extra find-and-add is that the number
                    // of different polynomial number of variables is one more than the number of
                    // rounds.
                    if let Some(update_values) = QCS::pre_update_values(
                        self,
                        coeffs_outer,
                        coeffs_inner,
                        current_codeword_size_log,
                    ) {
                        // There should be two update values (if any), but the
                        // current values are only one, because this update is
                        // happening after the folding. This is no longer a
                        // problem now because it's the last round and won't be
                        // folded any more. However, we only need one of them,
                        // i.e., the one at the same position of the only current
                        // value. This can be found out by the current index.
                        current_values[0] += update_values[current_value_starting_index % 2];
                    }

                    // This is the last round, so the next oracle must be empty
                    // Otherwise the oracle list contains extra oracle that is
                    // never used, which indicates a problem.
                    assert!(
                        oracle_query_result.is_none(),
                        "Something wrong with the oracle schedule, too many oracles"
                    );
                    assert_eq!(
                        current_values[0], final_codeword[current_value_starting_index],
                        "Current value different from the final oracle"
                    );
                }
            } else {
                // If the current values have not been folded into a single value
                // Then it shouldn't be the last round
                assert!(
                    i < num_rounds - 1,
                    "Something wrong with the round schedule, the current values have not been folded to a single value when the last round is reached"
                );
            }
        }
    }
}
