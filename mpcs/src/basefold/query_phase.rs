use super::basecode::{encode_rs_basecode, query_point};
use crate::util::{
    arithmetic::{
        degree_2_eval, degree_2_zero_plus_one, inner_product, interpolate2,
        interpolate_over_boolean_hypercube,
    },
    ext_to_usize,
    hash::{Digest, Hasher},
    log2_strict,
    merkle_tree::{MerklePathWithoutLeafOrRoot, MerkleTree},
    transcript::{TranscriptRead, TranscriptWrite},
};
use aes::cipher::KeyIvInit;
use ark_std::{end_timer, start_timer};
use core::fmt::Debug;
use ctr;
use ff_ext::ExtensionField;
use generic_array::GenericArray;

use itertools::Itertools;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use multilinear_extensions::mle::FieldType;

use crate::util::plonky2_util::{reverse_bits, reverse_index_bits_in_place};
use rand_chacha::{rand_core::RngCore, ChaCha8Rng};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

use super::structure::{BasefoldCommitment, BasefoldCommitmentWithData};

pub fn query_phase<E: ExtensionField>(
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    comm: &BasefoldCommitmentWithData<E>,
    oracles: &Vec<Vec<E>>,
    num_verifier_queries: usize,
) -> QueriesResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let queries = transcript.squeeze_challenges(num_verifier_queries);

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
                    basefold_get_query::<E>(comm.get_codeword(), &oracles, *x_index),
                )
            })
            .collect(),
    }
}

fn basefold_get_query<E: ExtensionField>(
    poly_codeword: &FieldType<E>,
    oracles: &Vec<Vec<E>>,
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

    let mut oracle_queries = Vec::with_capacity(oracles.len() + 1);
    for oracle in oracles {
        let p1 = index | 1;
        let p0 = p1 - 1;

        oracle_queries.push(CodewordSingleQueryResult::new_ext(
            oracle[p0], oracle[p1], p0,
        ));
        index >>= 1;
    }

    let oracle_query = OracleListQueryResult {
        inner: oracle_queries,
    };

    return SingleQueryResult {
        oracle_query,
        commitment_query,
    };
}

fn batch_basefold_get_query<E: ExtensionField>(
    comms: &[&BasefoldCommitmentWithData<E>],
    oracles: &Vec<Vec<E>>,
    codeword_size: usize,
    x_index: usize,
) -> BatchedSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut oracle_list_queries = Vec::with_capacity(oracles.len());

    let mut index = x_index;
    index >>= 1;
    for oracle in oracles {
        let p1 = index | 1;
        let p0 = p1 - 1;
        oracle_list_queries.push(CodewordSingleQueryResult::<E>::new_ext(
            oracle[p0], oracle[p1], p0,
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
            match comm.get_codeword() {
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

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum CodewordPointPair<E: ExtensionField> {
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
struct CodewordSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    codepoints: CodewordPointPair<E>,
    index: usize,
}

impl<E: ExtensionField> CodewordSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn new_ext(left: E, right: E, index: usize) -> Self {
        Self {
            codepoints: CodewordPointPair::Ext(left, right),
            index,
        }
    }

    fn new_base(left: E::BaseField, right: E::BaseField, index: usize) -> Self {
        Self {
            codepoints: CodewordPointPair::Base(left, right),
            index,
        }
    }

    fn left_ext(&self) -> E {
        match &self.codepoints {
            CodewordPointPair::Ext(x, _) => *x,
            CodewordPointPair::Base(x, _) => E::from(*x),
        }
    }

    fn right_ext(&self) -> E {
        match &self.codepoints {
            CodewordPointPair::Ext(_, y) => *y,
            CodewordPointPair::Base(_, y) => E::from(*y),
        }
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        match self.codepoints {
            CodewordPointPair::Ext(x, y) => {
                transcript.write_field_element_ext(&x).unwrap();
                transcript.write_field_element_ext(&y).unwrap();
            }
            CodewordPointPair::Base(x, y) => {
                transcript.write_field_element_base(&x).unwrap();
                transcript.write_field_element_base(&y).unwrap();
            }
        };
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self::new_ext(
            transcript.read_field_element_ext().unwrap(),
            transcript.read_field_element_ext().unwrap(),
            index >> (full_codeword_size_log - codeword_size_log),
        )
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self::new_base(
            transcript.read_field_element_base().unwrap(),
            transcript.read_field_element_base().unwrap(),
            index >> (full_codeword_size_log - codeword_size_log),
        )
    }
}

#[derive(Debug, Clone)]
struct CodewordSingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    query: CodewordSingleQueryResult<E>,
    merkle_path: MerklePathWithoutLeafOrRoot<E>,
}

impl<E: ExtensionField> CodewordSingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.query.write_transcript(transcript);
        self.merkle_path.write_transcript(transcript);
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self {
            query: CodewordSingleQueryResult::read_transcript_base(
                transcript,
                full_codeword_size_log,
                codeword_size_log,
                index,
            ),
            merkle_path: MerklePathWithoutLeafOrRoot::read_transcript(
                transcript,
                codeword_size_log,
            ),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self {
            query: CodewordSingleQueryResult::read_transcript_ext(
                transcript,
                full_codeword_size_log,
                codeword_size_log,
                index,
            ),
            merkle_path: MerklePathWithoutLeafOrRoot::read_transcript(
                transcript,
                codeword_size_log,
            ),
        }
    }

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
struct OracleListQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResult<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitmentsQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResult<E>>,
}

#[derive(Debug, Clone)]
struct OracleListQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>,
}

impl<E: ExtensionField> OracleListQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn read_transcript(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        // Remember that the prover doesn't send the commitment in the last round.
        // In the first round, the oracle is sent after folding, so the first oracle
        // has half the size of the full codeword size.
        Self {
            inner: (0..num_rounds - 1)
                .map(|round| {
                    CodewordSingleQueryResultWithMerklePath::read_transcript_ext(
                        transcript,
                        codeword_size_log,
                        codeword_size_log - round - 1,
                        index,
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct CommitmentsQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>,
}

impl<E: ExtensionField> CommitmentsQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        max_num_vars: usize,
        poly_num_vars: &[usize],
        log_rate: usize,
        index: usize,
    ) -> Self {
        Self {
            inner: poly_num_vars
                .iter()
                .map(|num_vars| {
                    CodewordSingleQueryResultWithMerklePath::read_transcript_base(
                        transcript,
                        max_num_vars + log_rate,
                        num_vars + log_rate,
                        index,
                    )
                })
                .collect(),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        max_num_vars: usize,
        poly_num_vars: &[usize],
        log_rate: usize,
        index: usize,
    ) -> Self {
        Self {
            inner: poly_num_vars
                .iter()
                .map(|num_vars| {
                    CodewordSingleQueryResultWithMerklePath::read_transcript_ext(
                        transcript,
                        max_num_vars + log_rate,
                        num_vars + log_rate,
                        index,
                    )
                })
                .collect(),
        }
    }
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
            .into_iter()
            .enumerate()
            .map(|(i, query_result)| {
                let path = path(i, query_result.index);
                path
            })
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
                .zip(query_result.get_inner_into().into_iter())
                .map(
                    |(path, codeword_result)| CodewordSingleQueryResultWithMerklePath {
                        query: codeword_result,
                        merkle_path: path,
                    },
                )
                .collect_vec(),
        )
    }

    fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.get_inner()
            .iter()
            .for_each(|q| q.write_transcript(transcript));
    }

    fn check_merkle_paths(&self, roots: &Vec<Digest<E::BaseField>>, hasher: &Hasher<E::BaseField>) {
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

#[derive(Debug, Clone)]
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
        oracle_trees: &Vec<MerkleTree<E>>,
        commitment: &BasefoldCommitmentWithData<E>,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::from_query_and_trees(
                single_query_result.oracle_query,
                |i, j| oracle_trees[i].merkle_path_without_leaf_sibling_or_root(j),
            ),
            commitment_query: CodewordSingleQueryResultWithMerklePath {
                query: single_query_result.commitment_query.clone(),
                merkle_path: commitment
                    .codeword_tree
                    .merkle_path_without_leaf_sibling_or_root(
                        single_query_result.commitment_query.index,
                    ),
            },
        }
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.oracle_query.write_transcript(transcript);
        self.commitment_query.write_transcript(transcript);
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        num_vars: usize,
        index: usize,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                num_vars + log_rate,
                index,
            ),
            commitment_query: CodewordSingleQueryResultWithMerklePath::read_transcript_base(
                transcript,
                num_vars + log_rate,
                num_vars + log_rate,
                index,
            ),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        num_vars: usize,
        index: usize,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                num_vars + log_rate,
                index,
            ),
            commitment_query: CodewordSingleQueryResultWithMerklePath::read_transcript_ext(
                transcript,
                num_vars + log_rate,
                num_vars + log_rate,
                index,
            ),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comm: &BasefoldCommitment<E>,
        mut cipher: ctr::Ctr32LE<aes::Aes128>,
        index: usize,
        hasher: &Hasher<E::BaseField>,
    ) {
        // let timer = start_timer!(|| "Checking codeword single query");
        self.oracle_query.check_merkle_paths(roots, hasher);
        self.commitment_query
            .check_merkle_path(&Digest(comm.root().0.try_into().unwrap()), hasher);

        let (mut curr_left, mut curr_right) = self.commitment_query.query.codepoints.as_ext();

        let mut right_index = index | 1;
        let mut left_index = right_index - 1;

        for i in 0..num_rounds {
            // let round_timer = start_timer!(|| format!("SingleQueryResult::round {}", i));
            let ri0 = reverse_bits(left_index, num_vars + log_rate - i);

            let x0 = E::from(query_point::<E>(
                1 << (num_vars + log_rate - i),
                ri0,
                num_vars + log_rate - i - 1,
                &mut cipher,
            ));
            let x1 = -x0;

            let res = interpolate2([(x0, curr_left), (x1, curr_right)], fold_challenges[i]);

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchedSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitments_query: CommitmentsQueryResult<E>,
}

#[derive(Debug, Clone)]
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
        oracle_trees: &Vec<MerkleTree<E>>,
        commitments: &Vec<&BasefoldCommitmentWithData<E>>,
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

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.oracle_query.write_transcript(transcript);
        self.commitments_query.write_transcript(transcript);
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        index: usize,
    ) -> Self {
        let num_vars = poly_num_vars.iter().max().unwrap();
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                *num_vars + log_rate,
                index,
            ),
            commitments_query: CommitmentsQueryResultWithMerklePath::read_transcript_base(
                transcript,
                *num_vars,
                poly_num_vars,
                log_rate,
                index,
            ),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        index: usize,
    ) -> Self {
        let num_vars = poly_num_vars.iter().max().unwrap();
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                *num_vars + log_rate,
                index,
            ),
            commitments_query: CommitmentsQueryResultWithMerklePath::read_transcript_ext(
                transcript,
                *num_vars,
                poly_num_vars,
                log_rate,
                index,
            ),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comms: &Vec<&BasefoldCommitment<E>>,
        coeffs: &[E],
        mut cipher: ctr::Ctr32LE<aes::Aes128>,
        index: usize,
        hasher: &Hasher<E::BaseField>,
    ) {
        self.oracle_query.check_merkle_paths(roots, hasher);
        self.commitments_query
            .check_merkle_paths(&comms.iter().map(|comm| comm.root()).collect(), hasher);
        // end_timer!(commit_timer);

        let mut curr_left = E::ZERO;
        let mut curr_right = E::ZERO;

        let mut right_index = index | 1;
        let mut left_index = right_index - 1;

        for i in 0..num_rounds {
            // let round_timer = start_timer!(|| format!("BatchedSingleQueryResult::round {}", i));
            let ri0 = reverse_bits(left_index, num_vars + log_rate - i);
            let matching_comms = comms
                .iter()
                .enumerate()
                .filter(|(_, comm)| comm.num_vars().unwrap() == num_vars - i)
                .map(|(index, _)| index)
                .collect_vec();

            matching_comms.iter().for_each(|index| {
                let query = self.commitments_query.get_inner()[*index].query.clone();
                assert_eq!(query.index >> 1, left_index >> 1);
                curr_left += query.left_ext() * coeffs[*index];
                curr_right += query.right_ext() * coeffs[*index];
            });

            let x0: E = E::from(query_point::<E>(
                1 << (num_vars + log_rate - i),
                ri0,
                num_vars + log_rate - i - 1,
                &mut cipher,
            ));
            let x1 = -x0;

            let mut res = interpolate2([(x0, curr_left), (x1, curr_right)], fold_challenges[i]);

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
                        self.commitments_query.get_inner()[*index].query.clone();
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

pub struct BatchedQueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, BatchedSingleQueryResult<E>)>,
}

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
        oracle_trees: &Vec<MerkleTree<E>>,
        commitments: &Vec<&BasefoldCommitmentWithData<E>>,
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

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.inner
            .iter()
            .for_each(|(_, q)| q.write_transcript(transcript));
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        BatchedSingleQueryResultWithMerklePath::read_transcript_base(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        BatchedSingleQueryResultWithMerklePath::read_transcript_ext(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comms: &Vec<&BasefoldCommitment<E>>,
        coeffs: &[E],
        cipher: ctr::Ctr32LE<aes::Aes128>,
        hasher: &Hasher<E::BaseField>,
    ) {
        let timer = start_timer!(|| "BatchedQueriesResult::check");
        self.inner.par_iter().for_each(|(index, query)| {
            query.check(
                fold_challenges,
                num_rounds,
                num_vars,
                log_rate,
                final_codeword,
                roots,
                comms,
                coeffs,
                cipher.clone(),
                *index,
                hasher,
            );
        });
        end_timer!(timer);
    }
}

pub struct QueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SingleQueryResult<E>)>,
}

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
    pub fn from_query_result(
        query_result: QueriesResult<E>,
        oracle_trees: &Vec<MerkleTree<E>>,
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

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.inner
            .iter()
            .for_each(|(_, q)| q.write_transcript(transcript));
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: usize,
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        SingleQueryResultWithMerklePath::read_transcript_base(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: usize,
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        SingleQueryResultWithMerklePath::read_transcript_ext(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comm: &BasefoldCommitment<E>,
        cipher: ctr::Ctr32LE<aes::Aes128>,
        hasher: &Hasher<E::BaseField>,
    ) {
        let timer = start_timer!(|| "QueriesResult::check");
        self.inner.par_iter().for_each(|(index, query)| {
            query.check(
                fold_challenges,
                num_rounds,
                num_vars,
                log_rate,
                final_codeword,
                roots,
                comm,
                cipher.clone(),
                *index,
                hasher,
            );
        });
        end_timer!(timer);
    }
}

pub fn batch_query_phase<E: ExtensionField>(
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    codeword_size: usize,
    comms: &[&BasefoldCommitmentWithData<E>],
    oracles: &Vec<Vec<E>>,
    num_verifier_queries: usize,
) -> BatchedQueriesResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let queries = transcript.squeeze_challenges(num_verifier_queries);

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
                    batch_basefold_get_query::<E>(comms, &oracles, codeword_size, *x_index),
                )
            })
            .collect(),
    }
}

pub fn verifier_query_phase<E: ExtensionField>(
    queries: &QueriesResultWithMerklePath<E>,
    sum_check_messages: &Vec<Vec<E>>,
    fold_challenges: &Vec<E>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    final_message: &Vec<E>,
    roots: &Vec<Digest<E::BaseField>>,
    comm: &BasefoldCommitment<E>,
    partial_eq: &[E],
    rng: ChaCha8Rng,
    eval: &E,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier query phase");

    let encode_timer = start_timer!(|| "Encode final codeword");
    let mut message = final_message.clone();
    interpolate_over_boolean_hypercube(&mut message);
    let mut final_codeword = encode_rs_basecode(&message, 1 << log_rate, message.len());
    assert_eq!(final_codeword.len(), 1);
    let mut final_codeword = final_codeword.remove(0);
    reverse_index_bits_in_place(&mut final_codeword);
    end_timer!(encode_timer);

    // For computing the weights on the fly, because the verifier is incapable of storing
    // the weights.
    let aes_timer = start_timer!(|| "Initialize AES");
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );
    end_timer!(aes_timer);

    queries.check(
        fold_challenges,
        num_rounds,
        num_vars,
        log_rate,
        &final_codeword,
        roots,
        comm,
        cipher,
        hasher,
    );

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

pub fn batch_verifier_query_phase<E: ExtensionField>(
    queries: &BatchedQueriesResultWithMerklePath<E>,
    sum_check_messages: &Vec<Vec<E>>,
    fold_challenges: &Vec<E>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    final_message: &Vec<E>,
    roots: &Vec<Digest<E::BaseField>>,
    comms: &Vec<&BasefoldCommitment<E>>,
    coeffs: &[E],
    partial_eq: &[E],
    rng: ChaCha8Rng,
    eval: &E,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier batch query phase");
    let encode_timer = start_timer!(|| "Encode final codeword");
    let mut message = final_message.clone();
    interpolate_over_boolean_hypercube(&mut message);
    let mut final_codeword = encode_rs_basecode(&message, 1 << log_rate, message.len());
    assert_eq!(final_codeword.len(), 1);
    let mut final_codeword = final_codeword.remove(0);
    reverse_index_bits_in_place(&mut final_codeword);
    end_timer!(encode_timer);

    // For computing the weights on the fly, because the verifier is incapable of storing
    // the weights.
    let aes_timer = start_timer!(|| "Initialize AES");
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );
    end_timer!(aes_timer);

    queries.check(
        fold_challenges,
        num_rounds,
        num_vars,
        log_rate,
        &final_codeword,
        roots,
        comms,
        coeffs,
        cipher,
        hasher,
    );

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
