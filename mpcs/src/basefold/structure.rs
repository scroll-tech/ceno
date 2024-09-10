use crate::{
    sum_check::classic::{Coefficients, SumcheckProof},
    util::{hash::Digest, merkle_tree::MerkleTree},
};
use core::fmt::Debug;
use ff_ext::ExtensionField;

use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use multilinear_extensions::mle::FieldType;

use rand_chacha::ChaCha8Rng;
use std::{marker::PhantomData, slice};

pub use super::encoding::{EncodingProverParameters, EncodingScheme, RSCode, RSCodeDefaultSpec};
use super::{
    query_phase::{
        BatchedQueriesResultWithMerklePath, QueriesResultWithMerklePath,
        SimpleBatchQueriesResultWithMerklePath,
    },
    Basecode, BasecodeDefaultSpec,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldParams<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(super) params: <Spec::EncodingScheme as EncodingScheme<E>>::PublicParameters,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldProverParams<E: ExtensionField, Spec: BasefoldSpec<E>> {
    pub encoding_params: <Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldProverParams<E, Spec> {
    pub fn get_max_message_size_log(&self) -> usize {
        self.encoding_params.get_max_message_size_log()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldVerifierParams<E: ExtensionField, Spec: BasefoldSpec<E>> {
    pub(super) encoding_params: <Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
}

/// A polynomial commitment together with all the data (e.g., the codeword, and Merkle tree)
/// used to generate this commitment and for assistant in opening
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "E: Serialize", deserialize = "E: DeserializeOwned"))]
pub struct BasefoldCommitmentWithData<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) codeword_tree: MerkleTree<E>,
    pub(crate) polynomials_bh_evals: Vec<FieldType<E>>,
    pub(crate) num_vars: usize,
    pub(crate) is_base: bool,
    pub(crate) num_polys: usize,
}

impl<E: ExtensionField> BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn to_commitment(&self) -> BasefoldCommitment<E> {
        BasefoldCommitment::new(
            self.codeword_tree.root(),
            self.num_vars,
            self.is_base,
            self.num_polys,
        )
    }

    pub fn get_root_ref(&self) -> &Digest<E::BaseField> {
        self.codeword_tree.root_ref()
    }

    pub fn get_root_as(&self) -> Digest<E::BaseField> {
        Digest::<E::BaseField>(self.get_root_ref().0)
    }

    pub fn get_codewords(&self) -> &Vec<FieldType<E>> {
        self.codeword_tree.leaves()
    }

    pub fn batch_codewords(&self, coeffs: &[E]) -> Vec<E> {
        self.codeword_tree.batch_leaves(coeffs)
    }

    pub fn codeword_size(&self) -> usize {
        self.codeword_tree.size().1
    }

    pub fn codeword_size_log(&self) -> usize {
        self.codeword_tree.height()
    }

    pub fn poly_size(&self) -> usize {
        1 << self.num_vars
    }

    pub fn get_codeword_entry_base(&self, index: usize) -> Vec<E::BaseField> {
        self.codeword_tree.get_leaf_as_base(index)
    }

    pub fn get_codeword_entry_ext(&self, index: usize) -> Vec<E> {
        self.codeword_tree.get_leaf_as_extension(index)
    }

    pub fn is_base(&self) -> bool {
        self.is_base
    }
}

impl<E: ExtensionField> From<BasefoldCommitmentWithData<E>> for Digest<E::BaseField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn from(val: BasefoldCommitmentWithData<E>) -> Self {
        val.get_root_as()
    }
}

impl<E: ExtensionField> From<&BasefoldCommitmentWithData<E>> for BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn from(val: &BasefoldCommitmentWithData<E>) -> Self {
        val.to_commitment()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldCommitment<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(super) root: Digest<E::BaseField>,
    pub(super) num_vars: Option<usize>,
    pub(super) is_base: bool,
    pub(super) num_polys: Option<usize>,
}

impl<E: ExtensionField> BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(
        root: Digest<E::BaseField>,
        num_vars: usize,
        is_base: bool,
        num_polys: usize,
    ) -> Self {
        Self {
            root,
            num_vars: Some(num_vars),
            is_base,
            num_polys: Some(num_polys),
        }
    }

    pub fn root(&self) -> Digest<E::BaseField> {
        self.root.clone()
    }

    pub fn num_vars(&self) -> Option<usize> {
        self.num_vars
    }

    pub fn is_base(&self) -> bool {
        self.is_base
    }
}

impl<E: ExtensionField> PartialEq for BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn eq(&self, other: &Self) -> bool {
        self.get_codewords().eq(other.get_codewords())
            && self.polynomials_bh_evals.eq(&other.polynomials_bh_evals)
    }
}

impl<E: ExtensionField> Eq for BasefoldCommitmentWithData<E> where
    E::BaseField: Serialize + DeserializeOwned
{
}

pub trait BasefoldSpec<E: ExtensionField>: Debug + Clone {
    type EncodingScheme: EncodingScheme<E>;

    fn get_number_queries() -> usize {
        Self::EncodingScheme::get_number_queries()
    }

    fn get_rate_log() -> usize {
        Self::EncodingScheme::get_rate_log()
    }

    fn get_basecode_msg_size_log() -> usize {
        Self::EncodingScheme::get_basecode_msg_size_log()
    }
}

#[derive(Debug, Clone)]
pub struct BasefoldBasecodeParams;

impl<E: ExtensionField> BasefoldSpec<E> for BasefoldBasecodeParams
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type EncodingScheme = Basecode<BasecodeDefaultSpec>;
}

#[derive(Debug, Clone)]
pub struct BasefoldRSParams;

impl<E: ExtensionField> BasefoldSpec<E> for BasefoldRSParams
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type EncodingScheme = RSCode<RSCodeDefaultSpec>;
}

#[derive(Debug)]
pub struct Basefold<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore>(
    PhantomData<(E, Spec, Rng)>,
);

pub type BasefoldDefault<F> = Basefold<F, BasefoldRSParams, ChaCha8Rng>;

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore> Clone for Basefold<E, Spec, Rng> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<E: ExtensionField> AsRef<[Digest<E::BaseField>]> for BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn as_ref(&self) -> &[Digest<E::BaseField>] {
        let root = &self.root;
        slice::from_ref(root)
    }
}

impl<E: ExtensionField> AsRef<[Digest<E::BaseField>]> for BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn as_ref(&self) -> &[Digest<E::BaseField>] {
        let root = self.get_root_ref();
        slice::from_ref(root)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofQueriesResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    Single(QueriesResultWithMerklePath<E>),
    Batched(BatchedQueriesResultWithMerklePath<E>),
    SimpleBatched(SimpleBatchQueriesResultWithMerklePath<E>),
}

impl<E: ExtensionField> ProofQueriesResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn as_single<'a>(&'a self) -> &'a QueriesResultWithMerklePath<E> {
        match self {
            Self::Single(x) => x,
            _ => panic!("Not a single query result"),
        }
    }

    pub fn as_batched<'a>(&'a self) -> &'a BatchedQueriesResultWithMerklePath<E> {
        match self {
            Self::Batched(x) => x,
            _ => panic!("Not a batched query result"),
        }
    }

    pub fn as_simple_batched<'a>(&'a self) -> &'a SimpleBatchQueriesResultWithMerklePath<E> {
        match self {
            Self::SimpleBatched(x) => x,
            _ => panic!("Not a simple batched query result"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasefoldProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E::BaseField>>,
    pub(crate) final_message: Vec<E>,
    pub(crate) query_result_with_merkle_path: ProofQueriesResultWithMerklePath<E>,
    pub(crate) sumcheck_proof: Option<SumcheckProof<E, Coefficients<E>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasefoldCommitPhaseProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E::BaseField>>,
    pub(crate) final_message: Vec<E>,
}
