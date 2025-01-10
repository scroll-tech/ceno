use crate::{
    sum_check::classic::{Coefficients, SumcheckProof},
    util::{hash::Digest, merkle_tree::MerkleTree},
};
use core::fmt::Debug;
use ff_ext::ExtensionField;

use p3_mds::MdsPermutation;
use poseidon::SPONGE_WIDTH;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};

use multilinear_extensions::mle::FieldType;

use std::{marker::PhantomData, slice};

pub use super::encoding::{EncodingProverParameters, EncodingScheme, RSCode, RSCodeDefaultSpec};
use super::{
    Basecode, BasecodeDefaultSpec,
    query_phase::{
        BatchedQueriesResultWithMerklePath, QueriesResultWithMerklePath,
        SimpleBatchQueriesResultWithMerklePath,
    },
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
#[derive(Clone, Debug, Default)]
pub struct BasefoldCommitmentWithWitness<E: ExtensionField, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    pub(crate) codeword_tree: MerkleTree<E, Mds>,
    pub(crate) polynomials_bh_evals: Vec<FieldType<E>>,
    pub(crate) num_vars: usize,
    pub(crate) is_base: bool,
    pub(crate) num_polys: usize,
}

impl<E: ExtensionField, Mds> BasefoldCommitmentWithWitness<E, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
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

    pub fn trivial_num_vars<Spec: BasefoldSpec<E>>(num_vars: usize) -> bool {
        num_vars <= Spec::get_basecode_msg_size_log()
    }

    pub fn is_trivial<Spec: BasefoldSpec<E>>(&self) -> bool {
        Self::trivial_num_vars::<Spec>(self.num_vars)
    }
}

impl<E: ExtensionField, Mds> From<BasefoldCommitmentWithWitness<E, Mds>> for Digest<E::BaseField>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    fn from(val: BasefoldCommitmentWithWitness<E, Mds>) -> Self {
        val.get_root_as()
    }
}

impl<E: ExtensionField, Mds> From<&BasefoldCommitmentWithWitness<E, Mds>> for BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    fn from(val: &BasefoldCommitmentWithWitness<E, Mds>) -> Self {
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

impl<E: ExtensionField, Mds> PartialEq for BasefoldCommitmentWithWitness<E, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    fn eq(&self, other: &Self) -> bool {
        self.get_codewords().eq(other.get_codewords())
            && self.polynomials_bh_evals.eq(&other.polynomials_bh_evals)
    }
}

impl<E: ExtensionField, Mds> Eq for BasefoldCommitmentWithWitness<E, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
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
pub struct Basefold<E: ExtensionField, Spec: BasefoldSpec<E>, Mds>(PhantomData<(E, Spec, Mds)>);

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Mds> Serialize for Basefold<E, Spec, Mds> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("base_fold")
    }
}

pub type BasefoldDefault<F, Mds> = Basefold<F, BasefoldRSParams, Mds>;

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Mds> Clone for Basefold<E, Spec, Mds> {
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

impl<E: ExtensionField, Mds> AsRef<[Digest<E::BaseField>]> for BasefoldCommitmentWithWitness<E, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    fn as_ref(&self) -> &[Digest<E::BaseField>] {
        let root = self.get_root_ref();
        slice::from_ref(root)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum ProofQueriesResultWithMerklePath<E: ExtensionField, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    Single(QueriesResultWithMerklePath<E, Mds>),
    Batched(BatchedQueriesResultWithMerklePath<E, Mds>),
    SimpleBatched(SimpleBatchQueriesResultWithMerklePath<E, Mds>),
}

impl<E: ExtensionField, Mds> ProofQueriesResultWithMerklePath<E, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    pub fn as_single(&self) -> &QueriesResultWithMerklePath<E, Mds> {
        match self {
            Self::Single(x) => x,
            _ => panic!("Not a single query result"),
        }
    }

    pub fn as_batched(&self) -> &BatchedQueriesResultWithMerklePath<E, Mds> {
        match self {
            Self::Batched(x) => x,
            _ => panic!("Not a batched query result"),
        }
    }

    pub fn as_simple_batched(&self) -> &SimpleBatchQueriesResultWithMerklePath<E, Mds> {
        match self {
            Self::SimpleBatched(x) => x,
            _ => panic!("Not a simple batched query result"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BasefoldProof<E: ExtensionField, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E::BaseField>>,
    pub(crate) final_message: Vec<E>,
    pub(crate) query_result_with_merkle_path: ProofQueriesResultWithMerklePath<E, Mds>,
    pub(crate) sumcheck_proof: Option<SumcheckProof<E, Coefficients<E>>>,
    pub(crate) trivial_proof: Vec<FieldType<E>>,
}

impl<E: ExtensionField, Mds> BasefoldProof<E, Mds>
where
    E::BaseField: Serialize + DeserializeOwned,
    Mds: MdsPermutation<E::BaseField, SPONGE_WIDTH> + Default,
{
    pub fn trivial(evals: Vec<FieldType<E>>) -> Self {
        Self {
            sumcheck_messages: vec![],
            roots: vec![],
            final_message: vec![],
            query_result_with_merkle_path: ProofQueriesResultWithMerklePath::Single(
                QueriesResultWithMerklePath::empty(),
            ),
            sumcheck_proof: None,
            trivial_proof: evals,
        }
    }

    pub fn is_trivial(&self) -> bool {
        !self.trivial_proof.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BasefoldCommitPhaseProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E::BaseField>>,
    pub(crate) final_message: Vec<E>,
}
