use crate::{
    sum_check::classic::{Coefficients, SumcheckProof},
    util::merkle_tree::{Hasher as MerkleTreeHasher, MerkleTree, PoseidonHasher},
};
use core::fmt::Debug;
use ff_ext::ExtensionField;

use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use multilinear_extensions::mle::FieldType;

use std::{marker::PhantomData, slice};

pub use super::encoding::{EncodingProverParameters, EncodingScheme, RSCode, RSCodeDefaultSpec};
use super::{query_phase::BasefoldQueriesResult, Basecode, BasecodeDefaultSpec};

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

impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldProverParams<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
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

type Digest<E, Spec> = <<Spec as BasefoldSpec<E>>::Hasher as MerkleTreeHasher<E>>::Digest;

/// A polynomial commitment together with all the data (e.g., the codeword, and Merkle tree)
/// used to generate this commitment and for assistant in opening
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "E: Serialize", deserialize = "E: DeserializeOwned"))]
pub struct BasefoldCommitmentWithData<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) codeword_tree: MerkleTree<E, Spec::Hasher>,
    pub(crate) polynomials_bh_evals: Vec<FieldType<E>>,
    pub(crate) num_vars: usize,
    pub(crate) is_base: bool,
    pub(crate) num_polys: usize,
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldCommitmentWithData<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn to_commitment(&self) -> BasefoldCommitment<E, Spec> {
        BasefoldCommitment::new(
            self.codeword_tree.root(),
            self.num_vars,
            self.is_base,
            self.num_polys,
        )
    }

    pub fn get_root_ref(&self) -> &Digest<E, Spec> {
        self.codeword_tree.root_ref()
    }

    pub fn get_root_as(&self) -> Digest<E, Spec> {
        self.get_root_ref().clone()
    }

    pub fn get_codewords(&self) -> &Vec<FieldType<E>> {
        self.codeword_tree.leaves()
    }

    pub fn batch_codewords(&self, coeffs: &[E]) -> Vec<E> {
        self.codeword_tree.batch_leaves(coeffs)
    }

    pub fn batch_codewords_at(&self, coeffs: &[E], index: usize) -> E {
        self.codeword_tree.batch_leaf(coeffs, index)
    }

    pub fn iter_batch_codewords<'a>(&'a self, coeffs: &'a [E]) -> impl Iterator<Item = E> + 'a {
        (0..self.codeword_size()).map(|i| {
            self.get_codeword_entry_ext(i)
                .iter()
                .zip(coeffs.iter())
                .map(|(a, b)| *a * b)
                .sum()
        })
    }

    pub fn par_iter_batch_codewords<'a>(
        &'a self,
        coeffs: &'a [E],
    ) -> impl ParallelIterator<Item = E> + IndexedParallelIterator + 'a {
        (0..self.codeword_size()).into_par_iter().map(|i| {
            self.get_codeword_entry_ext(i)
                .par_iter()
                .zip(coeffs.par_iter())
                .map(|(a, b)| *a * b)
                .sum()
        })
    }

    pub fn codeword_size(&self) -> usize {
        self.codeword_tree.leaves_size().1
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

    pub fn trivial_num_vars(num_vars: usize) -> bool {
        num_vars <= Spec::get_basecode_msg_size_log()
    }

    pub fn is_trivial(&self) -> bool {
        Self::trivial_num_vars(self.num_vars)
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> From<BasefoldCommitmentWithData<E, Spec>>
    for Digest<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn from(val: BasefoldCommitmentWithData<E, Spec>) -> Self {
        val.get_root_as()
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> From<&BasefoldCommitmentWithData<E, Spec>>
    for BasefoldCommitment<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn from(val: &BasefoldCommitmentWithData<E, Spec>) -> Self {
        val.to_commitment()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldCommitment<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(super) root: Digest<E, Spec>,
    pub(super) num_vars: Option<usize>,
    pub(super) is_base: bool,
    pub(super) num_polys: Option<usize>,
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldCommitment<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(root: Digest<E, Spec>, num_vars: usize, is_base: bool, num_polys: usize) -> Self {
        Self {
            root,
            num_vars: Some(num_vars),
            is_base,
            num_polys: Some(num_polys),
        }
    }

    pub fn root(&self) -> Digest<E, Spec> {
        self.root.clone()
    }

    pub fn root_ref(&self) -> &Digest<E, Spec> {
        &self.root
    }

    pub fn num_vars(&self) -> Option<usize> {
        self.num_vars
    }

    pub fn is_base(&self) -> bool {
        self.is_base
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> PartialEq for BasefoldCommitmentWithData<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn eq(&self, other: &Self) -> bool {
        self.get_codewords().eq(other.get_codewords())
            && self.polynomials_bh_evals.eq(&other.polynomials_bh_evals)
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Eq for BasefoldCommitmentWithData<E, Spec> where
    E::BaseField: Serialize + DeserializeOwned
{
}

pub trait BasefoldSpec<E: ExtensionField>: Debug + Clone + Default
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type EncodingScheme: EncodingScheme<E>;
    type Hasher: MerkleTreeHasher<E>;

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

#[derive(Debug, Clone, Default)]
pub struct BasefoldBasecodeParams;

impl<E: ExtensionField> BasefoldSpec<E> for BasefoldBasecodeParams
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type EncodingScheme = Basecode<BasecodeDefaultSpec>;
    type Hasher = PoseidonHasher;
}

#[derive(Debug, Clone, Default)]
pub struct BasefoldRSParams;

impl<E: ExtensionField> BasefoldSpec<E> for BasefoldRSParams
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type EncodingScheme = RSCode<RSCodeDefaultSpec>;
    type Hasher = PoseidonHasher;
}

#[derive(Debug)]
pub struct Basefold<E: ExtensionField, Spec: BasefoldSpec<E>>(PhantomData<(E, Spec)>)
where
    E::BaseField: Serialize + DeserializeOwned;

pub type BasefoldDefault<F> = Basefold<F, BasefoldRSParams>;

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Clone for Basefold<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> AsRef<[Digest<E, Spec>]>
    for BasefoldCommitment<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn as_ref(&self) -> &[Digest<E, Spec>] {
        let root = &self.root;
        slice::from_ref(root)
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> AsRef<[Digest<E, Spec>]>
    for BasefoldCommitmentWithData<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn as_ref(&self) -> &[Digest<E, Spec>] {
        let root = self.get_root_ref();
        slice::from_ref(root)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "E: Serialize", deserialize = "E: DeserializeOwned"))]
pub struct BasefoldProof<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E, Spec>>,
    pub(crate) final_message: Vec<E>,
    pub(crate) query_result: BasefoldQueriesResult<E, Spec>,
    pub(crate) sumcheck_proof: Option<SumcheckProof<E, Coefficients<E>>>,
    pub(crate) trivial_proof: Vec<FieldType<E>>,
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldProof<E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn trivial(evals: Vec<FieldType<E>>) -> Self {
        Self {
            sumcheck_messages: vec![],
            roots: vec![],
            final_message: vec![],
            query_result: BasefoldQueriesResult::empty(),
            sumcheck_proof: None,
            trivial_proof: evals,
        }
    }

    pub fn is_trivial(&self) -> bool {
        !self.trivial_proof.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasefoldCommitPhaseProof<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E, Spec>>,
    pub(crate) final_message: Vec<E>,
}
