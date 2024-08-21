use crate::util::{hash::Digest, merkle_tree::MerkleTree};
use core::fmt::Debug;
use ff_ext::ExtensionField;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use multilinear_extensions::mle::FieldType;

use rand_chacha::rand_core::RngCore;
use std::{marker::PhantomData, slice};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldParams<E: ExtensionField, Rng: RngCore>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(super) log_rate: usize,
    pub(super) num_verifier_queries: usize,
    pub(super) max_num_vars: usize,
    pub(super) table_w_weights: Vec<Vec<(E::BaseField, E::BaseField)>>,
    pub(super) table: Vec<Vec<E::BaseField>>,
    pub(super) rng: Rng,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldProverParams<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(super) log_rate: usize,
    pub(super) table_w_weights: Vec<Vec<(E::BaseField, E::BaseField)>>,
    pub(super) table: Vec<Vec<E::BaseField>>,
    pub(super) num_verifier_queries: usize,
    pub(super) max_num_vars: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldVerifierParams<Rng: RngCore> {
    pub(super) rng: Rng,
    pub(super) max_num_vars: usize,
    pub(super) log_rate: usize,
    pub(super) num_verifier_queries: usize,
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

    pub fn batch_codewords(&self, coeffs: &Vec<E>) -> Vec<E> {
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

impl<E: ExtensionField> Into<Digest<E::BaseField>> for BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn into(self) -> Digest<E::BaseField> {
        self.get_root_as()
    }
}

impl<E: ExtensionField> Into<BasefoldCommitment<E>> for &BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn into(self) -> BasefoldCommitment<E> {
        self.to_commitment()
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

pub trait BasefoldExtParams: Debug {
    fn get_reps() -> usize;

    fn get_rate() -> usize;

    fn get_basecode() -> usize;
}

#[derive(Debug)]
pub struct BasefoldDefaultParams;

impl BasefoldExtParams for BasefoldDefaultParams {
    fn get_reps() -> usize {
        return 260;
    }

    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode() -> usize {
        return 7;
    }
}

#[derive(Debug)]
pub struct Basefold<E: ExtensionField, V: BasefoldExtParams>(PhantomData<(E, V)>);

pub type BasefoldDefault<F> = Basefold<F, BasefoldDefaultParams>;

impl<E: ExtensionField, V: BasefoldExtParams> Clone for Basefold<E, V> {
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
