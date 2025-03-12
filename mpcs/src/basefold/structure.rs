use crate::sum_check::classic::{Coefficients, SumcheckProof};
use core::fmt::Debug;
use ff_ext::ExtensionField;

use itertools::izip;
use p3_matrix::{dense::RowMajorMatrix, extension::FlatMatrixView};
use p3_merkle_tree::MerkleTree as P3MerkleTree;
use p3_symmetric::Hash as P3Hash;
use poseidon::DIGEST_WIDTH;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};

use multilinear_extensions::{mle::FieldType, virtual_poly::ArcMultilinearExtension};

use std::marker::PhantomData;

pub type Digest<E: ExtensionField> = P3Hash<E::BaseField, E::BaseField, DIGEST_WIDTH>;
pub type MerkleTree<F> = P3MerkleTree<F, F, RowMajorMatrix<F>, DIGEST_WIDTH>;
pub type MerkleTreeExt<E: ExtensionField> = P3MerkleTree<
    E::BaseField,
    E::BaseField,
    FlatMatrixView<E::BaseField, E, RowMajorMatrix<E>>,
    DIGEST_WIDTH,
>;

pub use super::encoding::{EncodingProverParameters, EncodingScheme, RSCode, RSCodeDefaultSpec};
use super::query_phase::{
    BatchedQueriesResultWithMerklePath, QueriesResultWithMerklePath,
    SimpleBatchQueriesResultWithMerklePath,
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
#[derive(Debug)]
pub struct BasefoldCommitmentWithWitness<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) comm: Digest<E>,
    pub(crate) codeword: MerkleTree<E::BaseField>,
    pub(crate) polynomials_bh_evals: Vec<ArcMultilinearExtension<'static, E>>,
    pub(crate) num_vars: usize,
    pub(crate) is_base: bool,
    pub(crate) num_polys: usize,
}

impl<E: ExtensionField> BasefoldCommitmentWithWitness<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn to_commitment(&self) -> BasefoldCommitment<E> {
        BasefoldCommitment::new(
            self.comm.clone(),
            self.num_vars,
            self.is_base,
            self.num_polys,
        )
    }

    pub fn poly_size(&self) -> usize {
        1 << self.num_vars
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

// impl<E: ExtensionField> From<&BasefoldCommitmentWithWitness<E>> for BasefoldCommitment<E>
// where
//     E::BaseField: Serialize + DeserializeOwned,
// {
//     fn from(val: &BasefoldCommitmentWithWitness<E>) -> Self {
//         val.to_commitment()
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldCommitment<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(super) root: Digest<E>,
    pub(super) num_vars: Option<usize>,
    pub(super) is_base: bool,
    pub(super) num_polys: Option<usize>,
}

impl<E: ExtensionField> BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(root: Digest<E>, num_vars: usize, is_base: bool, num_polys: usize) -> Self {
        Self {
            root,
            num_vars: Some(num_vars),
            is_base,
            num_polys: Some(num_polys),
        }
    }

    pub fn root(&self) -> Digest<E> {
        self.root.clone()
    }

    pub fn num_vars(&self) -> Option<usize> {
        self.num_vars
    }

    pub fn is_base(&self) -> bool {
        self.is_base
    }
}

impl<E: ExtensionField> PartialEq for BasefoldCommitmentWithWitness<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn eq(&self, other: &Self) -> bool {
        self.get_codewords().eq(other.get_codewords())
            && izip!(&self.polynomials_bh_evals, &other.polynomials_bh_evals).all(
                |(bh_evals_a, bh_evals_b)| bh_evals_a.evaluations() == bh_evals_b.evaluations(),
            )
    }
}

impl<E: ExtensionField> Eq for BasefoldCommitmentWithWitness<E> where
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
    type EncodingScheme = RSCode<RSCodeDefaultSpec, E>;
}

#[derive(Debug)]
pub struct Basefold<E: ExtensionField, Spec: BasefoldSpec<E>>(PhantomData<(E, Spec)>);

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Serialize for Basefold<E, Spec> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("base_fold")
    }
}

pub type BasefoldDefault<F> = Basefold<F, BasefoldRSParams>;

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Clone for Basefold<E, Spec> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

// impl<E: ExtensionField> AsRef<[Digest<E::BaseField>]> for BasefoldCommitment<E>
// where
//     E::BaseField: Serialize + DeserializeOwned,
// {
//     fn as_ref(&self) -> &[Digest<E::BaseField>] {
//         let root = &self.root;
//         slice::from_ref(root)
//     }
// }

// impl<E: ExtensionField> AsRef<[Digest<E::BaseField>]> for BasefoldCommitmentWithWitness<E>
// where
//     E::BaseField: Serialize + DeserializeOwned,
// {
//     fn as_ref(&self) -> &[Digest<E::BaseField>] {
//         let root = self.get_root_ref();
//         slice::from_ref(root)
//     }
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
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
    pub fn as_single(&self) -> &QueriesResultWithMerklePath<E> {
        match self {
            Self::Single(x) => x,
            _ => panic!("Not a single query result"),
        }
    }

    pub fn as_batched(&self) -> &BatchedQueriesResultWithMerklePath<E> {
        match self {
            Self::Batched(x) => x,
            _ => panic!("Not a batched query result"),
        }
    }

    pub fn as_simple_batched(&self) -> &SimpleBatchQueriesResultWithMerklePath<E> {
        match self {
            Self::SimpleBatched(x) => x,
            _ => panic!("Not a simple batched query result"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E>>,
    pub(crate) final_message: Vec<E>,
    pub(crate) query_result_with_merkle_path: ProofQueriesResultWithMerklePath<E>,
    pub(crate) sumcheck_proof: Option<SumcheckProof<E, Coefficients<E>>>,
    pub(crate) trivial_proof: Vec<FieldType<E>>,
}

impl<E: ExtensionField> BasefoldProof<E>
where
    E::BaseField: Serialize + DeserializeOwned,
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
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldCommitPhaseProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) roots: Vec<Digest<E>>,
    pub(crate) final_message: Vec<E>,
}
