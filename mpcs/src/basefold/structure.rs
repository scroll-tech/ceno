use crate::util::merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree};
use core::fmt::Debug;
use ff_ext::{ExtensionField, PoseidonField};
use itertools::izip;
use p3::{
    commit::Mmcs,
    matrix::{Matrix, dense::DenseMatrix},
};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use sumcheck::structs::IOPProverMessage;

use multilinear_extensions::virtual_poly::ArcMultilinearExtension;

use std::marker::PhantomData;

pub type Digest<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment;
pub type MerkleTree<F> = <<F as PoseidonField>::MMCS as Mmcs<F>>::ProverData<DenseMatrix<F>>;
pub type MerkleTreeExt<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::ProverData<DenseMatrix<E>>;

pub use super::encoding::{EncodingProverParameters, EncodingScheme, RSCode, RSCodeDefaultSpec};

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
pub struct BasefoldCommitmentWithWitness<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) pi_d_digest: Digest<E>,
    pub(crate) codeword: MerkleTree<E::BaseField>,
    pub(crate) polynomials_bh_evals: Vec<Vec<ArcMultilinearExtension<'static, E>>>,
    // format Vec<(num_var, num_polys)>
    pub(crate) meta_info: Vec<(usize, usize)>,
}

impl<E: ExtensionField> BasefoldCommitmentWithWitness<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn to_commitment(&self) -> BasefoldCommitment<E> {
        BasefoldCommitment::new(self.pi_d_digest.clone(), self.meta_info.clone())
    }

    // pub fn poly_size(&self) -> usize {
    //     1 << self.num_vars
    // }

    // pub fn trivial_num_vars<Spec: BasefoldSpec<E>>(num_vars: usize) -> bool {
    //     num_vars <= Spec::get_basecode_msg_size_log()
    // }

    // pub fn is_trivial<Spec: BasefoldSpec<E>>(&self) -> bool {
    //     Self::trivial_num_vars::<Spec>(self.num_vars)
    // }

    pub fn codeword_size(&self) -> usize {
        let mmcs = poseidon2_merkle_tree::<E>();
        // size = height * 2 because we concat pi[left]/pi[right] under same row index
        mmcs.get_matrices(&self.codeword)[0].height() * 2
    }

    pub fn get_codewords(&self) -> &DenseMatrix<E::BaseField> {
        let mmcs = poseidon2_merkle_tree::<E>();
        mmcs.get_matrices(&self.codeword)[0]
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldCommitment<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(super) pi_d_digest: Digest<E>,
    pub(crate) meta_info: Vec<(usize, usize)>,
}

impl<E: ExtensionField> BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(pi_d_digest: Digest<E>, meta_info: Vec<(usize, usize)>) -> Self {
        Self {
            pi_d_digest,
            meta_info,
        }
    }

    pub fn pi_d_digest(&self) -> Digest<E> {
        self.pi_d_digest.clone()
    }

    // pub fn num_vars(&self) -> Option<usize> {
    //     self.num_vars
    // }
}

impl<E: ExtensionField> PartialEq for BasefoldCommitmentWithWitness<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn eq(&self, other: &Self) -> bool {
        self.get_codewords().eq(other.get_codewords())
            && izip!(&self.polynomials_bh_evals, &other.polynomials_bh_evals).all(
                |(bh_evals_a, bh_evals_b)| {
                    izip!(bh_evals_a, bh_evals_b).all(|(bh_evals_a, bh_evals_b)| {
                        bh_evals_a.evaluations() == bh_evals_b.evaluations()
                    })
                },
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
pub struct BasefoldRSParams;

impl<E: ExtensionField> BasefoldSpec<E> for BasefoldRSParams
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type EncodingScheme = RSCode<RSCodeDefaultSpec>;
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

pub type MKProofNTo1<F1, P> = (Vec<F1>, P);
// for 2 to 1, leaf layer just need one value, as the other can be interpolated from previous layer
pub type MKProof2To1<F1, P> = (F1, P);
pub type QueryOpeningProofs<E> = Vec<(
    MKProofNTo1<
        <E as ExtensionField>::BaseField,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<
            <E as ExtensionField>::BaseField,
        >>::Proof,
    >,
    Vec<
        MKProof2To1<
            E,
            <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<
                <E as ExtensionField>::BaseField,
            >>::Proof,
        >,
    >,
)>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) commits: Vec<Digest<E>>,
    pub(crate) final_message: Vec<E>,
    pub(crate) query_opening_proof: QueryOpeningProofs<E>,
    pub(crate) sumcheck_proof: Option<Vec<IOPProverMessage<E>>>,
    pub(crate) trivial_proof: Option<DenseMatrix<E::BaseField>>,
}

impl<E: ExtensionField> BasefoldProof<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn trivial(evals: DenseMatrix<E::BaseField>) -> Self {
        Self {
            sumcheck_messages: vec![],
            commits: vec![],
            final_message: vec![],
            query_opening_proof: Default::default(),
            sumcheck_proof: None,
            trivial_proof: Some(evals),
        }
    }

    pub fn is_trivial(&self) -> bool {
        self.trivial_proof.is_some()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldCommitPhaseProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) sumcheck_messages: Vec<Vec<E>>,
    pub(crate) commits: Vec<Digest<E>>,
    pub(crate) final_message: Vec<E>,
}
