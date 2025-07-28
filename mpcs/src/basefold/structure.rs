use crate::{
    PCSFriParam, SecurityLevel,
    basefold::log2_strict_usize,
    util::merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
};
use core::fmt::Debug;
use ff_ext::{ExtensionField, PoseidonField};
use itertools::izip;
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    fri::{BatchOpening, CommitPhaseProofStep},
    matrix::{Matrix, dense::DenseMatrix},
};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use sumcheck::structs::IOPProverMessage;

use multilinear_extensions::mle::ArcMultilinearExtension;
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
    pub(crate) security_level: SecurityLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldProverParams<E: ExtensionField, Spec: BasefoldSpec<E>> {
    pub encoding_params: <Spec::EncodingScheme as EncodingScheme<E>>::ProverParameters,
    pub(super) security_level: SecurityLevel,
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldProverParams<E, Spec> {
    pub fn get_max_message_size_log(&self) -> usize {
        self.encoding_params.get_max_message_size_log()
    }
}

macro_rules! impl_pcs_fri_param {
    ($type_name:ident) => {
        impl<E: ExtensionField, Spec: BasefoldSpec<E>> PCSFriParam for $type_name<E, Spec> {
            // refer security bit setting from https://github.com/openvm-org/stark-backend/blob/92171baab084b7aaeabc659d0e616cd93a3fdea4/crates/stark-sdk/src/config/fri_params.rs#L59
            fn get_pow_bits_by_level(&self, pow_strategy: crate::PowStrategy) -> usize {
                match (
                    &self.security_level,
                    pow_strategy,
                    <Spec::EncodingScheme as EncodingScheme<E>>::get_rate_log(),
                    <Spec::EncodingScheme as EncodingScheme<E>>::get_number_queries(),
                ) {
                    (SecurityLevel::Conjecture100bits, crate::PowStrategy::FriPow, 1, 100) => 16,
                    _ => unimplemented!(),
                }
            }
        }
    };
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldVerifierParams<E: ExtensionField, Spec: BasefoldSpec<E>> {
    pub(super) encoding_params: <Spec::EncodingScheme as EncodingScheme<E>>::VerifierParameters,
    pub(super) security_level: SecurityLevel,
}

impl_pcs_fri_param!(BasefoldProverParams);
impl_pcs_fri_param!(BasefoldVerifierParams);

/// A polynomial commitment together with all the data (e.g., the codeword, and Merkle tree)
/// used to generate this commitment and for assistant in opening
pub struct BasefoldCommitmentWithWitness<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub commit: Digest<E>,
    pub codeword: MerkleTree<E::BaseField>,

    pub log2_max_codeword_size: usize,
    pub polys: Vec<Vec<ArcMultilinearExtension<'static, E>>>,
}

impl<E: ExtensionField> BasefoldCommitmentWithWitness<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(
        commit: Digest<E>,
        codeword: MerkleTree<E::BaseField>,
        polys: Vec<Vec<ArcMultilinearExtension<'static, E>>>,
    ) -> Self {
        let mmcs = poseidon2_merkle_tree::<E>();
        // size = height * 2 because we split codeword leafs into left/right, concat and commit under same row index
        let log2_max_codeword_size = log2_strict_usize(
            mmcs.get_matrices(&codeword)
                .iter()
                .map(|m| m.height() * 2)
                .max()
                .unwrap(),
        );
        Self {
            commit,
            codeword,
            polys,
            log2_max_codeword_size,
        }
    }

    pub fn to_commitment(&self) -> BasefoldCommitment<E> {
        BasefoldCommitment::new(self.commit.clone(), self.log2_max_codeword_size)
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

    pub fn get_codewords(&self) -> Vec<&DenseMatrix<E::BaseField>> {
        let mmcs = poseidon2_merkle_tree::<E>();
        mmcs.get_matrices(&self.codeword)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldCommitment<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub commit: Digest<E>,
    pub log2_max_codeword_size: usize,
}

impl<E: ExtensionField> BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(commit: Digest<E>, log2_max_codeword_size: usize) -> Self {
        Self {
            commit,
            log2_max_codeword_size,
        }
    }

    pub fn commit(&self) -> Digest<E> {
        self.commit.clone()
    }
}

impl<E: ExtensionField> PartialEq for BasefoldCommitmentWithWitness<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn eq(&self, other: &Self) -> bool {
        izip!(self.get_codewords(), other.get_codewords())
            .all(|(codeword_a, codeword_b)| codeword_a.eq(codeword_b))
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

pub type ExtMmcs<E> = ExtensionMmcs<
    <E as ExtensionField>::BaseField,
    E,
    <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct QueryOpeningProof<E: ExtensionField> {
    pub input_proofs: Vec<
        BatchOpening<
            <E as ExtensionField>::BaseField,
            <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
        >,
    >,
    pub commit_phase_openings: Vec<CommitPhaseProofStep<E, ExtMmcs<E>>>,
}

pub type QueryOpeningProofs<E> = Vec<QueryOpeningProof<E>>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub commits: Vec<Digest<E>>,
    pub final_message: Vec<Vec<E>>,
    pub query_opening_proof: QueryOpeningProofs<E>,
    pub sumcheck_proof: Option<Vec<IOPProverMessage<E>>>,
    pub pow_witness: E::BaseField,
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
    pub sumcheck_messages: Vec<IOPProverMessage<E>>,
    pub commits: Vec<Digest<E>>,
    pub final_message: Vec<Vec<E>>,
}
