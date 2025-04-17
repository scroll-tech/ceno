use crate::{
    basefold::log2_strict_usize,
    util::merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
};
use core::fmt::Debug;
use ff_ext::{ExtensionField, PoseidonField};
use itertools::{Itertools, izip};
use p3::{
    commit::Mmcs,
    matrix::{Matrix, dense::DenseMatrix},
};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use sumcheck::structs::IOPProverMessage;

use multilinear_extensions::virtual_poly::ArcMultilinearExtension;

use std::{collections::BTreeMap, marker::PhantomData};

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
    pub(crate) commit: Digest<E>,
    pub(crate) codeword: MerkleTree<E::BaseField>,

    pub(crate) log2_max_codeword_size: usize,
    // for small polynomials, the prover commits the entire polynomial as merkle leaves without encoding to codeword
    // the verifier performs direct checks on these leaves without requiring a proximity test.
    pub(crate) trivial_proofdata: BTreeMap<usize, (Digest<E>, MerkleTree<E::BaseField>)>,
    // poly groups w.r.t circuit index
    pub(crate) polys: BTreeMap<usize, Vec<ArcMultilinearExtension<'static, E>>>,
    // keep codeword index w.r.t circuit index
    pub circuit_codeword_index: BTreeMap<usize, usize>,
}

impl<E: ExtensionField> BasefoldCommitmentWithWitness<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(
        commit: Digest<E>,
        codeword: MerkleTree<E::BaseField>,
        polys: BTreeMap<usize, Vec<ArcMultilinearExtension<'static, E>>>,
        trivial_proofdata: BTreeMap<usize, (Digest<E>, MerkleTree<E::BaseField>)>,
        circuit_codeword_index: BTreeMap<usize, usize>,
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
            trivial_proofdata,
            circuit_codeword_index,
            log2_max_codeword_size,
        }
    }

    pub fn to_commitment(&self) -> BasefoldCommitment<E> {
        BasefoldCommitment::new(
            self.commit.clone(),
            self.trivial_proofdata
                .iter()
                .map(|(_, (digest, _))| digest.clone())
                .collect_vec(),
            self.log2_max_codeword_size,
        )
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
    pub(super) commit: Digest<E>,
    pub(crate) log2_max_codeword_size: usize,
    pub(crate) trivial_commits: Vec<Digest<E>>,
}

impl<E: ExtensionField> BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(
        commit: Digest<E>,
        trivial_commits: Vec<Digest<E>>,
        log2_max_codeword_size: usize,
    ) -> Self {
        Self {
            commit,
            trivial_commits,
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
            && izip!(self.polys.values(), other.polys.values()).all(|(evals_a, evals_b)| {
                izip!(evals_a, evals_b)
                    .all(|(evals_a, evals_b)| evals_a.evaluations() == evals_b.evaluations())
            })
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

pub type MKProofNTo1<F1, P> = (Vec<Vec<F1>>, P);
// for 2 to 1, leaf layer just need one value, as the other can be interpolated from previous layer
pub type MKProof2To1<F1, P> = (F1, P);
pub type QueryOpeningProofs<E> = Vec<(
    MKProofNTo1<
        <E as ExtensionField>::BaseField,
        <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<
            <E as ExtensionField>::BaseField,
        >>::Proof,
    >,
    Option<
        MKProofNTo1<
            <E as ExtensionField>::BaseField,
            <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<
                <E as ExtensionField>::BaseField,
            >>::Proof,
        >,
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

pub type TrivialProof<E> = Vec<Vec<DenseMatrix<<E as ExtensionField>::BaseField>>>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct BasefoldProof<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) commits: Vec<Digest<E>>,
    pub(crate) final_message: Vec<Vec<E>>,
    pub(crate) query_opening_proof: QueryOpeningProofs<E>,
    pub(crate) sumcheck_proof: Option<Vec<IOPProverMessage<E>>>,
    // vec![witness, fixed], where fixed is optional
    pub(crate) trivial_proof: Option<TrivialProof<E>>,
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
    pub(crate) sumcheck_messages: Vec<IOPProverMessage<E>>,
    pub(crate) commits: Vec<Digest<E>>,
    pub(crate) final_message: Vec<Vec<E>>,
}

#[derive(Clone, Default)]
pub(crate) struct CircuitIndexMeta {
    pub witin_num_vars: usize,
    pub witin_num_polys: usize,
    pub fixed_num_vars: usize,
    pub fixed_num_polys: usize,
}
