use ff_ext::{ExtensionField, PoseidonField};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    matrix::{
        Dimensions,
        dense::{DenseMatrix, RowMajorMatrix},
    },
};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use transcript::Transcript;

use crate::error::Error;

pub type Poseidon2BaseMerkleMmcs<E> = <<E as ExtensionField>::BaseField as PoseidonField>::MMCS;
pub type Poseidon2ExtMerkleMmcs<E> = ExtensionMmcs<
    <E as ExtensionField>::BaseField,
    E,
    <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
>;

#[derive(Clone)]
pub struct Poseidon2MerkleMmcs<E: ExtensionField> {
    pub(crate) base_mmcs: Poseidon2BaseMerkleMmcs<E>,
    pub(crate) ext_mmcs: Poseidon2ExtMerkleMmcs<E>,
}

impl<E: ExtensionField> Poseidon2MerkleMmcs<E> {
    pub fn commit_matrix_base(
        &self,
        matrix: RowMajorMatrix<E::BaseField>,
    ) -> (Digest<E>, MerkleTree<E>) {
        let (digest, merkle_tree) = self.base_mmcs.commit_matrix(matrix);
        (Digest::Base(digest), MerkleTree::Base(merkle_tree))
    }

    pub fn commit_matrix_ext(&self, matrix: RowMajorMatrix<E>) -> (Digest<E>, MerkleTree<E>) {
        let (digest, merkle_tree) = self.ext_mmcs.commit_matrix(matrix);
        (Digest::Ext(digest), MerkleTree::Ext(merkle_tree))
    }
}

pub fn poseidon2_base_merkle_tree<E: ExtensionField>() -> Poseidon2BaseMerkleMmcs<E> {
    <E::BaseField as PoseidonField>::get_default_mmcs()
}

pub fn poseidon2_ext_merkle_tree<E: ExtensionField>() -> Poseidon2ExtMerkleMmcs<E> {
    ExtensionMmcs::new(<E::BaseField as PoseidonField>::get_default_mmcs())
}

pub fn poseidon2_merkle_tree<E: ExtensionField>() -> Poseidon2MerkleMmcs<E> {
    Poseidon2MerkleMmcs {
        base_mmcs: poseidon2_base_merkle_tree::<E>(),
        ext_mmcs: poseidon2_ext_merkle_tree::<E>(),
    }
}

pub type MerklePathBase<E> =
    <Poseidon2BaseMerkleMmcs<E> as Mmcs<<E as ExtensionField>::BaseField>>::Proof;
pub type MerklePathExt<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Proof;
pub enum MerklePath<E: ExtensionField>
where
    E::BaseField: PoseidonField,
{
    Base(MerklePathBase<E>),
    Ext(MerklePathExt<E>),
}

pub type MultiPathBase<E> = Vec<(
    Vec<Vec<<E as ExtensionField>::BaseField>>,
    MerklePathBase<E>,
)>;
pub type MultiPathExt<E> = Vec<(Vec<Vec<E>>, MerklePathExt<E>)>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub enum MultiPath<E: ExtensionField>
where
    E::BaseField: PoseidonField,
{
    Base(MultiPathBase<E>),
    Ext(MultiPathExt<E>),
}

impl<E: ExtensionField> MultiPath<E> {
    pub fn answers_ext(&self) -> Vec<Vec<Vec<E>>> {
        match self {
            MultiPath::Base(paths) => paths
                .iter()
                .map(|(leaves, _)| {
                    leaves
                        .iter()
                        .map(|leaf| leaf.iter().map(|x| E::from_ref_base(x)).collect())
                        .collect()
                })
                .collect(),
            MultiPath::Ext(paths) => paths.iter().map(|(leaves, _)| leaves.clone()).collect(),
        }
    }
}

pub type MerkleTreeBase<E> = <Poseidon2BaseMerkleMmcs<E> as Mmcs<
    <E as ExtensionField>::BaseField,
>>::ProverData<DenseMatrix<<E as ExtensionField>::BaseField>>;
pub type MerkleTreeExt<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::ProverData<DenseMatrix<E>>;
pub enum MerkleTree<E: ExtensionField>
where
    E::BaseField: PoseidonField,
{
    Base(MerkleTreeBase<E>),
    Ext(MerkleTreeExt<E>),
}

pub type DigestBase<E> =
    <Poseidon2BaseMerkleMmcs<E> as Mmcs<<E as ExtensionField>::BaseField>>::Commitment;
pub type DigestExt<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "E: Serialize", deserialize = "E: DeserializeOwned"))]
pub enum Digest<E: ExtensionField>
where
    E::BaseField: PoseidonField,
{
    Base(DigestBase<E>),
    Ext(DigestExt<E>),
}

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E>,
    transcript: &mut impl Transcript<E>,
) where
    <Poseidon2BaseMerkleMmcs<E> as Mmcs<<E as ExtensionField>::BaseField>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    match digest {
        Digest::Base(digest) => {
            digest
                .clone()
                .into_iter()
                .for_each(|x| transcript.append_field_element(&x));
        }
        Digest::Ext(digest) => {
            digest
                .clone()
                .into_iter()
                .for_each(|x| transcript.append_field_element(&x));
        }
    }
}

pub fn generate_multi_proof<E: ExtensionField>(
    hash_params: &Poseidon2MerkleMmcs<E>,
    merkle_tree: &MerkleTree<E>,
    indices: &[usize],
) -> MultiPath<E>
where
    MerklePathBase<E>: Send + Sync,
    MerkleTreeBase<E>: Send + Sync,
    MerklePathExt<E>: Send + Sync,
    MerkleTreeExt<E>: Send + Sync,
{
    match merkle_tree {
        MerkleTree::Base(merkle_tree) => MultiPath::Base(
            indices
                .par_iter()
                .map(|index| hash_params.base_mmcs.open_batch(*index, merkle_tree))
                .collect(),
        ),
        MerkleTree::Ext(merkle_tree) => MultiPath::Ext(
            indices
                .par_iter()
                .map(|index| hash_params.ext_mmcs.open_batch(*index, merkle_tree))
                .collect(),
        ),
    }
}

pub fn verify_multi_proof<E: ExtensionField>(
    hash_params: &Poseidon2MerkleMmcs<E>,
    root: &Digest<E>,
    indices: &[usize],
    proof: &MultiPath<E>,
    matrix_height: usize,
) -> Result<(), Error>
where
    MerklePathExt<E>: Send + Sync,
    MerklePathBase<E>: Send + Sync,
    <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
        Send + Sync,
    <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
        Send + Sync,
{
    match (root, proof) {
        (Digest::<E>::Base(root), MultiPath::<E>::Base(proof)) => {
            let leaf_size = proof[0].0[0].len();
            indices
                .par_iter()
                .zip(proof.par_iter())
                .map(|(index, path)| {
                    hash_params.base_mmcs
                        .verify_batch(
                            root,
                            &[Dimensions {
                                width: leaf_size,
                                height: 1 << matrix_height,
                            }],
                            *index,
                            &path.0,
                            &path.1,
                        )
                        .map_err(|e| {
                            Error::MmcsError(format!(
                                "Failed to verify proof for index {}, leaf size {}, matrix height log {}, error: {:?}",
                                index, leaf_size, matrix_height, e
                            ))
                        })?;
                    Ok(())
                }).collect::<Result<Vec<()>, Error>>()?;
        }
        (Digest::<E>::Ext(root), MultiPath::<E>::Ext(proof)) => {
            let leaf_size = proof[0].0[0].len();
            indices
                .par_iter()
                .zip(proof.par_iter())
                .map(|(index, path)| {
                    hash_params.ext_mmcs
                        .verify_batch(
                            root,
                            &[Dimensions {
                                width: leaf_size,
                                height: 1 << matrix_height,
                            }],
                            *index,
                            &path.0,
                            &path.1,
                        )
                        .map_err(|e| {
                            Error::MmcsError(format!(
                                "Failed to verify proof for index {}, leaf size {}, matrix height log {}, error: {:?}",
                                index, leaf_size, matrix_height, e
                            ))
                        })?;
                    Ok(())
                }).collect::<Result<Vec<()>, Error>>()?;
        }
        _ => panic!("Mismatching Merkle root and proof types"),
    }
    Ok(())
}
