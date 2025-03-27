use ff_ext::{ExtensionField, PoseidonField};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    matrix::{Dimensions, dense::RowMajorMatrix, extension::FlatMatrixView},
    merkle_tree::{MerkleTree as P3MerkleTree, MerkleTreeMmcs},
    symmetric::Hash as P3Hash,
};
use poseidon::digest::DIGEST_WIDTH;
use transcript::Transcript;

use crate::error::Error;

pub(crate) type Poseidon2MerkleMmcs<F> =
    MerkleTreeMmcs<F, F, <F as PoseidonField>::S, <F as PoseidonField>::C, DIGEST_WIDTH>;
pub type Poseidon2ExtMerkleMmcs<E> = ExtensionMmcs<
    <E as ExtensionField>::BaseField,
    E,
    Poseidon2MerkleMmcs<<E as ExtensionField>::BaseField>,
>;

pub fn poseidon2_merkle_tree<E: ExtensionField>() -> Poseidon2MerkleMmcs<E::BaseField> {
    MerkleTreeMmcs::new(
        <E::BaseField as PoseidonField>::get_default_sponge(),
        <E::BaseField as PoseidonField>::get_default_compression(),
    )
}

pub fn poseidon2_ext_merkle_tree<E: ExtensionField>() -> Poseidon2ExtMerkleMmcs<E> {
    ExtensionMmcs::new(poseidon2_merkle_tree::<E>())
}

pub type Digest<E> =
    P3Hash<<E as ExtensionField>::BaseField, <E as ExtensionField>::BaseField, DIGEST_WIDTH>;
pub type MerkleTree<F> = P3MerkleTree<F, F, RowMajorMatrix<F>, DIGEST_WIDTH>;
pub type MerkleTreeExt<E> = P3MerkleTree<
    <E as ExtensionField>::BaseField,
    <E as ExtensionField>::BaseField,
    FlatMatrixView<<E as ExtensionField>::BaseField, E, RowMajorMatrix<E>>,
    DIGEST_WIDTH,
>;
pub type MerklePathExt<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Proof;
pub type MultiPath<E> = Vec<(Vec<Vec<E>>, MerklePathExt<E>)>;

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E>,
    transcript: &mut impl Transcript<E>,
) {
    digest
        .as_ref()
        .iter()
        .for_each(|x| transcript.append_field_element(x));
}

pub fn generate_multi_proof<E: ExtensionField>(
    hash_params: &Poseidon2ExtMerkleMmcs<E>,
    merkle_tree: &MerkleTreeExt<E>,
    indices: &[usize],
) -> MultiPath<E> {
    indices
        .iter()
        .map(|index| hash_params.open_batch(*index, merkle_tree))
        .collect()
}

pub fn verify_multi_proof<E: ExtensionField>(
    hash_params: &Poseidon2ExtMerkleMmcs<E>,
    root: &Digest<E>,
    indices: &[usize],
    values: &[Vec<E>],
    proof: &MultiPath<E>,
    leaf_size: usize,
    matrix_height: usize,
) -> Result<(), Error> {
    for ((index, path), value) in indices.iter().zip(proof.iter()).zip(values.iter()) {
        hash_params
            .verify_batch(
                root,
                &[Dimensions {
                    width: leaf_size,
                    height: 1 << matrix_height,
                }],
                *index,
                &[value.clone()],
                &path.1,
            )
            .map_err(|e| {
                Error::MmcsError(format!(
                    "Failed to verify proof for index {}, leaf size {}, matrix height log {}, error: {:?}",
                    index, leaf_size, matrix_height, e
                ))
            })?
    }
    Ok(())
}
