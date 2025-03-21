use ff_ext::{ExtensionField, PoseidonField};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    matrix::{Dimensions, dense::RowMajorMatrix, extension::FlatMatrixView},
    merkle_tree::{MerkleTree as P3MerkleTree, MerkleTreeMmcs},
    symmetric::{Hash as P3Hash, PaddingFreeSponge, TruncatedPermutation},
};
use poseidon::digest::DIGEST_WIDTH;
use transcript::Transcript;

use crate::error::Error;

pub(crate) type Poseidon2Sponge<P> = PaddingFreeSponge<P, 8, 4, 4>;
// TODO investigate compression setting legibility
pub(crate) type Poseidon2Compression<P> = TruncatedPermutation<P, 2, 4, 8>;
pub(crate) type Poseidon2MerkleMmcs<F> = MerkleTreeMmcs<
    F,
    F,
    Poseidon2Sponge<<F as PoseidonField>::T>,
    Poseidon2Compression<<F as PoseidonField>::T>,
    DIGEST_WIDTH,
>;
pub type Poseidon2ExtMerkleMmcs<E: ExtensionField> =
    ExtensionMmcs<E::BaseField, E, Poseidon2MerkleMmcs<E::BaseField>>;

pub fn poseidon2_merkle_tree<E: ExtensionField>() -> Poseidon2MerkleMmcs<E::BaseField> {
    MerkleTreeMmcs::new(
        Poseidon2Sponge::new(<E::BaseField as PoseidonField>::get_perm()),
        Poseidon2Compression::new(<E::BaseField as PoseidonField>::get_perm()),
    )
}

pub fn poseidon2_ext_merkle_tree<E: ExtensionField>() -> Poseidon2ExtMerkleMmcs<E> {
    ExtensionMmcs::new(poseidon2_merkle_tree::<E>())
}

pub type Digest<E: ExtensionField> = P3Hash<E::BaseField, E::BaseField, DIGEST_WIDTH>;
pub type MerkleTree<F> = P3MerkleTree<F, F, RowMajorMatrix<F>, DIGEST_WIDTH>;
pub type MerkleTreeExt<E: ExtensionField> = P3MerkleTree<
    E::BaseField,
    E::BaseField,
    FlatMatrixView<E::BaseField, E, RowMajorMatrix<E>>,
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
