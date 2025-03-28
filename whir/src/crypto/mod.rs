use ff_ext::{ExtensionField, PoseidonField};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    matrix::{Dimensions, dense::DenseMatrix},
};
use transcript::Transcript;

use crate::error::Error;

pub type Poseidon2ExtMerkleMmcs<E> = ExtensionMmcs<
    <E as ExtensionField>::BaseField,
    E,
    <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
>;

pub fn poseidon2_ext_merkle_tree<E: ExtensionField>() -> Poseidon2ExtMerkleMmcs<E> {
    ExtensionMmcs::new(<E::BaseField as PoseidonField>::get_default_mmcs())
}

// pub type Digest<E> = <<E as ExtensionField>::BaseField as PoseidonField>::D;

pub type MerklePathExt<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Proof;
pub type MultiPath<E> = Vec<(Vec<Vec<E>>, MerklePathExt<E>)>;
pub type Digest<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment;
pub type MerkleTreeExt<E> = <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::ProverData<DenseMatrix<E>>;

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E>,
    transcript: &mut impl Transcript<E>,
) where
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    digest
        .clone()
        .into_iter()
        .for_each(|x| transcript.append_field_element(&x));
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
