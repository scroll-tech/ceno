use ff_ext::{ExtensionField, PoseidonField};
use p3::{
    commit::{ExtensionMmcs, Mmcs},
    matrix::{Dimensions, dense::DenseMatrix},
};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use transcript::Transcript;

use crate::error::Error;

pub type Poseidon2BaseMerkleMmcs<E> = <<E as ExtensionField>::BaseField as PoseidonField>::MMCS;
pub type Poseidon2ExtMerkleMmcs<E> = ExtensionMmcs<
    <E as ExtensionField>::BaseField,
    E,
    <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
>;

pub struct Poseidon2MerkleMmcs<E: ExtensionField> {
    pub(crate) base_mmcs: Poseidon2BaseMerkleMmcs<E>,
    pub(crate) ext_mmcs: Poseidon2ExtMerkleMmcs<E>,
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

pub type MultiPathBase<E> = Vec<(Vec<Vec<E>>, MerklePathBase<E>)>;
pub type MultiPathExt<E> = Vec<(Vec<Vec<E>>, MerklePathExt<E>)>;
pub enum MultiPath<E: ExtensionField>
where
    E::BaseField: PoseidonField,
{
    Base(MultiPathBase<E>),
    Ext(MultiPathExt<E>),
}

pub type MerkleTreeBase<E> = <Poseidon2BaseMerkleMmcs<E> as Mmcs<
    <E as ExtensionField>::BaseField,
>>::ProverData<DenseMatrix<E>>;
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
pub enum Digest<E: ExtensionField>
where
    E::BaseField: PoseidonField,
{
    Base(DigestBase<E>),
    Ext(DigestExt<E>),
}

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &DigestExt<E>,
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
) -> MultiPathExt<E>
where
    MerklePathExt<E>: Send + Sync,
    MerkleTreeExt<E>: Send + Sync,
{
    indices
        .par_iter()
        .map(|index| hash_params.open_batch(*index, merkle_tree))
        .collect()
}

pub fn verify_multi_proof<E: ExtensionField>(
    hash_params: &Poseidon2ExtMerkleMmcs<E>,
    root: &DigestExt<E>,
    indices: &[usize],
    proof: &MultiPathExt<E>,
    leaf_size: usize,
    matrix_height: usize,
) -> Result<(), Error>
where
    MerklePathExt<E>: Send + Sync,
    <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Commitment:
        Send + Sync,
    <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<E::BaseField>>::Proof:
        Send + Sync,
{
    indices
        .par_iter()
        .zip(proof.par_iter())
        .map(|(index, path)| {
            hash_params
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
    Ok(())
}
