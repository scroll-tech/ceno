use std::{borrow::Borrow, marker::PhantomData, sync::atomic::AtomicUsize};

use ff_ext::{ExtensionField, PoseidonField};
use lazy_static::lazy_static;
use p3_commit::Mmcs;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::CompressionFunctionFromHasher;
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub trait MerkleConfig<E: ExtensionField> {
    type Mmcs: Mmcs<E>;
}

pub struct MerkleTree<E: ExtensionField, Config: MerkleConfig<E>> {
    pub mmcs: <Config::Mmcs as Mmcs<E>>::ProverData<RowMajorMatrix<E>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MultiPath<E: ExtensionField, Config: MerkleConfig<E>>
where
    E: Serialize + DeserializeOwned,
{
    pub path: Vec<<Config::Mmcs as Mmcs<E>>::Proof>,
}

impl<E: ExtensionField, Config: MerkleConfig<E>> MultiPath<E, Config> {
    pub fn verify(
        &self,
        hasher: &Config::Mmcs,
        commit: &<Config::Mmcs as Mmcs<E>>::Commitment,
        merkle_height: usize,
        leaf_size: usize,
        indices: &[usize],
        opened_values: &[Vec<E>],
    ) -> Result<(), crate::error::Error> {
        for (i, index) in indices.iter().enumerate() {
            Config::Mmcs::verify_batch(
                hasher,
                commit,
                &[Dimensions {
                    height: 1 << merkle_height,
                    width: leaf_size,
                }],
                *index,
                opened_values,
                &self.path[i],
            )
            .map_err(|err| crate::error::Error::MmcsError(format!("{:?}", err)))?;
        }
        Ok(())
    }
}

pub struct MerkleDefaultConfig<E: ExtensionField>
where
    E::BaseField: PoseidonField,
{
    hasher: <E::BaseField as PoseidonField>::T,
}

impl<E: ExtensionField> MerkleConfig<E> for MerkleDefaultConfig<E>
where
    E::BaseField: PoseidonField,
{
    type Mmcs = MerkleTreeMmcs<
        E,
        E::BaseField,
        <E::BaseField as PoseidonField>::T,
        CompressionFunctionFromHasher<<E::BaseField as PoseidonField>::T, 2, 4>,
        4,
    >;
}

impl<E: ExtensionField> MerkleDefaultConfig<E>
where
    E::BaseField: PoseidonField,
{
    pub fn new() -> Self {
        Self {
            hasher: <E::BaseField as PoseidonField>::get_perm(),
        }
    }
}

#[derive(Debug, Default)]
pub struct HashCounter {
    counter: AtomicUsize,
}

lazy_static! {
    static ref HASH_COUNTER: HashCounter = HashCounter::default();
}

impl HashCounter {
    pub(crate) fn add() -> usize {
        HASH_COUNTER
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn reset() {
        HASH_COUNTER
            .counter
            .store(0, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn get() -> usize {
        HASH_COUNTER
            .counter
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}
