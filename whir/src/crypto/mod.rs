use ff_ext::{ExtensionField, PoseidonField};
use lazy_static::lazy_static;
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, Permutation};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::atomic::AtomicUsize;

pub trait MerkleConfig<E: ExtensionField> {
    type Mmcs: Mmcs<E>;
}

pub struct MerkleTree<E: ExtensionField, Config: MerkleConfig<E>> {
    pub mmcs: <Config::Mmcs as Mmcs<E>>::ProverData<RowMajorMatrix<E>>,
}

impl<E: ExtensionField, Config: MerkleConfig<E>> MerkleTree<E, Config> {
    pub fn new(params: &Config::Mmcs, leaves: &[E], leaf_size: usize) -> Self {}

    pub fn root(&self) -> <Config::Mmcs as Mmcs<E>>::Commitment {}

    pub fn generate_multi_proof(&self, indices: &[usize]) -> MultiPath<E, Config> {}
}

/// A padding-free, overwrite-mode sponge function.
///
/// `WIDTH` is the sponge's rate plus the sponge's capacity.
#[derive(Clone)]
pub struct WhirHasher<E: ExtensionField, const RATE: usize, const OUT: usize> {
    permutation: <E::BaseField as PoseidonField>::T,
}

#[derive(Clone)]
pub struct WhirHasherBase<E: ExtensionField, const RATE: usize, const OUT: usize> {
    permutation: <E::BaseField as PoseidonField>::T,
}

impl<E: ExtensionField, const RATE: usize, const OUT: usize> WhirHasher<E, RATE, OUT> {
    pub const fn new(permutation: <E::BaseField as PoseidonField>::T) -> Self {
        Self { permutation }
    }
}

impl<E: ExtensionField, const RATE: usize, const OUT: usize> WhirHasherBase<E, RATE, OUT> {
    pub const fn new(permutation: <E::BaseField as PoseidonField>::T) -> Self {
        Self { permutation }
    }
}

impl<E: ExtensionField, const RATE: usize, const OUT: usize>
    CryptographicHasher<E, [E::BaseField; OUT]> for WhirHasher<E, RATE, OUT>
{
    fn hash_iter<I>(&self, input: I) -> [E::BaseField; OUT]
    where
        I: IntoIterator<Item = E>,
    {
        // static_assert(RATE < WIDTH)
        let mut state = [E::BaseField::ZERO; 8];
        let mut input = input
            .into_iter()
            .flat_map(|x| x.as_bases().iter())
            .map(|x| *x);

        // Itertools' chunks() is more convenient, but seems to add more overhead,
        // hence the more manual loop.
        'outer: loop {
            for i in 0..RATE {
                if let Some(x) = input.next() {
                    state[i] = x;
                } else {
                    if i != 0 {
                        self.permutation.permute_mut(&mut state);
                    }
                    break 'outer;
                }
            }
            self.permutation.permute_mut(&mut state);
        }

        state[..OUT].try_into().unwrap()
    }
}

impl<E: ExtensionField, const RATE: usize, const OUT: usize>
    CryptographicHasher<E::BaseField, [E::BaseField; OUT]> for WhirHasherBase<E, RATE, OUT>
{
    fn hash_iter<I>(&self, input: I) -> [E::BaseField; OUT]
    where
        I: IntoIterator<Item = E::BaseField>,
    {
        // static_assert(RATE < WIDTH)
        let mut state = [E::BaseField::ZERO; 8];
        let mut input = input.into_iter();

        // Itertools' chunks() is more convenient, but seems to add more overhead,
        // hence the more manual loop.
        'outer: loop {
            for i in 0..RATE {
                if let Some(x) = input.next() {
                    state[i] = x;
                } else {
                    if i != 0 {
                        self.permutation.permute_mut(&mut state);
                    }
                    break 'outer;
                }
            }
            self.permutation.permute_mut(&mut state);
        }

        state[..OUT].try_into().unwrap()
    }
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
                &[opened_values[i].clone()],
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
        WhirHasher<E, 4, 4>,
        CompressionFunctionFromHasher<WhirHasherBase<E, 4, 4>, 2, 4>,
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
