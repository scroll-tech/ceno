use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::mle::FieldType;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
    },
    slice::ParallelSlice,
};

use crate::util::{
    field_type_index_base, field_type_index_ext,
    hash::{hash_field_type_subvector, hash_two_digests, Digest, Hasher},
    log2_strict, Deserialize, DeserializeOwned, Serialize,
};
use transcript::Transcript;

use ark_std::{end_timer, start_timer};

use super::hash::{hash_field_type, write_digest_to_transcript, DIGEST_WIDTH};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(deserialize = "E: DeserializeOwned"))]
pub struct MerkleTreeDigests<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<Vec<Digest<E::BaseField>>>,
}

impl<E: ExtensionField> MerkleTreeDigests<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_leaves(
        leaves: &FieldType<E>,
        group_size: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Self {
        merkelize::<E, FieldType<E>>(&[leaves], group_size, hasher)
    }

    pub fn from_leaves_ext(
        leaves: &Vec<E>,
        group_size: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Self {
        merkelize::<E, Vec<E>>(&[leaves], group_size, hasher)
    }

    pub fn from_batch_leaves(
        leaves: &[&FieldType<E>],
        group_size: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Self {
        merkelize::<E, FieldType<E>>(leaves, group_size, hasher)
    }

    pub fn from_batch_leaves_ext(
        leaves: &[&Vec<E>],
        group_size: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Self {
        merkelize::<E, Vec<E>>(leaves, group_size, hasher)
    }

    pub fn root(&self) -> Digest<E::BaseField> {
        self.inner.last().unwrap()[0].clone()
    }

    pub fn root_ref(&self) -> &Digest<E::BaseField> {
        &self.inner.last().unwrap()[0]
    }

    pub fn height(&self) -> usize {
        self.inner.len()
    }

    pub fn bottom_size(&self) -> usize {
        self.inner.last().unwrap().len()
    }

    pub fn merkle_path_without_leaf_sibling_or_root(
        &self,
        leaf_group_index: usize,
    ) -> MerklePathWithoutLeafOrRoot<E> {
        assert!(leaf_group_index < self.bottom_size());
        MerklePathWithoutLeafOrRoot::<E>::new(
            self.inner
                .iter()
                .take(self.height() - 1)
                .enumerate()
                .map(|(index, layer)| {
                    Digest::<E::BaseField>(layer[(leaf_group_index >> index) ^ 1].clone().0)
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(deserialize = "E: DeserializeOwned"))]
pub struct MerkleTree<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: MerkleTreeDigests<E>,
    leaves: Vec<FieldType<E>>,
}

impl<E: ExtensionField> MerkleTree<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(inner: MerkleTreeDigests<E>, leaves: FieldType<E>) -> Self {
        Self {
            inner,
            leaves: vec![leaves],
        }
    }

    pub fn from_leaves(
        leaves: FieldType<E>,
        group_size: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Self {
        Self {
            inner: MerkleTreeDigests::<E>::from_leaves(&leaves, group_size, hasher),
            leaves: vec![leaves],
        }
    }

    pub fn from_batch_leaves(
        leaves: Vec<FieldType<E>>,
        group_size: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Self {
        Self {
            inner: MerkleTreeDigests::<E>::from_batch_leaves(
                &leaves.iter().collect_vec(),
                group_size,
                hasher,
            ),
            leaves,
        }
    }

    pub fn root(&self) -> Digest<E::BaseField> {
        self.inner.root()
    }

    pub fn root_ref(&self) -> &Digest<E::BaseField> {
        &self.inner.root_ref()
    }

    pub fn height(&self) -> usize {
        self.inner.height()
    }

    pub fn leaves(&self) -> &Vec<FieldType<E>> {
        &self.leaves
    }

    pub fn batch_leaves(&self, coeffs: &[E]) -> Vec<E> {
        (0..self.leaves[0].len())
            .into_par_iter()
            .map(|i| {
                self.leaves
                    .iter()
                    .zip(coeffs.iter())
                    .map(|(leaf, coeff)| field_type_index_ext(leaf, i) * *coeff)
                    .sum()
            })
            .collect()
    }

    pub fn leaves_size(&self) -> (usize, usize) {
        (self.leaves.len(), self.leaves[0].len())
    }

    pub fn get_leaf_as_base(&self, index: usize) -> Vec<E::BaseField> {
        match &self.leaves[0] {
            FieldType::Base(_) => self
                .leaves
                .iter()
                .map(|leaves| field_type_index_base(leaves, index))
                .collect(),
            FieldType::Ext(_) => panic!(
                "Mismatching field type, calling get_leaf_as_base on a Merkle tree over extension fields"
            ),
            FieldType::Unreachable => unreachable!(),
        }
    }

    pub fn get_leaf_as_extension(&self, index: usize) -> Vec<E> {
        match &self.leaves[0] {
            FieldType::Base(_) => self
                .leaves
                .iter()
                .map(|leaves| field_type_index_ext(leaves, index))
                .collect(),
            FieldType::Ext(_) => self
                .leaves
                .iter()
                .map(|leaves| field_type_index_ext(leaves, index))
                .collect(),
            FieldType::Unreachable => unreachable!(),
        }
    }

    pub fn leaf_group_size(&self) -> usize {
        self.leaves_size().1 / self.inner.bottom_size()
    }

    pub fn leaf_group_num(&self) -> usize {
        self.inner.bottom_size()
    }

    pub fn merkle_path_without_leaf_sibling_or_root(
        &self,
        leaf_index: usize,
    ) -> MerklePathWithoutLeafOrRoot<E> {
        assert!(leaf_index < self.leaves_size().1);
        self.inner
            .merkle_path_without_leaf_sibling_or_root(leaf_index / self.leaf_group_size())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerklePathWithoutLeafOrRoot<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<Digest<E::BaseField>>,
}

impl<E: ExtensionField> MerklePathWithoutLeafOrRoot<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(inner: Vec<Digest<E::BaseField>>) -> Self {
        Self { inner }
    }

    pub fn group_num(&self) -> usize {
        1 << self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn height(&self) -> usize {
        // The height of the Merkle tree this path comes from. Plus 1 for the root.
        self.len() + 1
    }

    pub fn iter(&self) -> impl Iterator<Item = &Digest<E::BaseField>> {
        self.inner.iter()
    }

    pub fn write_transcript(&self, transcript: &mut Transcript<E>) {
        self.inner
            .iter()
            .for_each(|hash| write_digest_to_transcript(hash, transcript));
    }

    pub fn authenticate_leaves_group(
        &self,
        leaves: &SingleLeavesGroup<E>,
        index: usize,
        root: &Digest<E::BaseField>,
        hasher: &Hasher<E::BaseField>,
    ) {
        authenticate_merkle_path_root::<E>(&self.inner, leaves, index, root, hasher)
    }

    pub fn authenticate_batch_leaves_pair(
        &self,
        leaves_pair: &BatchLeavesPair<E>,
        index: usize,
        root: &Digest<E::BaseField>,
        hasher: &Hasher<E::BaseField>,
    ) {
        authenticate_merkle_path_root_batch::<E>(&self.inner, leaves_pair, index, root, hasher)
    }
}

trait Merkelizable<E: ExtensionField>: Sync
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn len(&self) -> usize;
    fn hash_part(
        &self,
        start: usize,
        end: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Digest<E::BaseField>;
    fn get_leaves_pair_at(leaves: &[&Self], index: usize) -> BatchLeavesPair<E>;
}

impl<E: ExtensionField> Merkelizable<E> for FieldType<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn len(&self) -> usize {
        FieldType::len(self)
    }

    fn hash_part(
        &self,
        start: usize,
        end: usize,
        hasher: &Hasher<E::BaseField>,
    ) -> Digest<E::BaseField> {
        hash_field_type_subvector(self, start..end, hasher)
    }

    fn get_leaves_pair_at(leaves: &[&Self], index: usize) -> BatchLeavesPair<E> {
        match leaves[0] {
            FieldType::Ext(_) => BatchLeavesPair::Ext(
                leaves
                    .iter()
                    .map(|x| {
                        (
                            field_type_index_ext(x, index << 1),
                            field_type_index_ext(x, (index << 1) + 1),
                        )
                    })
                    .collect(),
            ),
            FieldType::Base(_) => BatchLeavesPair::Base(
                leaves
                    .iter()
                    .map(|x| {
                        (
                            field_type_index_base(x, index << 1),
                            field_type_index_base(x, (index << 1) + 1),
                        )
                    })
                    .collect(),
            ),
            _ => unreachable!(),
        }
    }
}

impl<E: ExtensionField> Merkelizable<E> for Vec<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn hash_part(
        &self,
        start: usize,
        end: usize,
        hasher: &Hasher<<E as ExtensionField>::BaseField>,
    ) -> Digest<<E as ExtensionField>::BaseField> {
        let mut hasher = hasher.clone();
        (start..end).into_iter().for_each(|i| {
            hasher.update(self[i].as_bases());
        });
        let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
        Digest(result)
    }

    fn get_leaves_pair_at(leaves: &[&Self], index: usize) -> BatchLeavesPair<E> {
        BatchLeavesPair::Ext(
            leaves
                .iter()
                .map(|x| (x[index << 1], x[(index << 1) + 1]))
                .collect(),
        )
    }
}

/// Merkle tree construction
/// TODO: Support merkelizing mixed-type values
fn merkelize<E: ExtensionField, DataType: Merkelizable<E>>(
    values: &[&DataType],
    group_size: usize,
    hasher: &Hasher<E::BaseField>,
) -> MerkleTreeDigests<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    #[cfg(feature = "sanity-check")]
    for i in 0..(values.len() - 1) {
        assert_eq!(values[i].len(), values[i + 1].len());
    }
    assert_eq!(values[0].len() % group_size, 0);
    let leaves_group_count = values[0].len() / group_size;

    let timer = start_timer!(|| format!("merkelize {} values", values[0].len() * values.len()));
    let log_v = log2_strict(values[0].len());
    let mut tree = Vec::with_capacity(log_v);
    // The first layer of hashes, half the number of leaves
    let mut hashes = vec![Digest::default(); leaves_group_count];
    if values.len() == 1 {
        hashes.par_iter_mut().enumerate().for_each(|(i, hash)| {
            *hash = values[0].hash_part(i * group_size, (i + 1) * group_size, hasher);
        });
    } else {
        assert_eq!(group_size, 2); // For batched case, only support two leaves
        hashes.par_iter_mut().enumerate().for_each(|(i, hash)| {
            *hash = hash_two_leaves_batch::<E>(&DataType::get_leaves_pair_at(values, i), hasher);
        });
    }

    tree.push(hashes);

    for i in 1..(log_v) {
        let oracle = tree[i - 1]
            .par_chunks_exact(2)
            .map(|ys| hash_two_digests(&ys[0], &ys[1], hasher))
            .collect::<Vec<_>>();

        tree.push(oracle);
    }
    end_timer!(timer);
    MerkleTreeDigests { inner: tree }
}

fn authenticate_merkle_path_root<E: ExtensionField>(
    path: &[Digest<E::BaseField>],
    leaves: &SingleLeavesGroup<E>,
    group_index: usize,
    root: &Digest<E::BaseField>,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut x_index = group_index;
    let mut hash = hash_leaves_group(leaves, hasher);

    for path_i in path.iter() {
        hash = if x_index & 1 == 0 {
            hash_two_digests(&hash, path_i, hasher)
        } else {
            hash_two_digests(path_i, &hash, hasher)
        };
        x_index >>= 1;
    }
    assert_eq!(&hash, root);
}

fn authenticate_merkle_path_root_batch<E: ExtensionField>(
    path: &[Digest<E::BaseField>],
    leaves_pair: &BatchLeavesPair<E>,
    group_index: usize,
    root: &Digest<E::BaseField>,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut x_index = group_index;
    let mut hash = hash_two_leaves_batch(leaves_pair, hasher);

    // The lowest bit in the index is ignored. It can point to either leaves
    x_index >>= 1;
    for path_i in path.iter() {
        hash = if x_index & 1 == 0 {
            hash_two_digests(&hash, path_i, hasher)
        } else {
            hash_two_digests(path_i, &hash, hasher)
        };
        x_index >>= 1;
    }
    assert_eq!(&hash, root);
}

/// For cases where the oracle are committed in the way that
/// multiple leaves are hashed together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleLeavesGroup<E: ExtensionField>(FieldType<E>);

impl<E: ExtensionField> SingleLeavesGroup<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn as_ext(&self) -> Vec<E> {
        match &self.0 {
            FieldType::Ext(leaves) => leaves.clone(),
            FieldType::Base(leaves) => leaves.iter().map(|x| (*x).into()).collect::<Vec<_>>(),
            _ => unreachable!(),
        }
    }

    pub fn equal_to_at(&self, a: E, index: usize) -> bool {
        match &self.0 {
            FieldType::Ext(leaves) => leaves[index] == a,
            FieldType::Base(leaves) => E::from(leaves[index]) == a,
            _ => unreachable!(),
        }
    }

    pub fn get_ext(&self, index: usize) -> E {
        match &self.0 {
            FieldType::Ext(leaves) => leaves[index],
            FieldType::Base(leaves) => E::from(leaves[index]),
            _ => unreachable!(),
        }
    }

    pub fn as_field_type(self) -> FieldType<E> {
        self.0
    }

    pub fn as_field_type_ref(&self) -> &FieldType<E> {
        &self.0
    }

    pub fn from_all_leaves(group_index: usize, group_size: usize, leaves: &FieldType<E>) -> Self {
        match leaves {
            FieldType::Ext(leaves) => Self(FieldType::Ext(
                (group_index * group_size..(group_index + 1) * group_size)
                    .map(|i| leaves[i])
                    .collect::<Vec<_>>(),
            )),
            FieldType::Base(leaves) => Self(FieldType::Base(
                (group_index * group_size..(group_index + 1) * group_size)
                    .map(|i| leaves[i])
                    .collect::<Vec<_>>(),
            )),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BatchLeavesPair<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    Ext(Vec<(E, E)>),
    Base(Vec<(E::BaseField, E::BaseField)>),
}

impl<E: ExtensionField> BatchLeavesPair<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_all_leaves(index: usize, leaves: &[&FieldType<E>]) -> Self {
        FieldType::<E>::get_leaves_pair_at(leaves, index)
    }

    pub fn as_ext(&self) -> Vec<(E, E)> {
        match self {
            BatchLeavesPair::Ext(x) => x.clone(),
            BatchLeavesPair::Base(x) => x.iter().map(|(x, y)| ((*x).into(), (*y).into())).collect(),
        }
    }

    pub fn single_leave_ext(&self) -> (E, E) {
        match self {
            BatchLeavesPair::Ext(x) => {
                assert_eq!(x.len(), 1);
                x[0]
            }
            BatchLeavesPair::Base(x) => {
                assert_eq!(x.len(), 1);
                (x[0].0.into(), x[0].1.into())
            }
        }
    }

    pub fn batch(&self, coeffs: &[E]) -> (E, E) {
        match self {
            BatchLeavesPair::Ext(x) => {
                let mut result = (E::ZERO, E::ZERO);
                for (i, (x, y)) in x.iter().enumerate() {
                    result.0 += coeffs[i] * *x;
                    result.1 += coeffs[i] * *y;
                }
                result
            }
            BatchLeavesPair::Base(x) => {
                let mut result = (E::ZERO, E::ZERO);
                for (i, (x, y)) in x.iter().enumerate() {
                    result.0 += coeffs[i] * *x;
                    result.1 += coeffs[i] * *y;
                }
                result
            }
        }
    }

    pub fn left(&self) -> FieldType<E> {
        match self {
            BatchLeavesPair::Ext(x) => {
                FieldType::Ext(x.iter().map(|(x, _)| x.clone()).collect::<Vec<_>>())
            }
            BatchLeavesPair::Base(x) => {
                FieldType::Base(x.iter().map(|(x, _)| x.clone()).collect::<Vec<_>>())
            }
        }
    }

    pub fn right(&self) -> FieldType<E> {
        match self {
            BatchLeavesPair::Ext(x) => {
                FieldType::Ext(x.iter().map(|(_, y)| y.clone()).collect::<Vec<_>>())
            }
            BatchLeavesPair::Base(x) => {
                FieldType::Base(x.iter().map(|(_, y)| y.clone()).collect::<Vec<_>>())
            }
        }
    }
}

pub fn hash_leaves_group<E: ExtensionField>(
    leaves_group: &SingleLeavesGroup<E>,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    hash_field_type(leaves_group.as_field_type_ref(), hasher)
}

pub fn hash_two_leaves_batch<E: ExtensionField>(
    leaves: &BatchLeavesPair<E>,
    hasher: &Hasher<E::BaseField>,
) -> Digest<E::BaseField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let left_hash = hash_field_type(&leaves.left(), hasher);
    let right_hash = hash_field_type(&leaves.right(), hasher);

    hash_two_digests(&left_hash, &right_hash, hasher)
}
