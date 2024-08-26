use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::util::{
    hash::{hash_two_digests, hash_two_leaves_base, hash_two_leaves_ext, Digest, Hasher},
    log2_strict,
    transcript::{TranscriptRead, TranscriptWrite},
    Deserialize, DeserializeOwned, Serialize,
};

use ark_std::{end_timer, start_timer};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "E: Serialize", deserialize = "E: DeserializeOwned"))]
pub struct MerkleTree<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<Vec<Digest<E::BaseField>>>,
    leaves: FieldType<E>,
}

impl<E: ExtensionField> MerkleTree<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_leaves(leaves: FieldType<E>, hasher: &Hasher<E::BaseField>) -> Self {
        Self {
            inner: merkelize::<E>(&leaves, hasher),
            leaves,
        }
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

    pub fn leaves(&self) -> &FieldType<E> {
        &self.leaves
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    pub fn get_leaf_as_base(&self, index: usize) -> E::BaseField {
        match &self.leaves {
            FieldType::Base(leaves) => leaves[index],
            FieldType::Ext(_) => panic!("Mismatching field type, calling get_leaf_as_base on a Merkle tree over extension fields"),
            FieldType::Unreachable => unreachable!(),
        }
    }

    pub fn get_leaf_as_extension(&self, index: usize) -> E {
        match &self.leaves {
            FieldType::Base(leaves) => E::from(leaves[index]),
            FieldType::Ext(leaves) => leaves[index],
            FieldType::Unreachable => unreachable!(),
        }
    }

    pub fn merkle_path_without_leaf_sibling_or_root(
        &self,
        leaf_index: usize,
    ) -> MerklePathWithoutLeafOrRoot<E> {
        assert!(leaf_index < self.size());
        MerklePathWithoutLeafOrRoot::<E>::new(
            self.inner
                .iter()
                .take(self.height() - 1)
                .enumerate()
                .map(|(index, layer)| {
                    Digest::<E::BaseField>(layer[(leaf_index >> (index + 1)) ^ 1].clone().0)
                })
                .collect(),
        )
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

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Digest<E::BaseField>> {
        self.inner.iter()
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.inner
            .iter()
            .for_each(|hash| transcript.write_commitment(hash).unwrap());
    }

    pub fn read_transcript(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        height: usize,
    ) -> Self {
        // Since no root, the number of digests is height - 1
        let mut inner = Vec::with_capacity(height - 1);
        for _ in 0..(height - 1) {
            inner.push(transcript.read_commitment().unwrap());
        }
        Self { inner }
    }

    pub fn authenticate_leaves_root_ext(
        &self,
        left: E,
        right: E,
        index: usize,
        root: &Digest<E::BaseField>,
        hasher: &Hasher<E::BaseField>,
    ) {
        authenticate_merkle_path_root::<E>(
            &self.inner,
            FieldType::Ext(vec![left, right]),
            index,
            root,
            hasher,
        )
    }

    pub fn authenticate_leaves_root_base(
        &self,
        left: E::BaseField,
        right: E::BaseField,
        index: usize,
        root: &Digest<E::BaseField>,
        hasher: &Hasher<E::BaseField>,
    ) {
        authenticate_merkle_path_root::<E>(
            &self.inner,
            FieldType::Base(vec![left, right]),
            index,
            root,
            hasher,
        )
    }
}

fn merkelize<E: ExtensionField>(
    values: &FieldType<E>,
    hasher: &Hasher<E::BaseField>,
) -> Vec<Vec<Digest<E::BaseField>>> {
    let timer = start_timer!(|| format!("merkelize {} values", values.len()));
    let log_v = log2_strict(values.len());
    let mut tree = Vec::with_capacity(log_v);
    // The first layer of hashes, half the number of leaves
    let mut hashes = vec![Digest::default(); values.len() >> 1];
    hashes.par_iter_mut().enumerate().for_each(|(i, hash)| {
        *hash = match values {
            FieldType::Base(values) => {
                hash_two_leaves_base::<E>(&values[i << 1], &values[(i << 1) + 1], hasher)
            }
            FieldType::Ext(values) => {
                hash_two_leaves_ext::<E>(&values[i << 1], &values[(i << 1) + 1], hasher)
            }
            FieldType::Unreachable => unreachable!(),
        };
    });

    tree.push(hashes);

    for i in 1..(log_v) {
        let oracle = tree[i - 1]
            .par_chunks_exact(2)
            .map(|ys| hash_two_digests(&ys[0], &ys[1], hasher))
            .collect::<Vec<_>>();

        tree.push(oracle);
    }
    end_timer!(timer);
    tree
}

fn authenticate_merkle_path_root<E: ExtensionField>(
    path: &Vec<Digest<E::BaseField>>,
    leaves: FieldType<E>,
    x_index: usize,
    root: &Digest<E::BaseField>,
    hasher: &Hasher<E::BaseField>,
) {
    let mut x_index = x_index;
    assert_eq!(leaves.len(), 2);
    let mut hash = match leaves {
        FieldType::Base(leaves) => hash_two_leaves_base::<E>(&leaves[0], &leaves[1], hasher),
        FieldType::Ext(leaves) => hash_two_leaves_ext(&leaves[0], &leaves[1], hasher),
        FieldType::Unreachable => unreachable!(),
    };

    // The lowest bit in the index is ignored. It can point to either leaves
    x_index >>= 1;
    for i in 0..path.len() {
        hash = if x_index & 1 == 0 {
            hash_two_digests(&hash, &path[i], hasher)
        } else {
            hash_two_digests(&path[i], &hash, hasher)
        };
        x_index >>= 1;
    }
    assert_eq!(&hash, root);
}
