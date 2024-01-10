use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::util::{
    hash::{Hash, Output},
    log2_strict,
    transcript::{TranscriptRead, TranscriptWrite},
    Deserialize, DeserializeOwned, PrimeField, Serialize,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct MerkleTree<F, H: Hash> {
    inner: Vec<Vec<Output<H>>>,
    leaves: Vec<F>,
}

impl<F: PrimeField, H: Hash> MerkleTree<F, H> {
    pub fn from_leaves(leaves: Vec<F>) -> Self {
        Self {
            inner: merkelize::<F, H>(&leaves),
            leaves,
        }
    }

    pub fn root(&self) -> Output<H> {
        self.inner.last().unwrap()[0].clone()
    }

    pub fn root_ref(&self) -> &Output<H> {
        &self.inner.last().unwrap()[0]
    }

    pub fn height(&self) -> usize {
        self.inner.len()
    }

    pub fn leaves(&self) -> &Vec<F> {
        &self.leaves
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    pub fn get_leaf(&self, index: usize) -> &F {
        &self.leaves[index]
    }

    pub fn merkle_path_without_leaf_sibling_or_root(
        &self,
        leaf_index: usize,
    ) -> MerklePathWithoutLeafOrRoot<H> {
        assert!(leaf_index < self.size());
        MerklePathWithoutLeafOrRoot::<H>::new(
            self.inner
                .iter()
                .take(self.height() - 1)
                .map(|layer| layer[(leaf_index >> 1) ^ 1].clone())
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MerklePathWithoutLeafOrRoot<H: Hash> {
    inner: Vec<Output<H>>,
}

impl<H: Hash> MerklePathWithoutLeafOrRoot<H> {
    pub fn new(inner: Vec<Output<H>>) -> Self {
        Self { inner }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Output<H>> {
        self.inner.iter()
    }

    pub fn write_transcript<F: PrimeField>(
        &self,
        transcript: &mut impl TranscriptWrite<Output<H>, F>,
    ) {
        self.inner
            .iter()
            .for_each(|hash| transcript.write_commitment(hash).unwrap());
    }

    pub fn read_transcript<F: PrimeField>(
        transcript: &mut impl TranscriptRead<Output<H>, F>,
        height: usize,
    ) -> Self {
        // Since no root, the number of digests is height - 1
        let mut inner = Vec::with_capacity(height - 1);
        for _ in 0..(height - 1) {
            inner.push(transcript.read_commitment().unwrap());
        }
        Self { inner }
    }

    pub fn authenticate_leaves_root<F: PrimeField>(
        &self,
        left: F,
        right: F,
        index: usize,
        root: &Output<H>,
    ) {
        authenticate_merkle_path_root::<H, F>(&self.inner, (left, right), index, root)
    }
}

fn merkelize<F: PrimeField, H: Hash>(values: &Vec<F>) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict(values.len());
    let mut tree = Vec::with_capacity(log_v);
    // The first layer of hashes, half the number of leaves
    let mut hashes = vec![Output::<H>::default(); values.len() >> 1];
    hashes.par_iter_mut().enumerate().for_each(|(i, hash)| {
        let mut hasher = H::new();
        hasher.update_field_element(&values[i << 1]);
        hasher.update_field_element(&values[(i << 1) + 1]);
        *hash = hasher.finalize_fixed();
    });

    tree.push(hashes);

    for i in 1..(log_v) {
        let oracle = tree[i - 1]
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = H::new();
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect::<Vec<_>>();

        tree.push(oracle);
    }
    tree
}

fn authenticate_merkle_path_root<H: Hash, F: PrimeField>(
    path: &Vec<Output<H>>,
    leaves: (F, F),
    x_index: usize,
    root: &Output<H>,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    let mut x_index = x_index;
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    // The lowest bit in the index is ignored. It can point to either leaves
    x_index >>= 1;
    for i in 0..path.len() {
        let mut hasher = H::new();
        let mut new_hash = Output::<H>::default();
        if x_index & 1 == 0 {
            hasher.update(&hash);
            hasher.update(&path[i]);
        } else {
            hasher.update(&path[i]);
            hasher.update(&hash);
        }
        hasher.finalize_into_reset(&mut new_hash);
        hash = new_hash;

        x_index >>= 1;
    }
    assert_eq!(&hash, root);
}
