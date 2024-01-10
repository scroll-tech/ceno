use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::util::{
    hash::{Hash, Output},
    log2_strict,
    transcript::TranscriptWrite,
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
}

fn merkelize<F: PrimeField, H: Hash>(values: &Vec<F>) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict(values.len());
    let mut tree = Vec::with_capacity(log_v);
    // The first layer of hashes, half the number of leaves
    let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
    hashes.par_iter_mut().enumerate().for_each(|(i, mut hash)| {
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
