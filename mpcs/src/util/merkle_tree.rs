use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::util::{
    log2_strict,
    transcript::{TranscriptRead, TranscriptWrite},
    Deserialize, DeserializeOwned, Serialize,
};

use super::hash::{hash_two_digests, hash_two_leaves, Digest, Hasher};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct MerkleTree<F: SmallField>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<Vec<Digest<F>>>,
    leaves: Vec<F>,
}

impl<F: SmallField> MerkleTree<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_leaves(leaves: Vec<F>, hasher: &Hasher<F>) -> Self {
        Self {
            inner: merkelize::<F>(&leaves, hasher),
            leaves,
        }
    }

    pub fn root(&self) -> Digest<F> {
        self.inner.last().unwrap()[0].clone()
    }

    pub fn root_ref(&self) -> &Digest<F> {
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

    pub fn merkle_path_without_leaf_sibling_or_root<EF: SmallField<BaseField = F::BaseField>>(
        &self,
        leaf_index: usize,
    ) -> MerklePathWithoutLeafOrRoot<EF> {
        assert!(leaf_index < self.size());
        MerklePathWithoutLeafOrRoot::<EF>::new(
            self.inner
                .iter()
                .take(self.height() - 1)
                .enumerate()
                .map(|(index, layer)| {
                    Digest::<EF>(layer[(leaf_index >> (index + 1)) ^ 1].clone().0)
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MerklePathWithoutLeafOrRoot<F: SmallField>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<Digest<F>>,
}

impl<F: SmallField> MerklePathWithoutLeafOrRoot<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(inner: Vec<Digest<F>>) -> Self {
        Self { inner }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Digest<F>> {
        self.inner.iter()
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<F>, F>) {
        self.inner
            .iter()
            .for_each(|hash| transcript.write_commitment(hash).unwrap());
    }

    pub fn read_transcript(
        transcript: &mut impl TranscriptRead<Digest<F>, F>,
        height: usize,
    ) -> Self {
        // Since no root, the number of digests is height - 1
        let mut inner = Vec::with_capacity(height - 1);
        for _ in 0..(height - 1) {
            inner.push(transcript.read_commitment().unwrap());
        }
        Self { inner }
    }

    pub fn authenticate_leaves_root<EF: SmallField<BaseField = F::BaseField>>(
        &self,
        left: EF,
        right: EF,
        index: usize,
        root: &Digest<F>,
        hasher: &Hasher<F>,
    ) {
        authenticate_merkle_path_root::<F, EF>(&self.inner, (left, right), index, root, hasher)
    }
}

fn merkelize<F: SmallField>(values: &Vec<F>, hasher: &Hasher<F>) -> Vec<Vec<Digest<F>>>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| format!("merkelize {} values", values.len()));
    let log_v = log2_strict(values.len());
    let mut tree = Vec::with_capacity(log_v);
    // The first layer of hashes, half the number of leaves
    let mut hashes = vec![Digest::default(); values.len() >> 1];
    hashes.par_iter_mut().enumerate().for_each(|(i, hash)| {
        *hash = hash_two_leaves(&values[i << 1], &values[(i << 1) + 1], hasher);
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

fn authenticate_merkle_path_root<F: SmallField, EF: SmallField<BaseField = F::BaseField>>(
    path: &Vec<Digest<F>>,
    leaves: (EF, EF),
    x_index: usize,
    root: &Digest<F>,
    hasher: &Hasher<F>,
) where
    F::BaseField: Serialize + DeserializeOwned,
{
    let mut x_index = x_index;
    let mut hash = Digest::<F>(hash_two_leaves(&leaves.0, &leaves.1, hasher).0);

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

#[cfg(test)]
mod tests {
    use goldilocks::{Goldilocks, GoldilocksExt2};

    use crate::util::{
        hash::new_hasher,
        transcript::{InMemoryTranscript, PoseidonTranscript},
    };

    use super::*;
    type F = goldilocks::Goldilocks;

    #[test]
    fn test_merkle_tree() {
        let leaves = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        test_leaves(&leaves);

        let leaves = vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
        ];
        test_leaves(&leaves);

        let leaves = vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
        ];
        test_leaves(&leaves);
    }

    fn test_leaves(leaves: &Vec<F>) {
        let hasher = new_hasher::<F>();
        let tree = MerkleTree::<F>::from_leaves(leaves.clone(), &hasher);
        let root = tree.root();
        for (i, _) in leaves.iter().enumerate() {
            let path = tree.merkle_path_without_leaf_sibling_or_root(i);
            let left_leaf = leaves[(i | 1) - 1];
            let right_leaf = leaves[i | 1];
            path.authenticate_leaves_root(left_leaf, right_leaf, i, &root, &hasher);

            let mut transcript = PoseidonTranscript::new();
            path.write_transcript(&mut transcript);
            let proof = transcript.into_proof();
            let mut transcript = PoseidonTranscript::from_proof(&proof);
            let path =
                MerklePathWithoutLeafOrRoot::<F>::read_transcript(&mut transcript, tree.height());
            path.authenticate_leaves_root(left_leaf, right_leaf, i, &root, &hasher);

            let mut transcript = PoseidonTranscript::<GoldilocksExt2>::new();
            let path = tree.merkle_path_without_leaf_sibling_or_root::<GoldilocksExt2>(i);
            path.write_transcript(&mut transcript);
            let proof = transcript.into_proof();
            let mut transcript = PoseidonTranscript::<GoldilocksExt2>::from_proof(&proof);
            let path: MerklePathWithoutLeafOrRoot<GoldilocksExt2> =
                MerklePathWithoutLeafOrRoot::<GoldilocksExt2>::read_transcript(
                    &mut transcript,
                    tree.height(),
                );
            let left_leaf_ext = GoldilocksExt2::from(left_leaf);
            let right_leaf_ext = GoldilocksExt2::from(right_leaf);
            path.authenticate_leaves_root::<Goldilocks>(
                left_leaf_ext.try_into().unwrap(),
                right_leaf_ext.try_into().unwrap(),
                i,
                &Digest(root.0),
                &hasher,
            );
        }
    }
}
