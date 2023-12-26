use ff::FromUniformBytes;
use goldilocks::SmallField;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath(Vec<Digest>);

/// An opening of a leaf in a Merkle tree
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleOpening<F> {
    pub path: MerklePath,
    pub leaf: F,
    pub leaf_index: usize,
}

/// A Merkle tree
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTree<F> {
    pub(crate) root: Digest,
    pub(crate) leaves: Vec<F>,
    pub(crate) height: usize,
    pub(crate) intermediate_nodes: Vec<Digest>,
}

impl<F: SmallField + FromUniformBytes<64>> MerkleTree<F> {
    /// Create a Merkle tree from a list of leaves
    pub fn new(leaves: Vec<F>) -> Self {
        let height = leaves.len().next_power_of_two().trailing_zeros() as usize;
        let mut tree = MerkleTree {
            root: Digest::default(),
            leaves,
            height,
            intermediate_nodes: vec![],
        };
        tree.build();
        tree
    }

    fn build(&mut self) {
        // TODO: implement
    }

    /// Open a leaf at a given index
    pub fn open(&self, leaf_index: usize) -> MerkleOpening<F> {
        // TODO: replace with real implementation
        MerkleOpening {
            path: MerklePath(vec![Digest::default(); self.height]),
            leaf: self.leaves[leaf_index],
            leaf_index,
        }
    }
}
