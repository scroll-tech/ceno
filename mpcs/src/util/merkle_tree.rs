use crate::util::{
    hash::{Hash, Output},
    Deserialize, DeserializeOwned, Serialize,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleTree<H: Hash> {
    inner: Vec<Vec<Output<H>>>,
}
