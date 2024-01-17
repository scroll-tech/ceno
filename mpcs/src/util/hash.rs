use goldilocks::SmallField;

use poseidon::Poseidon;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const DIGEST_WIDTH: usize = super::transcript::OUTPUT_WIDTH;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest<F: SmallField>(pub [F::BaseField; DIGEST_WIDTH])
where
    F::BaseField: Serialize + DeserializeOwned;

pub type Hasher<F> = Poseidon<<F as SmallField>::BaseField, 12, 11>;

pub fn new_hasher<F: SmallField>() -> Hasher<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    // FIXME: Change to the right parameter
    Hasher::<F>::new(8, 22)
}

pub fn hash_two_leaves<F: SmallField>(a: &F, b: &F) -> Digest<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    let mut hasher = new_hasher::<F>();
    hasher.update(a.to_limbs().as_slice());
    hasher.update(b.to_limbs().as_slice());
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}

pub fn hash_two_digests<F: SmallField>(a: &Digest<F>, b: &Digest<F>) -> Digest<F>
where
    F::BaseField: Serialize + DeserializeOwned,
{
    let mut hasher = new_hasher::<F>();
    hasher.update(a.0.as_slice());
    hasher.update(b.0.as_slice());
    let result = hasher.squeeze_vec()[0..DIGEST_WIDTH].try_into().unwrap();
    Digest(result)
}
