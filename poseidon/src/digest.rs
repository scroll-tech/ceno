pub use crate::constants::DIGEST_WIDTH;
use p3::field::PrimeField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct Digest<F: PrimeField>(pub [F; DIGEST_WIDTH]);

impl<F: PrimeField> TryFrom<Vec<F>> for Digest<F> {
    type Error = String;

    fn try_from(values: Vec<F>) -> Result<Self, Self::Error> {
        if values.len() != DIGEST_WIDTH {
            return Err(format!(
                "can only create digest from {DIGEST_WIDTH} elements"
            ));
        }

        Ok(Digest(values.try_into().unwrap()))
    }
}
