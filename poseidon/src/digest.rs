use crate::constants::DIGEST_WIDTH;
use goldilocks::SmallField;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest<F: SmallField>(pub [F; DIGEST_WIDTH]);

impl<F: SmallField> TryFrom<Vec<F>> for Digest<F> {
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

impl<F: SmallField> Digest<F> {
    pub(crate) fn from_partial(inputs: &[F]) -> Self {
        let mut elements = [F::ZERO; DIGEST_WIDTH];
        elements[0..inputs.len()].copy_from_slice(inputs);
        Self(elements)
    }

    pub(crate) fn elements(&self) -> &[F] {
        &self.0
    }
}
