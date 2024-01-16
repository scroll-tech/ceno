//! This repo is not properly implemented
//! PoseidonTranscript APIs are placeholders; the actual logic is to be implemented later.

use goldilocks::SmallField;
use itertools::Itertools;
use poseidon::Poseidon;
use util::Error;

use crate::{FieldTranscript, FieldTranscriptRead};

// temporarily using 12-4 hashes
pub const INPUT_WIDTH: usize = 12;
pub const OUTPUT_WIDTH: usize = 4;
pub const STATE: usize = 12;
pub const RATE: usize = 11;

#[derive(Clone)]
pub struct PoseidonRead<F: SmallField> {
    sponge_hasher: Poseidon<F::BaseField, STATE, RATE>,
}

impl<F: SmallField> PoseidonRead<F> {
    pub fn init(sponge_hasher: Poseidon<F::BaseField, STATE, RATE>) -> Self {
        Self { sponge_hasher }
    }
}

impl<F: SmallField> FieldTranscript<F> for PoseidonRead<F> {
    fn squeeze_challenge(&mut self) -> F {
        F::from_limbs(self.sponge_hasher.squeeze_vec().as_ref())
    }

    fn squeeze_challenges(&mut self, n: usize) -> Vec<F> {
        let num_iter = n * F::DEGREE / OUTPUT_WIDTH;

        (0..num_iter)
            .flat_map(|_| self.sponge_hasher.squeeze_vec())
            .collect_vec()
            .chunks(F::DEGREE)
            .take(n)
            .map(|chunk| F::from_limbs(chunk))
            .collect()
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.sponge_hasher.update(fe.to_limbs().as_ref());
        Ok(())
    }

    fn common_field_elements(&mut self, fes: &[F]) -> Result<(), Error> {
        let inputs = fes.iter().flat_map(|fe| fe.to_limbs()).collect::<Vec<_>>();
        self.sponge_hasher.update(inputs.as_ref());
        Ok(())
    }
}

impl<F: SmallField> FieldTranscriptRead<F> for PoseidonRead<F> {
    fn read_field_element(&mut self) -> Result<F, Error> {
        unimplemented!()
        // let mut buffer = vec![0u8; F::NUM_BITS as usize / 8];
        // // TODO: wrap errors
        // self.reader.read_exact(&mut buffer).unwrap();
        // let res = F::from_raw_bytes(buffer.as_ref()).unwrap();
        // self.common_field_element(&res)?;
        // Ok(res)
    }

    fn read_field_elements(&mut self, _n: usize) -> Result<Vec<F>, Error> {
        unimplemented!()
        // let mut buffer = vec![0u8; n * F::NUM_BITS as usize / 8];
        // // TODO: wrap errors
        // self.reader.read_exact(&mut buffer).unwrap();
        // let res = F::bytes_to_field_elements(buffer.as_ref());
        // self.common_field_elements(&res)?;
        // Ok(res)
    }
}
