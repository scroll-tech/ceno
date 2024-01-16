use std::io::Write;

use goldilocks::SmallField;
use itertools::Itertools;
use poseidon::Poseidon;
use util::Error;

use crate::{FieldTranscript, FieldTranscriptWrite, OUTPUT_WIDTH, RATE, STATE};

#[derive(Clone)]
pub struct PoseidonWrite<F: SmallField, W: Write> {
    sponge_hasher: Poseidon<F::BaseField, STATE, RATE>,
    writer: W,
}

impl<F: SmallField, W: Write> PoseidonWrite<F, W> {
    pub fn init(writer: W) -> Self {
        Self {
            sponge_hasher: Poseidon::new(8, 22),
            writer,
        }
    }
}

impl<F: SmallField, W: Write> FieldTranscript<F> for PoseidonWrite<F, W> {
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

impl<F: SmallField, W: Write> FieldTranscriptWrite<F> for PoseidonWrite<F, W> {
    fn write_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.common_field_element(fe)?;
        // TODO: wrap errors
        self.writer.write_all(fe.to_raw_bytes().as_ref()).unwrap();
        Ok(())
    }

    fn write_field_elements(&mut self, fes: &[F]) -> Result<(), Error> {
        self.common_field_elements(fes)?;
        // TODO: wrap errors
        fes.iter()
            .for_each(|fe| self.writer.write_all(fe.to_raw_bytes().as_ref()).unwrap());
        Ok(())
    }
}
