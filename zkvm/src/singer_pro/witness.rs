use goldilocks::SmallField;

use crate::{singer_basic::SingerBasicCircuit, ZKVMWitness};

use super::SingerProWitness;

impl<F: SmallField> ZKVMWitness<F> for SingerProWitness<F> {
    type Circuit = SingerBasicCircuit<F>;

    fn new(circuit: &Self::Circuit) -> Self {
        todo!()
    }

    fn initialize(
        &mut self,
        bytecode: &[u8],
        public_input: &[F],
    ) -> Result<(), crate::error::ZKVMError> {
        todo!()
    }

    fn execute(&mut self) -> Result<(), crate::error::ZKVMError> {
        todo!()
    }

    fn finalize(&mut self) -> Result<(), crate::error::ZKVMError> {
        todo!()
    }
}
