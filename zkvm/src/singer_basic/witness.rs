use goldilocks::SmallField;

use crate::ZKVMWitness;

use super::{SingerBasicCircuit, SingerBasicWitness};

impl<F: SmallField> ZKVMWitness<F> for SingerBasicWitness<F> {
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
