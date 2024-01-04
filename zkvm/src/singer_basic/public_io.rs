use goldilocks::SmallField;

use crate::ZKVMPublicIO;

use super::{SingerBasicCircuit, SingerBasicPublicIO};

impl<F: SmallField> ZKVMPublicIO<F> for SingerBasicPublicIO<F> {
    type Circuit = SingerBasicCircuit<F>;

    fn new(circuit: &Self::Circuit, bytecode: &[u8], public_input: &[F]) -> Self {
        todo!()
    }
}
