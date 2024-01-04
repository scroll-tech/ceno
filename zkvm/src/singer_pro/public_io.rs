use goldilocks::SmallField;

use crate::ZKVMPublicIO;

use super::{SingerProCircuit, SingerProPublicIO};

impl<F: SmallField> ZKVMPublicIO<F> for SingerProPublicIO<F> {
    type Circuit = SingerProCircuit<F>;

    fn new(circuit: &Self::Circuit, bytecode: &[u8], public_input: &[F]) -> Self {
        todo!()
    }
}
