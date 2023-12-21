use super::structs::{VMBasic, VMBasicBuilder, VMBasicInterpreter, VMBasicWitness};
use goldilocks::SmallField;

impl<F: SmallField> VMBasic<F> {
    pub fn new(vm_builder: VMBasicBuilder<F>) -> Self {
        todo!()
    }
}

impl<F: SmallField> VMBasicWitness<F> {
    /// Generate witness for proving zkVM basic.
    pub fn new(vm: &VMBasic<F>, interpreter: &VMBasicInterpreter<F>) -> Self {
        todo!()
    }
}
