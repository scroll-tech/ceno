use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, expression::Expression, structs::RAMType,
};

use super::GlobalStateRegisterMachineChipOperations;

impl<E: ExtensionField> GlobalStateRegisterMachineChipOperations<E> for CircuitBuilder<E> {
    fn state_in(
        &mut self,
        pc: &crate::structs::PCUInt<E>,
        ts: &crate::structs::TSUInt<E>,
    ) -> Result<(), ZKVMError> {
        let items: Vec<Expression<E>> = [
            vec![Expression::Constant(E::BaseField::from(
                RAMType::GlobalState as u64,
            ))],
            pc.expr(),
            ts.expr(),
        ]
        .concat();

        let rlc_record = self.rlc_chip_record(items);
        self.read_record(rlc_record)
    }

    fn state_out(
        &mut self,
        pc: &crate::structs::PCUInt<E>,
        ts: &crate::structs::TSUInt<E>,
    ) -> Result<(), ZKVMError> {
        let items: Vec<Expression<E>> = [
            vec![Expression::Constant(E::BaseField::from(
                RAMType::GlobalState as u64,
            ))],
            pc.expr(),
            ts.expr(),
        ]
        .concat();

        let rlc_record = self.rlc_chip_record(items);
        self.write_record(rlc_record)
    }
}
