use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, expression::Expression, structs::RAMType,
};

use super::GlobalStateRegisterMachineChipOperations;

impl<'a, E: ExtensionField> GlobalStateRegisterMachineChipOperations<E> for CircuitBuilder<'a, E> {
    fn state_in(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError> {
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(RAMType::GlobalState as u64)),
            pc,
            ts,
        ];

        let rlc_record = self.rlc_chip_record(items);
        self.read_record(|| "state_in", rlc_record)
    }

    fn state_out(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError> {
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(RAMType::GlobalState as u64)),
            pc,
            ts,
        ];
        let rlc_record = self.rlc_chip_record(items);
        self.write_record(|| "state_out", rlc_record)
    }
}
