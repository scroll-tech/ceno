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
            0.into(),
        ];

        let rlc_record = self.rlc_chip_record(items);
        self.read_record(|| "state_in", rlc_record)
    }

    fn state_out(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError> {
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(RAMType::GlobalState as u64)),
            pc,
            ts,
            0.into(),
        ];
        let rlc_record = self.rlc_chip_record(items);
        self.write_record(|| "state_out", rlc_record)
    }

    fn state_out_with_exit_code(
        &mut self,
        pc: Expression<E>,
        ts: Expression<E>,
        exit_code: Expression<E>,
    ) -> Result<(), ZKVMError> {
        let items: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(RAMType::GlobalState as u64)),
            pc,
            ts,
            exit_code,
        ];
        let rlc_record = self.rlc_chip_record(items);
        self.write_record(|| "state_out_with_exit_code", rlc_record)
    }
}
