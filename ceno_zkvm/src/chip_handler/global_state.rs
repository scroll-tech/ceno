use ff_ext::ExtensionField;

use super::GlobalStateRegisterMachineChipOperations;
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, expression::Expression, structs::RAMType,
};
use p3_field::FieldAlgebra;

impl<E: ExtensionField> GlobalStateRegisterMachineChipOperations<E> for CircuitBuilder<'_, E> {
    fn state_in(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError> {
        let record: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from_canonical_u64(
                RAMType::GlobalState as u64,
            )),
            pc,
            ts,
        ];

        self.read_record(|| "state_in", RAMType::GlobalState, record)
    }

    fn state_out(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError> {
        let record: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from_canonical_u64(
                RAMType::GlobalState as u64,
            )),
            pc,
            ts,
        ];
        self.write_record(|| "state_out", RAMType::GlobalState, record)
    }
}
