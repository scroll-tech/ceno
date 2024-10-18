use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    structs::RAMType,
};

pub trait StateCircuit<E: ExtensionField> {
    fn initial_global_state(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Expression<E>, ZKVMError>;
    fn finalize_global_state(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Expression<E>, ZKVMError>;
}

pub struct GlobalState;

impl<E: ExtensionField> StateCircuit<E> for GlobalState {
    fn initial_global_state(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
    ) -> Result<Expression<E>, ZKVMError> {
        let states: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(RAMType::GlobalState as u64)),
            circuit_builder.query_init_pc()?.expr(),
            circuit_builder.query_init_cycle()?.expr(),
        ];

        Ok(circuit_builder.rlc_chip_record(states))
    }

    fn finalize_global_state(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
    ) -> Result<crate::expression::Expression<E>, crate::error::ZKVMError> {
        let states: Vec<Expression<E>> = vec![
            Expression::Constant(E::BaseField::from(RAMType::GlobalState as u64)),
            circuit_builder.query_end_pc()?.expr(),
            circuit_builder.query_end_cycle()?.expr(),
        ];

        Ok(circuit_builder.rlc_chip_record(states))
    }
}
