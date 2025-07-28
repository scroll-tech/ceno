use ff_ext::ExtensionField;

use crate::{
    chip_handler::general::PublicIOQuery, circuit_builder::CircuitBuilder, error::ZKVMError,
    structs::RAMType,
};
use multilinear_extensions::{Expression, ToExpr};
use p3::field::FieldAlgebra;

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
            E::BaseField::from_canonical_u64(RAMType::GlobalState as u64).expr(),
            circuit_builder.query_init_pc()?.expr(),
            circuit_builder.query_init_cycle()?.expr(),
        ];

        Ok(circuit_builder.rlc_chip_record(states))
    }

    fn finalize_global_state(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
    ) -> Result<Expression<E>, ZKVMError> {
        let states: Vec<Expression<E>> = vec![
            E::BaseField::from_canonical_u64(RAMType::GlobalState as u64).expr(),
            circuit_builder.query_end_pc()?.expr(),
            circuit_builder.query_end_cycle()?.expr(),
        ];

        Ok(circuit_builder.rlc_chip_record(states))
    }
}
