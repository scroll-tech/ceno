use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
};

pub mod general;
pub mod global_state;
pub mod register;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError>;

    fn state_out(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError>;
}

pub trait RegisterChipOperations<E: ExtensionField> {
    fn register_read<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        values: &V,
    ) -> Result<Expression<E>, ZKVMError>;

    fn register_write<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: &V,
        values: &V,
    ) -> Result<Expression<E>, ZKVMError>;
}
