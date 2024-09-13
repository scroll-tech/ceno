use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::config::ExprLtConfig,
};

pub mod general;
pub mod global_state;
pub mod register;
pub mod utils;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError>;

    fn state_out(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError>;
}

pub trait RegisterChipOperations<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> {
    fn register_read<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        name_fn: N,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        values: &V,
    ) -> Result<(Expression<E>, ExprLtConfig), ZKVMError>;

    #[allow(clippy::too_many_arguments)]
    fn register_write<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        name_fn: N,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: &V,
        values: &V,
    ) -> Result<(Expression<E>, ExprLtConfig), ZKVMError>;
}
