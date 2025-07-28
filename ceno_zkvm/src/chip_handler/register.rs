use ff_ext::ExtensionField;
use gkr_iop::error::CircuitBuilderError;

use crate::{circuit_builder::CircuitBuilder, gadgets::AssertLtConfig, structs::RAMType};
use multilinear_extensions::{Expression, ToExpr};

use super::{RegisterChipOperations, RegisterExpr};

impl<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> RegisterChipOperations<E, NR, N>
    for CircuitBuilder<'_, E>
{
    fn register_read(
        &mut self,
        name_fn: N,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        self.ram_type_read(name_fn, RAMType::Register, register_id, prev_ts, ts, value)
    }

    fn register_write(
        &mut self,
        name_fn: N,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: RegisterExpr<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        self.ram_type_write(
            name_fn,
            RAMType::Register,
            register_id,
            prev_ts,
            ts,
            prev_values,
            value,
        )
    }
}
