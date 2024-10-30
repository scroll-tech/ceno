use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    expression::{Expression, ToExpr},
    gadgets::AssertLTConfig,
    instructions::riscv::constants::UINT_LIMBS,
};

pub mod general;
pub mod global_state;
pub mod memory;
pub mod register;
pub mod utils;

#[cfg(test)]
pub mod test;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError>;

    fn state_out(&mut self, pc: Expression<E>, ts: Expression<E>) -> Result<(), ZKVMError>;
}

/// The common representation of a register value.
/// Format: `[u16; UINT_LIMBS]`, least-significant-first.
pub type RegisterExpr<E> = [Expression<E>; UINT_LIMBS];

pub trait RegisterChipOperations<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> {
    fn register_read(
        &mut self,
        name_fn: N,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError>;

    #[allow(clippy::too_many_arguments)]
    fn register_write(
        &mut self,
        name_fn: N,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: RegisterExpr<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError>;
}

/// The common representation of a memory address.
pub type AddressExpr<E> = Expression<E>;

/// The common representation of a memory value.
pub type MemoryExpr<E> = Expression<E>;

pub trait MemoryChipOperations<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> {
    fn memory_read(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError>;

    #[allow(clippy::too_many_arguments)]
    fn memory_write(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: MemoryExpr<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError>;
}
