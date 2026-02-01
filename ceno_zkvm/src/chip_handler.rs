use ff_ext::ExtensionField;
use gkr_iop::{error::CircuitBuilderError, gadgets::AssertLtConfig, selector::SelectorType};

use crate::instructions::riscv::constants::UINT_LIMBS;
use multilinear_extensions::{Expression, ToExpr};

pub mod general;
pub mod global_state;
pub mod memory;
pub mod register;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(&mut self, pc: Expression<E>, ts: Expression<E>)
    -> Result<(), CircuitBuilderError>;

    fn state_out(
        &mut self,
        pc: Expression<E>,
        ts: Expression<E>,
    ) -> Result<(), CircuitBuilderError>;
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
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError>;

    #[allow(clippy::too_many_arguments)]
    fn register_write(
        &mut self,
        name_fn: N,
        register_id: impl ToExpr<E, Output = Expression<E>>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: RegisterExpr<E>,
        value: RegisterExpr<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError>;
}

/// The common representation of a memory address.
pub type AddressExpr<E> = Expression<E>;

/// The common representation of a register value.
/// Format: `[u16; UINT_LIMBS]`, least-significant-first.
pub type MemoryExpr<E> = [Expression<E>; UINT_LIMBS];

pub trait MemoryChipOperations<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> {
    fn memory_read(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError>;

    #[allow(clippy::too_many_arguments)]
    fn memory_write(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: MemoryExpr<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError>;

    fn memory_write_with_rw_selectors(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: MemoryExpr<E>,
        value: MemoryExpr<E>,
        r_selector: &SelectorType<E>,
        w_selector: &SelectorType<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError>;
}
