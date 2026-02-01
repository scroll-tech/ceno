use crate::{
    chip_handler::{AddressExpr, MemoryChipOperations, MemoryExpr},
    circuit_builder::CircuitBuilder,
    gadgets::AssertLtConfig,
    structs::RAMType,
};
use ff_ext::ExtensionField;
use gkr_iop::{error::CircuitBuilderError, selector::SelectorType};
use multilinear_extensions::Expression;

impl<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> MemoryChipOperations<E, NR, N>
    for CircuitBuilder<'_, E>
{
    fn memory_read(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        self.ram_type_read(
            name_fn,
            RAMType::Memory,
            memory_addr.clone(),
            prev_ts,
            ts,
            value,
        )
    }

    fn memory_write(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: MemoryExpr<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        self.ram_type_write(
            name_fn,
            RAMType::Memory,
            memory_addr.clone(),
            prev_ts,
            ts,
            prev_values,
            value,
        )
    }

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
    ) -> Result<(Expression<E>, AssertLtConfig), CircuitBuilderError> {
        self.ram_type_write_with_rw_selectors(
            name_fn,
            RAMType::Memory,
            memory_addr.clone(),
            prev_ts,
            ts,
            prev_values,
            value,
            r_selector,
            w_selector,
        )
    }
}
