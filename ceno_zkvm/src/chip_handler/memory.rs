use crate::{
    chip_handler::{AddressExpr, MemoryChipOperations, MemoryExpr},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::Expression,
    gadgets::AssertLTConfig,
    instructions::riscv::constants::UINT_LIMBS,
    structs::RAMType,
};
use ff_ext::ExtensionField;

impl<'a, E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> MemoryChipOperations<E, NR, N>
    for CircuitBuilder<'a, E>
{
    fn memory_read(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = [
                vec![RAMType::Memory.into(), memory_addr.clone()],
                vec![value.clone()],
                vec![prev_ts.clone()],
            ]
            .concat();
            // Write (a, v, t)
            let write_record = [
                vec![RAMType::Memory.into(), memory_addr.clone()],
                vec![value],
                vec![ts.clone()],
            ]
            .concat();
            cb.read_record(|| "read_record", RAMType::Memory, read_record)?;
            cb.write_record(|| "write_record", RAMType::Memory, write_record)?;

            // assert prev_ts < current_ts
            let lt_cfg = AssertLTConfig::construct_circuit(
                cb,
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                UINT_LIMBS,
            )?;

            let next_ts = ts + 1;

            Ok((next_ts, lt_cfg))
        })
    }

    fn memory_write(
        &mut self,
        name_fn: N,
        memory_addr: &AddressExpr<E>,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: MemoryExpr<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, AssertLTConfig), ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = [
                vec![RAMType::Memory.into(), memory_addr.clone()],
                vec![prev_values],
                vec![prev_ts.clone()],
            ]
            .concat();
            // Write (a, v, t)
            let write_record = [
                vec![RAMType::Memory.into(), memory_addr.clone()],
                vec![value],
                vec![ts.clone()],
            ]
            .concat();
            cb.read_record(|| "read_record", RAMType::Memory, read_record)?;
            cb.write_record(|| "write_record", RAMType::Memory, write_record)?;

            let lt_cfg = AssertLTConfig::construct_circuit(
                cb,
                || "prev_ts < ts",
                prev_ts,
                ts.clone(),
                UINT_LIMBS,
            )?;

            let next_ts = ts + 1;

            Ok((next_ts, lt_cfg))
        })
    }
}
