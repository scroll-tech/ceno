use crate::{
    chip_handler::{MemoryChipOperations, MemoryExpr},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::config::ExprLtConfig,
    structs::RAMType,
};
use ff_ext::ExtensionField;

impl<'a, E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> MemoryChipOperations<E, NR, N>
    for CircuitBuilder<'a, E>
{
    fn memory_read(
        &mut self,
        name_fn: N,
        memory_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, ExprLtConfig), ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Memory as u64,
                    ))],
                    vec![memory_id.expr()],
                    value.to_vec(),
                    vec![prev_ts.clone()],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Memory as u64,
                    ))],
                    vec![memory_id.expr()],
                    value.to_vec(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            // assert prev_ts < current_ts
            let lt_cfg = cb.less_than(|| "prev_ts < ts", prev_ts, ts.clone(), Some(true))?;

            let next_ts = ts + 1.into();

            Ok((next_ts, lt_cfg))
        })
    }

    fn memory_write(
        &mut self,
        name_fn: N,
        memory_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: MemoryExpr<E>,
        value: MemoryExpr<E>,
    ) -> Result<(Expression<E>, ExprLtConfig), ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Memory as u64,
                    ))],
                    vec![memory_id.expr()],
                    prev_values.to_vec(),
                    vec![prev_ts.clone()],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Memory as u64,
                    ))],
                    vec![memory_id.expr()],
                    value.to_vec(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            let lt_cfg = cb.less_than(|| "prev_ts < ts", prev_ts, ts.clone(), Some(true))?;

            let next_ts = ts + 1.into();

            Ok((next_ts, lt_cfg))
        })
    }
}
