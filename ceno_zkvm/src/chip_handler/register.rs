use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    structs::RAMType,
};

use super::RegisterChipOperations;

impl<'a, E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR> RegisterChipOperations<E, NR, N>
    for CircuitBuilder<'a, E>
{
    fn register_read<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        name_fn: N,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        values: &V,
    ) -> Result<Expression<E>, ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    values.expr(),
                    vec![prev_ts],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    values.expr(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            // assert prev_ts < current_ts
            // TODO implement lt gadget
            // let is_lt = prev_ts.lt(self, ts)?;
            // self.require_one(is_lt)?;
            let next_ts = ts + 1.into();

            Ok(next_ts)
        })
    }

    fn register_write<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        name_fn: N,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: &V,
        values: &V,
    ) -> Result<Expression<E>, ZKVMError> {
        self.namespace(name_fn, |cb| {
            // READ (a, v, t)
            let read_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    prev_values.expr(),
                    vec![prev_ts],
                ]
                .concat(),
            );
            // Write (a, v, t)
            let write_record = cb.rlc_chip_record(
                [
                    vec![Expression::<E>::Constant(E::BaseField::from(
                        RAMType::Register as u64,
                    ))],
                    vec![register_id.expr()],
                    values.expr(),
                    vec![ts.clone()],
                ]
                .concat(),
            );
            cb.read_record(|| "read_record", read_record)?;
            cb.write_record(|| "write_record", write_record)?;

            // assert prev_ts < current_ts
            // TODO implement lt gadget
            // let is_lt = prev_ts.lt(self, ts)?;
            // self.require_one(is_lt)?;
            let next_ts = ts + 1.into();

            Ok(next_ts)
        })
    }
}
