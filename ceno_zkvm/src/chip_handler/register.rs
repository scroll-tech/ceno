use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    structs::RAMType,
};

use super::RegisterChipOperations;

impl<E: ExtensionField> RegisterChipOperations<E> for CircuitBuilder<E> {
    fn register_read<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        values: &V,
    ) -> Result<Expression<E>, ZKVMError> {
        // READ (a, v, t)
        let read_record = self.rlc_chip_record(
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
        let write_record = self.rlc_chip_record(
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
        self.read_record(read_record)?;
        self.write_record(write_record)?;

        // assert prev_ts < current_ts
        // TODO implement lt gadget
        // let is_lt = prev_ts.lt(self, ts)?;
        // self.require_one(is_lt)?;
        let next_ts = ts + 1.into();

        Ok(next_ts)
    }

    fn register_write<V: ToExpr<E, Output = Vec<Expression<E>>>>(
        &mut self,
        register_id: &WitIn,
        prev_ts: Expression<E>,
        ts: Expression<E>,
        prev_values: &V,
        values: &V,
    ) -> Result<Expression<E>, ZKVMError> {
        // READ (a, v, t)
        let read_record = self.rlc_chip_record(
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
        let write_record = self.rlc_chip_record(
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
        self.read_record(read_record)?;
        self.write_record(write_record)?;

        // assert prev_ts < current_ts
        // TODO implement lt gadget
        // let is_lt = prev_ts.lt(self, ts)?;
        // self.require_one(is_lt)?;
        let next_ts = ts + 1.into();

        Ok(next_ts)
    }
}
