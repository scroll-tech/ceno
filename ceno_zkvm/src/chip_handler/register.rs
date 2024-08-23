use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    structs::{RAMType, TSUInt, UInt64},
};

use super::RegisterChipOperations;

impl<E: ExtensionField> RegisterChipOperations<E> for CircuitBuilder<E> {
    fn register_read(
        &mut self,
        register_id: &WitIn,
        prev_ts: &mut TSUInt,
        ts: &mut TSUInt,
        values: &UInt64,
    ) -> Result<TSUInt, ZKVMError> {
        // READ (a, v, t)
        let read_record = self.rlc_chip_record(
            [
                vec![Expression::<E>::Constant(E::BaseField::from(
                    RAMType::Register as u64,
                ))],
                vec![register_id.expr()],
                values.expr(),
                prev_ts.expr(),
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
                ts.expr(),
            ]
            .concat(),
        );
        self.read_record(read_record)?;
        self.write_record(write_record)?;

        // assert prev_ts < current_ts
        let is_lt = prev_ts.lt(self, ts)?;
        self.require_one(is_lt)?;
        let next_ts = ts.add_const(self, 1.into())?;

        Ok(next_ts)
    }

    fn register_write(
        &mut self,
        register_id: &WitIn,
        prev_ts: &mut TSUInt,
        ts: &mut TSUInt,
        prev_values: &UInt64,
        values: &UInt64,
    ) -> Result<TSUInt, ZKVMError> {
        // READ (a, v, t)
        let read_record = self.rlc_chip_record(
            [
                vec![Expression::<E>::Constant(E::BaseField::from(
                    RAMType::Register as u64,
                ))],
                vec![register_id.expr()],
                prev_values.expr(),
                prev_ts.expr(),
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
                ts.expr(),
            ]
            .concat(),
        );
        self.read_record(read_record)?;
        self.write_record(write_record)?;

        // assert prev_ts < current_ts
        let is_lt = prev_ts.lt(self, ts)?;
        self.require_one(is_lt)?;
        let next_ts = ts.add_const(self, 1.into())?;

        Ok(next_ts)
    }
}
