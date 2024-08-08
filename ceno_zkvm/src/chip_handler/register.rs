use ff_ext::ExtensionField;
use singer_utils::structs::RAMType;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    structs::{TSUInt, UInt64},
};

use super::RegisterChipOperations;

impl<E: ExtensionField> RegisterChipOperations<E> for CircuitBuilder<E> {
    fn register_read(
        &mut self,
        register_id: &WitIn,
        prev_ts: &TSUInt<E>,
        ts: &TSUInt<E>,
        values: &UInt64<E>,
    ) -> Result<(), ZKVMError> {
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
        Ok(())
    }

    fn register_write(
        &mut self,
        register_id: &WitIn,
        prev_ts: &TSUInt<E>,
        ts: &TSUInt<E>,
        prev_values: &UInt64<E>,
        values: &UInt64<E>,
    ) -> Result<(), ZKVMError> {
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
        Ok(())
    }
}
