use ff_ext::ExtensionField;

use crate::{
    structs::{RAMType, TSUIntV2, UInt64V2},
    structs_v2::CircuitBuilderV2,
    util_v2::{ExpressionV2, ToExpr, WitIn, ZKVMV2Error},
};

use super::RegisterChipOperations;

impl<E: ExtensionField> RegisterChipOperations<E> for CircuitBuilderV2<E> {
    fn register_read(
        &mut self,
        register_id: &WitIn,
        prev_ts: &TSUIntV2,
        ts: &TSUIntV2,
        values: &UInt64V2,
    ) -> Result<(), ZKVMV2Error> {
        // READ (a, v, t)
        let read_record = self.rlc_chip_record(
            [
                vec![ExpressionV2::<E>::Constant(E::BaseField::from(
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
                vec![ExpressionV2::<E>::Constant(E::BaseField::from(
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
        prev_ts: &TSUIntV2,
        ts: &TSUIntV2,
        prev_values: &UInt64V2,
        values: &UInt64V2,
    ) -> Result<(), ZKVMV2Error> {
        // READ (a, v, t)
        let read_record = self.rlc_chip_record(
            [
                vec![ExpressionV2::<E>::Constant(E::BaseField::from(
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
                vec![ExpressionV2::<E>::Constant(E::BaseField::from(
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
