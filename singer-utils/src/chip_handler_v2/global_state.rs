use ff_ext::ExtensionField;

use crate::{
    structs::RAMType,
    structs_v2::CircuitBuilderV2,
    util_v2::{ExpressionV2, ZKVMV2Error},
};

use super::GlobalStateRegisterMachineChipOperations;

impl<E: ExtensionField> GlobalStateRegisterMachineChipOperations<E> for CircuitBuilderV2<E> {
    fn state_in(
        &mut self,
        pc: &crate::structs::PCUIntV2,
        memory_ts: &crate::structs::TSUIntV2,
        clk: ExpressionV2<E>,
    ) -> Result<(), ZKVMV2Error> {
        let items: Vec<ExpressionV2<E>> = [
            vec![ExpressionV2::Constant(E::BaseField::from(
                RAMType::GlobalState as u64,
            ))],
            pc.expr(),
            memory_ts.expr(),
            vec![clk],
        ]
        .concat();

        let rlc_record = self.rlc_chip_record(items);
        self.read_record(rlc_record)
    }

    fn state_out(
        &mut self,
        pc: &crate::structs::PCUIntV2,
        memory_ts: &crate::structs::TSUIntV2,
        clk: ExpressionV2<E>,
    ) -> Result<(), ZKVMV2Error> {
        let items: Vec<ExpressionV2<E>> = [
            vec![ExpressionV2::Constant(E::BaseField::from(
                RAMType::GlobalState as u64,
            ))],
            pc.expr(),
            memory_ts.expr(),
            vec![clk],
        ]
        .concat();

        let rlc_record = self.rlc_chip_record(items);
        self.write_record(rlc_record)
    }
}
