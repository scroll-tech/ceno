use ff_ext::ExtensionField;

use crate::{
    structs::RAMType,
    util_v2::{CircuitBuilderV2, ExpressionV2, ToExpr, ZKVMV2Error},
};

use super::GlobalStateRegisterMachineChipOperations;

impl<E: ExtensionField> GlobalStateRegisterMachineChipOperations<E> for CircuitBuilderV2<E> {
    fn state_in(
        &mut self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        pc: &crate::structs::PCUInt,
        memory_ts: &[crate::util_v2::WitIn],
        clk: &crate::util_v2::WitIn,
    ) -> Result<(), ZKVMV2Error> {
        let items: [ExpressionV2<E>] = [
            vec![E::BaseField::from(RAMType::GlobalState as u64).into()],
            pc.expr(),
            memory_ts.iter().map(|limb| limb.expr()),
            vec![clk.expr()],
        ]
        .concat();

        let rlc_record = circuit_builder.rlc_chip_record(items);
        circuit_builder.read_record(rlc_record)
    }

    fn state_out(
        &mut self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        pc: &crate::structs::PCUInt,
        memory_ts: &[crate::util_v2::WitIn],
        clk: &crate::util_v2::WitIn,
    ) -> Result<(), ZKVMV2Error> {
        let items: [ExpressionV2<E>] = [
            vec![E::BaseField::from(RAMType::GlobalState as u64).into()],
            pc.expr(),
            memory_ts.iter().map(|limb| limb.expr()),
            vec![clk.expr()],
        ]
        .concat();

        let rlc_record = circuit_builder.rlc_chip_record(items);
        circuit_builder.write_record(rlc_record)
    }
}
