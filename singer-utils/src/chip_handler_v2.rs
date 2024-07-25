use ff_ext::ExtensionField;

use crate::{
    structs::PCUInt,
    util_v2::{CircuitBuilderV2, WitIn, ZKVMV2Error},
};

pub mod general;
pub mod global_state;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(
        &mut self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        pc: &PCUInt,
        memory_ts: &[WitIn],
        clk: &WitIn,
    ) -> Result<(), ZKVMV2Error>;

    fn state_out(
        &mut self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        pc: &PCUInt,
        memory_ts: &[WitIn],
        clk: &WitIn,
    ) -> Result<(), ZKVMV2Error>;
}

pub trait RegisterChipOperations<E: ExtensionField> {
    fn register_read(
        &mut self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        register_id: &[CellId],
        timestamp: &[CellId],
        values: &[CellId],
    );

    fn register_store(
        &mut self,
        circuit_builder: &mut CircuitBuilderV2<E>,
        register_id: &[CellId],
        timestamp: &[CellId],
        values: &[CellId],
    );
}
