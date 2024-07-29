use ff_ext::ExtensionField;

use crate::{
    structs::{PCUIntV2, TSUIntV2, UInt64V2},
    util_v2::{ExpressionV2, WitIn, ZKVMV2Error},
};

pub mod general;
pub mod global_state;
pub mod register;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(
        &mut self,
        pc: &PCUIntV2,
        memory_ts: &TSUIntV2,
        clk: ExpressionV2<E>,
    ) -> Result<(), ZKVMV2Error>;

    fn state_out(
        &mut self,
        pc: &PCUIntV2,
        memory_ts: &TSUIntV2,
        clk: ExpressionV2<E>,
    ) -> Result<(), ZKVMV2Error>;
}

pub trait RegisterChipOperations<E: ExtensionField> {
    fn register_read(
        &mut self,
        register_id: &WitIn,
        prev_ts: &TSUIntV2,
        ts: &TSUIntV2,
        values: &UInt64V2,
    ) -> Result<(), ZKVMV2Error>;

    fn register_write(
        &mut self,
        register_id: &WitIn,
        prev_ts: &TSUIntV2,
        ts: &TSUIntV2,
        prev_values: &UInt64V2,
        values: &UInt64V2,
    ) -> Result<(), ZKVMV2Error>;
}
