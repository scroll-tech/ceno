use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    expression::{Expression, WitIn},
    structs::{PCUInt, TSUInt, UInt64},
};

pub mod general;
pub mod global_state;
pub mod register;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(
        &mut self,
        pc: &PCUInt,
        memory_ts: &TSUInt,
        clk: Expression<E>,
    ) -> Result<(), ZKVMError>;

    fn state_out(
        &mut self,
        pc: &PCUInt,
        memory_ts: &TSUInt,
        clk: Expression<E>,
    ) -> Result<(), ZKVMError>;
}

pub trait RegisterChipOperations<E: ExtensionField> {
    fn register_read(
        &mut self,
        register_id: &WitIn,
        prev_ts: &TSUInt,
        ts: &TSUInt,
        values: &UInt64,
    ) -> Result<(), ZKVMError>;

    fn register_write(
        &mut self,
        register_id: &WitIn,
        prev_ts: &TSUInt,
        ts: &TSUInt,
        prev_values: &UInt64,
        values: &UInt64,
    ) -> Result<(), ZKVMError>;
}
