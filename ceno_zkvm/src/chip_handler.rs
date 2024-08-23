use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    expression::WitIn,
    structs::{PCUInt, TSUInt, UInt64},
};

pub mod general;
pub mod global_state;
pub mod register;

pub trait GlobalStateRegisterMachineChipOperations<E: ExtensionField> {
    fn state_in(&mut self, pc: &PCUInt, ts: &TSUInt) -> Result<(), ZKVMError>;

    fn state_out(&mut self, pc: &PCUInt, ts: &TSUInt) -> Result<(), ZKVMError>;
}

pub trait RegisterChipOperations<E: ExtensionField> {
    fn register_read(
        &mut self,
        register_id: &WitIn,
        prev_ts: &mut TSUInt,
        ts: &mut TSUInt,
        values: &UInt64,
    ) -> Result<TSUInt, ZKVMError>;

    fn register_write(
        &mut self,
        register_id: &WitIn,
        prev_ts: &mut TSUInt,
        ts: &mut TSUInt,
        prev_values: &UInt64,
        values: &UInt64,
    ) -> Result<TSUInt, ZKVMError>;
}
