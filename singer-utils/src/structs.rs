use ff_ext::ExtensionField;
use simple_frontend::structs::{ChallengeId, ExtCellId};
use strum_macros::EnumIter;
use uint::UInt;

use crate::{
    constants::{EVM_STACK_BIT_WIDTH, VALUE_BIT_WIDTH},
    uint,
};

#[derive(Clone, Debug, Copy, EnumIter)]
pub enum RAMType {
    Stack,
    Memory,
    GlobalState,
    Register,
}

#[derive(Clone, Debug, Copy, EnumIter)]
pub enum ROMType {
    Bytecode,
    Calldata,
    Range,
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum InstOutChipType {
    RAMLoad,
    RAMStore,
    ROMInput,
}

#[derive(Clone, Copy, Debug)]
pub struct ChipChallenges {
    // Challenges for multiple-tuple chip records
    pub(super) record_rlc: ChallengeId,
    // Challenges for multiple-cell values
    pub(super) record_item_rlc: ChallengeId,
}

pub type UInt64 = UInt<64, VALUE_BIT_WIDTH>;
pub type PCUInt = UInt64;
pub type TSUInt = UInt<48, 48>;
pub type StackUInt = UInt<{ EVM_STACK_BIT_WIDTH as usize }, { VALUE_BIT_WIDTH as usize }>;
