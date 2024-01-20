use std::sync::Arc;

use frontend::structs::WireId;
use gkr::structs::Circuit;
use goldilocks::SmallField;
use strum_macros::EnumIter;

use crate::{constants::OpcodeType, error::ZKVMError};

use self::{
    add::AddInstruction, calldataload::CalldataloadInstruction, dup::DupInstruction,
    gt::GtInstruction, jump::JumpInstruction, jumpdest::JumpdestInstruction,
    jumpi::JumpiInstruction, mstore::MstoreInstruction, pop::PopInstruction, push::PushInstruction,
    ret::ReturnInstruction, swap::SwapInstruction,
};

#[macro_use]
mod macros;

// arithmetic
pub mod add;

// bitwise
pub mod gt;

// control
pub mod jump;
pub mod jumpdest;
pub mod jumpi;
pub mod ret;

// stack
pub mod dup;
pub mod pop;
pub mod push;
pub mod swap;

// memory
pub mod mstore;

// system
pub mod calldataload;

pub mod utils;

#[derive(Clone, Copy, Debug, Default)]
pub struct ChipChallenges {
    // Challenges for multiple-tuple chip records
    record_rlc: usize,
    // Challenges for multiple-cell values
    record_item_rlc: usize,
}

impl ChipChallenges {
    pub fn new() -> Self {
        Self {
            record_rlc: 2,
            record_item_rlc: 1,
        }
    }
    pub fn bytecode(&self) -> usize {
        self.record_rlc
    }
    pub fn stack(&self) -> usize {
        self.record_rlc
    }
    pub fn global_state(&self) -> usize {
        self.record_rlc
    }
    pub fn mem(&self) -> usize {
        self.record_rlc
    }
    pub fn range(&self) -> usize {
        self.record_rlc
    }
    pub fn calldata(&self) -> usize {
        self.record_rlc
    }
    pub fn record_item_rlc(&self) -> usize {
        self.record_item_rlc
    }
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub(crate) enum InstOutputType {
    GlobalStateIn,
    GlobalStateOut,
    BytecodeChip,
    StackPop,
    StackPush,
    RangeChip,
    MemoryLoad,
    MemoryStore,
    CalldataChip,
}

#[derive(Clone, Debug)]
pub struct InstCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,

    // Wires out index
    pub(crate) outputs_wire_id: [Option<WireId>; 9],

    // Wires in index
    pub(crate) phases_wire_id: [Option<WireId>; 2],
}

pub(crate) fn construct_opcode_circuit<F: SmallField>(
    opcode: u8,
    challenges: &ChipChallenges,
) -> Result<InstCircuit<F>, ZKVMError> {
    match opcode {
        0x01 => AddInstruction::construct_circuit(challenges),
        0x11 => GtInstruction::construct_circuit(challenges),
        0x35 => CalldataloadInstruction::construct_circuit(challenges),
        0x50 => PopInstruction::construct_circuit(challenges),
        0x52 => MstoreInstruction::construct_circuit(challenges),
        0x56 => JumpInstruction::construct_circuit(challenges),
        0x57 => JumpiInstruction::construct_circuit(challenges),
        0x5B => JumpdestInstruction::construct_circuit(challenges),
        0x60 => PushInstruction::<1>::construct_circuit(challenges),
        0x80 => DupInstruction::<1>::construct_circuit(challenges),
        0x81 => DupInstruction::<2>::construct_circuit(challenges),
        0x91 => SwapInstruction::<2>::construct_circuit(challenges),
        0x93 => SwapInstruction::<4>::construct_circuit(challenges),
        0xF3 => ReturnInstruction::construct_circuit(challenges),
        _ => unimplemented!(),
    }
}

pub(crate) fn witness_size(opcode: u8, phase: usize) -> usize {
    match opcode {
        0x01 => AddInstruction::witness_size(phase),
        0x11 => GtInstruction::witness_size(phase),
        0x35 => CalldataloadInstruction::witness_size(phase),
        0x50 => PopInstruction::witness_size(phase),
        0x52 => MstoreInstruction::witness_size(phase),
        0x56 => JumpInstruction::witness_size(phase),
        0x57 => JumpiInstruction::witness_size(phase),
        0x5B => JumpdestInstruction::witness_size(phase),
        0x60 => PushInstruction::<1>::witness_size(phase),
        0x80 => DupInstruction::<1>::witness_size(phase),
        0x81 => DupInstruction::<2>::witness_size(phase),
        0x91 => SwapInstruction::<2>::witness_size(phase),
        0x93 => SwapInstruction::<4>::witness_size(phase),
        0xF3 => ReturnInstruction::witness_size(phase),
        _ => unimplemented!(),
    }
}

pub(crate) fn output_size(opcode: u8, inst_out: InstOutputType) -> usize {
    match opcode {
        0x01 => AddInstruction::output_size(inst_out),
        0x11 => GtInstruction::output_size(inst_out),
        0x35 => CalldataloadInstruction::output_size(inst_out),
        0x50 => PopInstruction::output_size(inst_out),
        0x52 => MstoreInstruction::output_size(inst_out),
        0x56 => JumpInstruction::output_size(inst_out),
        0x57 => JumpiInstruction::output_size(inst_out),
        0x5B => JumpdestInstruction::output_size(inst_out),
        0x60 => PushInstruction::<1>::output_size(inst_out),
        0x80 => DupInstruction::<1>::output_size(inst_out),
        0x81 => DupInstruction::<2>::output_size(inst_out),
        0x91 => SwapInstruction::<2>::output_size(inst_out),
        0x93 => SwapInstruction::<4>::output_size(inst_out),
        0xF3 => ReturnInstruction::output_size(inst_out),
        _ => unimplemented!(),
    }
}

#[derive(Clone, Debug)]
pub struct InstInfo<F: SmallField> {
    _marker: std::marker::PhantomData<F>,
}
pub(crate) trait Instruction {
    const OPCODE: OpcodeType;

    fn witness_size(phase: usize) -> usize;
    fn output_size(inst_out: InstOutputType) -> usize;

    fn construct_circuit<F: SmallField>(
        challenges: &ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError>;
}
