use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, ChallengeId, CircuitBuilder, MixedCell, WitnessId};

use crate::{
    constants::OpcodeType,
    error::UtilError,
    structs::{ChipChallenges, UInt},
};

pub mod bytecode;
pub mod calldata;
pub mod global_state;
pub mod memory;
pub mod ram_handler;
pub mod range;
pub mod rom_handler;
pub mod stack;

pub trait BytecodeChipOperations<Ext: ExtensionField>: ROMOperations<Ext> {
    fn bytecode_with_pc_opcode(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        opcode: OpcodeType,
    );

    fn bytecode_with_pc_byte(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        byte: CellId,
    );
}

pub trait StackChipOperations<Ext: ExtensionField>: OAMOperations<Ext> {
    fn stack_push(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
        stack_ts: &[CellId],
        values: &[CellId],
    );

    fn stack_pop(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
        stack_ts: &[CellId],
        values: &[CellId],
    );
}

pub trait RangeChipOperations<Ext: ExtensionField>: ROMOperations<Ext> {
    fn range_check_stack_top(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
    ) -> Result<(), UtilError>;

    fn range_check_uint<const M: usize, const C: usize>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        uint: &UInt<M, C>,
        range_value_witness: Option<&[CellId]>,
    ) -> Result<UInt<M, C>, UtilError>;

    fn range_check_bytes(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        bytes: &[CellId],
    ) -> Result<(), UtilError>;
}

pub trait MemoryChipOperations<Ext: ExtensionField>: RAMOperations<Ext> {
    fn mem_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        offset: &[CellId],
        old_ts: &[CellId],
        cur_ts: &[CellId],
        byte: CellId,
    );

    fn mem_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        offset: &[CellId],
        old_ts: &[CellId],
        cur_ts: &[CellId],
        old_byte: CellId,
        cur_byte: CellId,
    );
}

pub trait CalldataChipOperations<Ext: ExtensionField>: ROMOperations<Ext> {
    fn calldataload(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        offset: &[CellId],
        data: &[CellId],
    );
}

pub trait GlobalStateChipOperations<E: ExtensionField> {
    fn state_in(
        &mut self,
        circuit_builder: &mut CircuitBuilder<E>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: CellId,
        clk: CellId,
    );

    fn state_out(
        &mut self,
        circuit_builder: &mut CircuitBuilder<E>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: MixedCell<E>,
        clk: MixedCell<E>,
    );
}

pub trait ROMOperations<Ext: ExtensionField> {
    fn rom_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        key: &[CellId],
        value: &[CellId],
    );

    fn rom_load_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    );

    fn finalize(self, circuit_builder: &mut CircuitBuilder<Ext>) -> Option<(WitnessId, usize)>;
}

// Once access memory
pub trait OAMOperations<Ext: ExtensionField> {
    fn oam_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    );

    fn oam_load_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    );

    fn oam_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    );

    fn oam_store_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    );

    fn finalize(
        self,
        circuit_builder: &mut CircuitBuilder<Ext>,
    ) -> (Option<(WitnessId, usize)>, Option<(WitnessId, usize)>);
}

pub trait RAMOperations<Ext: ExtensionField>: OAMOperations<Ext> {
    fn ram_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    );

    fn ram_load_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    );

    fn ram_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        old_value: &[CellId],
        cur_value: &[CellId],
    );

    fn ram_store_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        old_value: &[MixedCell<Ext>],
        cur_value: &[MixedCell<Ext>],
    );
}

impl Default for ChipChallenges {
    fn default() -> Self {
        Self {
            record_rlc: 1,
            record_item_rlc: 0,
        }
    }
}

impl ChipChallenges {
    pub fn new(record_rlc: ChallengeId, record_item_rlc: ChallengeId) -> Self {
        Self {
            record_rlc,
            record_item_rlc,
        }
    }
    pub fn bytecode(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn stack(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn global_state(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn mem(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn range(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn calldata(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn record_item_rlc(&self) -> ChallengeId {
        self.record_item_rlc
    }
}
