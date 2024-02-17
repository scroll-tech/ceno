use ff::Field;
use goldilocks::SmallField;
use simple_frontend::structs::{
    CellId, ChallengeId, CircuitBuilder, ExtCellId, MixedCell, WitnessId,
};

use crate::{constants::OpcodeType, error::ZKVMError};

use super::uint::UInt;

pub(crate) mod bytecode;
pub(crate) mod calldata;
pub(crate) mod global_state;
pub(crate) mod memory;
pub(crate) mod range;
pub(crate) mod stack;

pub(crate) trait GlobalStateChipOperations<F: SmallField> {
    fn state_in(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: CellId,
        clk: CellId,
    );

    fn state_out(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: MixedCell<F>,
        clk: MixedCell<F>,
    );
}

pub(crate) trait BytecodeChipOperations<F: SmallField> {
    fn bytecode_with_pc_opcode(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        opcode: OpcodeType,
    );

    fn bytecode_with_pc_byte(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        byte: CellId,
    );
}

pub(crate) trait StackChipOperations<F: SmallField> {
    fn stack_push(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        values: &[CellId],
    );

    fn stack_pop(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        values: &[CellId],
    );
}

pub(crate) trait RangeChipOperations<F: SmallField> {
    fn range_check_stack_top(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
    ) -> Result<(), ZKVMError>;

    fn range_check_uint<const M: usize, const C: usize>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        uint: &UInt<M, C>,
        range_value_witness: Option<&[CellId]>,
    ) -> Result<UInt<M, C>, ZKVMError>;

    fn range_check_bytes(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        bytes: &[CellId],
    ) -> Result<(), ZKVMError>;
}

pub(crate) trait MemoryChipOperations<F: SmallField> {
    fn mem_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        memory_ts: &[CellId],
        byte: CellId,
    );

    fn mem_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        memory_ts: &[CellId],
        byte: CellId,
    );
}

pub(crate) trait CalldataChip<F: SmallField> {
    fn calldataload(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        data: &[CellId],
    );
}

#[derive(Clone, Debug)]
pub(crate) struct ChipHandler<F: SmallField> {
    records: Vec<ExtCellId<F>>,
    challenge: ChallengeId,
}

impl<F: SmallField> ChipHandler<F> {
    pub(crate) fn new(challenge: ChallengeId) -> Self {
        Self {
            records: Vec::new(),
            challenge,
        }
    }

    /// Pad th remaining cells with constants, return the wire id and the number
    /// of cells.
    pub(crate) fn finalize_with_const_pad(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        constant: F::BaseField,
    ) -> (WitnessId, usize) {
        let count = self.records.len().next_power_of_two() - self.records.len();
        for _ in 0..count {
            let out = circuit_builder.create_ext_cell();
            circuit_builder.add_const(out.cells[0], constant);
            self.records.push(out);
        }
        (
            circuit_builder.create_witness_out_from_exts(&self.records),
            self.records.len(),
        )
    }

    /// Pad th remaining cells with the last one, return the wire id and the
    /// number of cells.
    pub(crate) fn finalize_with_repeated_last(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
    ) -> (WitnessId, usize) {
        let count = self.records.len().next_power_of_two() - self.records.len();
        let last = self.records[self.records.len() - 1].clone();
        for _ in 0..count {
            let out = circuit_builder.create_ext_cell();
            circuit_builder.add_ext(&out, &last, F::BaseField::ONE);
            self.records.push(out);
        }
        (
            circuit_builder.create_witness_out_from_exts(&self.records),
            self.records.len(),
        )
    }
}
