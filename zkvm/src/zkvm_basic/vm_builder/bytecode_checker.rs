use goldilocks::SmallField;

use crate::structs::OpcodeType;

use super::structs::{BytecodeChecker, BytecodeCheckerBuilder};

impl<F: SmallField> BytecodeCheckerBuilder<F> {
    pub fn new() -> Self {
        todo!()
    }

    /// Set bytecode lookup table and check the code hash for basic design.
    pub fn set_bytecode_basic(&self, code_hash: &[usize], bytecode: &[usize]) {
        todo!()
    }

    /// Add bytecode lookup input for a given opcode through all execution.
    /// n_item is the number of lookup input in a single execution. n_exec is
    /// the number of execution.
    pub fn check_opcode_all_exec(&self, opcode: OpcodeType, n_item: usize, n_exec: usize) {
        todo!()
    }

    /// Set bytecode lookup table and check the code hash for pro design.
    pub fn set_bytecode_pro(&self, code_hash: &[usize], bytecode: &[usize]) {
        todo!()
    }

    /// Add bytecode lookup input for a given basic block through all execution.
    /// n_item is the number of lookup input in a single execution. n_exec is
    /// the number of execution. basic_block_id is the basic block id.
    pub fn check_block_all_exec(&self, basic_block_id: usize, n_item: usize, n_exec: usize) {
        todo!()
    }

    pub fn build_circuit(&self) -> BytecodeChecker<F> {
        todo!()
    }
}
