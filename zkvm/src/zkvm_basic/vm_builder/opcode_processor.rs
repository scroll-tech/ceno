use goldilocks::SmallField;

use crate::structs::OpcodeType;

use super::structs::OpcodeProcessorBuilder;

impl<F: SmallField> OpcodeProcessorBuilder<F> {
    fn new() -> Self {
        todo!()
    }

    fn add_opcode(&self, opcode: OpcodeType) {
        todo!()
    }

    fn add_opcode_sequence(&self, basic_block_id: usize, opcode_sequence: &[OpcodeType]) {
        todo!()
    }

    pub fn build_circuit(&self) {
        todo!()
    }
}
