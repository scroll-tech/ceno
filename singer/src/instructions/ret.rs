use goldilocks::SmallField;

use crate::{constants::OpcodeType, error::ZKVMError};

use super::{ChipChallenges, InstCircuit, Instruction};

pub struct ReturnInstruction;

impl Instruction for ReturnInstruction {
    const OPCODE: OpcodeType = OpcodeType::RETURN;

    fn witness_size(phase: usize) -> usize {
        todo!()
    }

    fn construct_circuit<F: SmallField>(
        challenges: &ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        todo!()
    }
}
