use goldilocks::SmallField;

use crate::{
    component::{ChipChallenges, InstCircuit},
    error::ZKVMError,
};

use super::{Instruction, InstructionGraph};

pub struct UnknownInstruction;
impl<F: SmallField> Instruction<F> for UnknownInstruction {
    fn construct_circuit(_: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        Err(ZKVMError::CircuitError)
    }
}
impl<F: SmallField> InstructionGraph<F> for UnknownInstruction {
    type InstType = Self;
}
