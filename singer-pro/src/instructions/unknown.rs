use ff_ext::ExtensionField;
use singer_utils::structs::ChipChallenges;

use crate::{component::InstCircuit, error::ZKVMError};

use super::{Instruction, InstructionGraph};

pub struct UnknownInstruction;
impl<E: ExtensionField> Instruction<E> for UnknownInstruction {
    fn construct_circuit(_: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        Err(ZKVMError::CircuitError)
    }
}
impl<E: ExtensionField> InstructionGraph<E> for UnknownInstruction {
    type InstType = Self;
}
