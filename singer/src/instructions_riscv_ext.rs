use ff_ext::ExtensionField;
use singer_utils::{
    chips::IntoEnumIterator,
    riscv_constant::{RV64IOpcode, RvInstructions, RvOpcode},
    structs::ChipChallenges,
};

use crate::{
    error::ZKVMError,
    instructions::{riscv, InstCircuit, InstructionGraph, SingerCircuitBuilder},
};

impl<E: ExtensionField> SingerCircuitBuilder<E> {
    pub fn new_riscv(challenges: ChipChallenges) -> Result<Self, ZKVMError> {
        let ins_len = RvInstructions::END as usize;
        let mut insts_circuits = Vec::with_capacity(256);
        for opcode in RvInstructions::iter() {
            insts_circuits.push(construct_instruction_circuits(opcode.into(), challenges)?);
        }
        for _ in ins_len..255 {
            insts_circuits.push(construct_instruction_circuits(RvInstructions::END.into(), challenges)?);
        }
        let insts_circuits: [Vec<InstCircuit<E>>; 256] =
            insts_circuits.try_into().map_err(|_| ZKVMError::CircuitError)?;
        Ok(Self {
            insts_circuits,
            challenges,
        })
    }
}

fn process_opcode_r<E: ExtensionField>(
    instruction: RvOpcode,
    challenges: ChipChallenges,
) -> Result<Vec<InstCircuit<E>>, ZKVMError> {
    // Find the instruction format here:
    // https://fraserinnovations.com/risc-v/risc-v-instruction-set-explanation/
    match instruction.funct3 {
        0b000 => match instruction.funct7 {
            0b000_0000 => riscv::add::AddInstruction::construct_circuits(challenges),
            _ => Ok(vec![]), // TODO: Add more operations.
        },
        _ => Ok(vec![]), // TODO: Add more instructions.
    }
}

pub(crate) fn construct_instruction_circuits<E: ExtensionField>(
    instruction: RvOpcode,
    challenges: ChipChallenges,
) -> Result<Vec<InstCircuit<E>>, ZKVMError> {
    match instruction.opcode {
        RV64IOpcode::R => process_opcode_r(instruction, challenges),
        _ => Ok(vec![]), // TODO: Add more instructions.
    }
}
