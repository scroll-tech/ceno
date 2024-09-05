use constants::OpcodeType;
use ff_ext::ExtensionField;

use super::Instruction;

pub mod addsub;
pub mod blt;
pub mod config;
pub mod constants;

#[cfg(test)]
mod test;

pub trait RIVInstruction<E: ExtensionField>: Instruction<E> {
    const OPCODE_TYPE: OpcodeType;
}
