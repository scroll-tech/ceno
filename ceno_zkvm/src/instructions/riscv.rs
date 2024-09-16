use ceno_emul::{FastDecodeEntry, InsnKind, RV32IM_ISA};
use ff_ext::ExtensionField;

use super::Instruction;

pub mod addsub;
pub mod blt;
pub mod config;
pub mod constants;
mod gadgets;

#[cfg(test)]
mod test;

pub trait RIVInstruction<E: ExtensionField>: Instruction<E> {
    const INST_KIND: InsnKind;
    const OPCODE_TYPE: FastDecodeEntry = RV32IM_ISA[Self::INST_KIND as usize];
}
