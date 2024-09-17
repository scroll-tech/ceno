use ff_ext::ExtensionField;

use super::Instruction;
use ceno_emul::{InsnCodes, InsnKind};

pub mod addsub;
pub mod blt;
pub mod config;
pub mod constants;
mod r_insn;

#[cfg(test)]
mod test;

pub trait RIVInstruction<E: ExtensionField>: Instruction<E> {
    const INST_KIND: InsnKind;
    const OPCODE_TYPE: InsnCodes = Self::INST_KIND.codes();
}
