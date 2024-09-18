use ceno_emul::InsnKind;

pub mod addsub;
pub mod blt;
pub mod config;
pub mod constants;

mod r_insn;

#[cfg(test)]
mod test;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
