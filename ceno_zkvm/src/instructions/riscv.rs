use ceno_emul::InsnKind;

pub mod arith;
pub mod blt;
pub mod config;
pub mod constants;
pub mod divu;
pub mod logic;

mod b_insn;
mod r_insn;

#[cfg(test)]
mod test;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
