use ceno_emul::InsnKind;

pub mod arith;
mod b_insn;
pub mod blt;
pub mod branch;
pub mod config;
pub mod constants;
mod i_insn;
pub mod logic;
mod r_insn;
pub mod srli;

#[cfg(test)]
mod test;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
