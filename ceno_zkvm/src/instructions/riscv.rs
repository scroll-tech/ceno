use ceno_emul::InsnKind;

pub mod arith;
pub mod blt;
pub mod config;
pub mod constants;
pub mod logic;

pub mod ecall;
mod b_insn;
mod r_insn;

mod i_insn;

#[cfg(test)]
mod test;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
