use ceno_emul::InsnKind;

pub mod arith;
mod b_insn;
pub mod blt;
pub mod branch;
pub mod config;
pub mod constants;
pub mod divu;
pub mod ecall;
mod i_insn;
pub mod logic;

mod ecall_insn;
mod r_insn;
pub mod shift_imm;

#[cfg(test)]
mod test;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
