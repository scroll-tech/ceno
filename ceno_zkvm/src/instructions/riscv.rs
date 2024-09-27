use ceno_emul::InsnKind;

pub mod arith;
pub mod arith_imm;
pub mod branch;
pub mod config;
pub mod constants;
pub mod divu;
mod i_insn;
pub mod logic;
pub mod sltu;

mod b_insn;
mod r_insn;
pub mod shift_imm;

#[cfg(test)]
mod test;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
