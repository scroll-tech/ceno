use ceno_emul::InsnKind;

pub mod arith;
pub mod arith_imm;
pub mod branch;
pub mod config;
pub mod constants;
pub mod divu;
pub mod ecall;
pub mod jump;
pub mod logic;
pub mod mulh;
pub mod shift;
pub mod shift_imm;
pub mod sltu;

mod b_insn;
mod i_insn;
mod insn_base;
mod j_insn;
mod r_insn;
mod u_insn;

mod ecall_insn;

mod im_insn;
mod mem;
mod s_insn;
#[cfg(test)]
mod test;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
