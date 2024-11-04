use ceno_emul::InsnKind;

mod rv32im;
pub use rv32im::Rv32imConfig;

pub mod arith;
pub mod arith_imm;
pub mod branch;
pub mod config;
pub mod constants;
pub mod divu;
pub mod ecall;
pub mod jump;
pub mod logic;
pub mod logic_imm;
pub mod mulh;
pub mod shift;
pub mod shift_imm;
pub mod slt;
pub mod slti;
pub mod sltu;

mod b_insn;
mod i_insn;
mod insn_base;
mod j_insn;
mod r_insn;
mod u_insn;

mod ecall_insn;

mod im_insn;
mod memory;
mod s_insn;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_utils;

pub trait RIVInstruction {
    const INST_KIND: InsnKind;
}
