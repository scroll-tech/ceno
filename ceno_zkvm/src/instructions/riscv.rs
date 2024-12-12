use ceno_emul::InsnKind;

mod rv32im;
pub use rv32im::{
    DummyExtraConfig, Rv32imConfig,
    mmu::{MemPadder, MmuConfig},
};

pub mod arith;
pub mod arith_imm;
pub mod branch;
pub mod config;
pub mod constants;
pub mod div;
pub mod dummy;
pub mod ecall;
pub mod jump;
pub mod logic;
pub mod logic_imm;
pub mod mul;
pub mod shift;
pub mod shift_imm;
pub mod slt;
pub mod slti;

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

pub use arith::{AddInstruction, SubInstruction};
pub use jump::{AuipcInstruction, JalInstruction, JalrInstruction, LuiInstruction};
pub use memory::{
    LbInstruction, LbuInstruction, LhInstruction, LhuInstruction, LwInstruction, SbInstruction,
    ShInstruction, SwInstruction,
};
