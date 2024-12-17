#![deny(clippy::cargo)]
#![feature(step_trait)]
mod addr;
pub use addr::*;

mod platform;
pub use platform::{CENO_PLATFORM, Platform};

mod tracer;
pub use tracer::{Change, MemOp, ReadOp, StepRecord, Tracer, WriteOp};

mod vm_state;
pub use vm_state::VMState;

mod rv32im;
pub use rv32im::{
    EmuContext, InsnCategory, InsnFormat, InsnKind, Instruction, encode_rv32, encode_rv32u,
};

mod elf;
pub use elf::Program;

pub mod disassemble;

mod syscalls;
pub use syscalls::{KECCAK_PERMUTE, keccak_permute::KECCAK_WORDS};

pub mod test_utils;

pub mod host_utils;
