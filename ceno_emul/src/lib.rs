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
pub use syscalls::{
    KECCAK_PERMUTE, SECP256K1_ADD, SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SHA_EXTEND, SyscallSpec,
    keccak_permute::{KECCAK_WORDS, KeccakSpec},
    secp256k1::{
        COORDINATE_WORDS, SECP256K1_ARG_WORDS, Secp256k1AddSpec, Secp256k1DecompressSpec,
        Secp256k1DoubleSpec,
    },
    sha256::{SHA_EXTEND_WORDS, Sha256ExtendSpec},
};

pub mod utils;

pub mod test_utils;

pub mod host_utils;
