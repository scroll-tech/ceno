#![deny(clippy::cargo)]
#![feature(step_trait)]
mod addr;
pub use addr::*;

mod dense_addr_space;

mod platform;
pub use platform::{CENO_PLATFORM, Platform};

mod tracer;
pub use tracer::{
    Change, FullTracer, LatestAccesses, MemOp, NextAccessPair, NextCycleAccess, PreflightTracer,
    PreflightTracerConfig, ReadOp, ShardPlanBuilder, StepCellExtractor, StepRecord, Tracer, WriteOp,
};

mod vm_state;
pub use vm_state::{HaltState, VM_REG_COUNT, VMState};

mod rv32im;
pub use rv32im::{
    EmuContext, InsnCategory, InsnFormat, InsnKind, Instruction, encode_rv32, encode_rv32u,
};

mod elf;
pub use elf::Program;

pub mod disassemble;

mod syscalls;
pub use syscalls::{
    BLS12381_ADD, BLS12381_DECOMPRESS, BLS12381_DOUBLE, BN254_ADD, BN254_DOUBLE, BN254_FP_ADD,
    BN254_FP_MUL, BN254_FP2_ADD, BN254_FP2_MUL, KECCAK_PERMUTE, SECP256K1_ADD,
    SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SECP256K1_SCALAR_INVERT, SECP256R1_ADD,
    SECP256R1_DECOMPRESS, SECP256R1_DOUBLE, SECP256R1_SCALAR_INVERT, SHA_EXTEND, SyscallSpec,
    UINT256_MUL,
    bn254::{
        BN254_FP_WORDS, BN254_FP2_WORDS, BN254_POINT_WORDS, Bn254AddSpec, Bn254DoubleSpec,
        Bn254Fp2AddSpec, Bn254Fp2MulSpec, Bn254FpAddSpec, Bn254FpMulSpec,
    },
    keccak_permute::{KECCAK_WORDS, KeccakSpec},
    phantom::LogPcCycleSpec,
    secp256k1::{
        COORDINATE_WORDS as SECP256K1_COORDINATE_WORDS, SECP256K1_ARG_WORDS, Secp256k1AddSpec,
        Secp256k1DecompressSpec, Secp256k1DoubleSpec, Secp256k1ScalarInvertSpec,
    },
    secp256r1::{
        COORDINATE_WORDS as SECP256R1_COORDINATE_WORDS, SECP256R1_ARG_WORDS, Secp256r1AddSpec,
        Secp256r1DoubleSpec, Secp256r1ScalarInvertSpec,
    },
    sha256::{SHA_EXTEND_WORDS, Sha256ExtendSpec},
    uint256::{UINT256_WORDS_FIELD_ELEMENT, Uint256MulSpec},
};

pub mod utils;

pub mod host_utils;
pub mod test_utils;
