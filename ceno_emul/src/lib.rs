#![deny(clippy::cargo)]
#![feature(step_trait)]
mod addr;
pub use addr::*;

mod dense_addr_space;

mod platform;
pub use platform::{CENO_PLATFORM, Platform};

pub mod tensor;

mod tracer;
pub use tracer::{
    Change, ChipCostSpec, FullTracer, FullTracerConfig, GpuReplayChunk, GpuReplayFallbackRecord,
    GpuReplayStep, GpuReplayTracer, GpuReplayTracerConfig, LatestAccesses, MemOp, NextAccessEvent,
    NextAccessPair, NextAccessTape, NextCycleAccess, PreflightTracer, PreflightTracerConfig,
    ReadOp, ReplayChunk, ReplayEngine, ReplayStopReason, SHARD_COST_BUCKETS, ShardCostModel,
    ShardPlanBuilder, StepCellExtractor, StepIndex, StepRecord, TensorSegmentPlan, Tracer, WriteOp,
};

mod compact_journal;
pub use compact_journal::{
    COMPACT_SHARD_JOURNAL_MAGIC, COMPACT_SHARD_JOURNAL_VERSION, CompactArenaDescriptorV1,
    CompactArenaKind, CompactMemoryAccessV1, CompactOpcodeRecordV1, CompactRegisterReadV1,
    CompactRegisterWriteV1, CompactShardJournalV1, CompactShardSummaryV1, CompactSyscallAccessV1,
    CompactSyscallRecordV1, CompactWitnessRecordSink, JournalValidationError,
    LegacyWitnessRecordSink, WitnessRecordSink, compact_journal_layout_fingerprint,
};

mod gpu_replay;
mod gpu_typed_ingress;
pub use gpu_replay::{GpuReplayRoutingError, GpuReplayShardArenas, GpuReplayTypedRange};
pub use gpu_typed_ingress::{
    CONTINUATION_ADDRESS_SEND_BOUND, GpuReplayFallbackInterval, GpuReplayRangeDescriptor,
    GpuShardPreview, GpuTypedKindSpec, GpuTypedLayout, GpuTypedSoaArena,
    MAX_SPARSE_ADDRESS_SENDS_PER_STEP, gpu_typed_kind_spec,
};

mod vm_state;
pub use vm_state::{HaltState, VM_REG_COUNT, VMState};

#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
pub mod aot;

mod rv32im;
pub use rv32im::{
    EmuContext, InsnCategory, InsnFormat, InsnKind, Instruction, encode_rv32, encode_rv32u,
};

mod elf;
pub use elf::Program;

pub mod disassemble;

mod syscalls;
#[cfg(feature = "llama-tiny")]
pub use syscalls::tensor::TensorBatchedMatMul2x2V1Spec;
pub use syscalls::{
    BLS12381_ADD, BLS12381_DECOMPRESS, BLS12381_DOUBLE, BN254_ADD, BN254_DOUBLE, BN254_FP_ADD,
    BN254_FP_MUL, BN254_FP2_ADD, BN254_FP2_MUL, KECCAK_PERMUTE, KECCAK_XORIN, PubIoCommitSpec,
    SECP256K1_ADD, SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SECP256K1_SCALAR_INVERT, SECP256R1_ADD,
    SECP256R1_DECOMPRESS, SECP256R1_DOUBLE, SECP256R1_SCALAR_INVERT, SHA_EXTEND,
    STATE_CONTINUATION, SyscallSpec, SyscallWitness, UINT256_MUL,
    bn254::{
        BN254_FP_WORDS, BN254_FP2_WORDS, BN254_POINT_WORDS, Bn254AddSpec, Bn254DoubleSpec,
        Bn254Fp2AddSpec, Bn254Fp2MulSpec, Bn254FpAddSpec, Bn254FpMulSpec,
    },
    keccak_permute::{KECCAK_WORDS, KeccakSpec},
    keccak_xorin::{KECCAK_RATE_WORDS, KeccakXorinSpec},
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
    tensor::{
        ATTENTION_REDUCED_PROFILE_V1, ATTENTION_RESCALE_SHIFT_Q20_V1,
        ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1, ATTENTION_SOFTMAX_TABLE_REDUCED_V1,
        BLOCK_REDUCED_PROFILE_V1, FFN_TABLE_COMMITMENT_V1, FFN_TABLE_REDUCED_V1,
        TENSOR_BUS_FIXED_TRANSFER_WORDS, TENSOR_SIGNATURE_2X3X2, TensorAttentionBlockReducedV1Spec,
        TensorAttentionReducedV1Spec, TensorExportEndV1Spec, TensorFfnBlockReducedV1Spec,
        TensorHandleAttentionV1Spec, TensorHandleFfnV1Spec, TensorImportBeginV1Spec,
        TensorMatMulHiddenV1Spec, TensorMatMulIntermediateV1Spec, TensorMatMulV1Spec,
        TensorRmsLookupV1Spec,
    },
    uint256::{UINT256_WORDS_FIELD_ELEMENT, Uint256MulSpec},
};

pub mod utils;

pub mod host_utils;
pub mod test_utils;
