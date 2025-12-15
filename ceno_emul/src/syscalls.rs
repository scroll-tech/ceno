use crate::{RegIdx, TraceDriver, VMState, Word, WordAddr, WriteOp};
use anyhow::Result;

pub mod bn254;
pub mod keccak_permute;
pub mod phantom;
pub mod secp256k1;
pub mod sha256;
pub mod uint256;
// Using the same function codes as sp1:
// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/code.rs

pub use ceno_syscall::{
    BLS12381_ADD, BLS12381_DECOMPRESS, BLS12381_DOUBLE, BN254_ADD, BN254_DOUBLE, BN254_FP_ADD,
    BN254_FP_MUL, BN254_FP2_ADD, BN254_FP2_MUL, KECCAK_PERMUTE, PHANTOM_LOG_PC_CYCLE,
    SECP256K1_ADD, SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SECP256K1_SCALAR_INVERT, SECP256R1_ADD,
    SECP256R1_DECOMPRESS, SECP256R1_DOUBLE, SHA_EXTEND, UINT256_MUL,
};

pub trait SyscallSpec {
    const NAME: &'static str;

    const REG_OPS_COUNT: usize;
    const MEM_OPS_COUNT: usize;
    const CODE: u32;

    const HAS_LOOKUPS: bool = false;

    const GKR_OUTPUTS: usize = 0;
}

/// Trace the inputs and effects of a syscall.
pub fn handle_syscall<T: TraceDriver>(vm: &VMState<T>, function_code: u32) -> Result<SyscallEffects> {
    match function_code {
        KECCAK_PERMUTE => Ok(keccak_permute::keccak_permute(vm)),
        SECP256K1_ADD => Ok(secp256k1::secp256k1_add(vm)),
        SECP256K1_DOUBLE => Ok(secp256k1::secp256k1_double(vm)),
        SECP256K1_DECOMPRESS => Ok(secp256k1::secp256k1_decompress(vm)),
        SECP256K1_SCALAR_INVERT => Ok(secp256k1::secp256k1_invert(vm)),
        SHA_EXTEND => Ok(sha256::extend(vm)),
        BN254_ADD => Ok(bn254::bn254_add(vm)),
        BN254_DOUBLE => Ok(bn254::bn254_double(vm)),
        BN254_FP_ADD => Ok(bn254::bn254_fp_add(vm)),
        BN254_FP_MUL => Ok(bn254::bn254_fp_mul(vm)),
        BN254_FP2_ADD => Ok(bn254::bn254_fp2_add(vm)),
        BN254_FP2_MUL => Ok(bn254::bn254_fp2_mul(vm)),
        UINT256_MUL => Ok(uint256::uint256_mul(vm)),

        // phantom syscall
        PHANTOM_LOG_PC_CYCLE => Ok(phantom::log_pc_cycle(vm)),
        // TODO: introduce error types.
        _ => Err(anyhow::anyhow!("Unknown syscall: {}", function_code)),
    }
}

/// A syscall event, available to the circuit witness generators.
/// TODO: separate mem_ops into two stages: reads-and-writes
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallWitness {
    pub mem_ops: Vec<WriteOp>,
    pub reg_ops: Vec<WriteOp>,
    _marker: (),
}

impl SyscallWitness {
    fn new(mem_ops: Vec<WriteOp>, reg_ops: Vec<WriteOp>) -> SyscallWitness {
        SyscallWitness {
            mem_ops,
            reg_ops,
            _marker: (),
        }
    }
}

/// The effects of a syscall to apply on the VM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallEffects {
    /// The witness being built. Get it with `finalize`.
    witness: SyscallWitness,

    /// The next PC after the syscall. Defaults to the next instruction.
    pub next_pc: Option<u32>,
}

impl SyscallEffects {
    /// Iterate over the register values after the syscall.
    pub fn iter_reg_values(&self) -> impl Iterator<Item = (RegIdx, Word)> + '_ {
        self.witness
            .reg_ops
            .iter()
            .map(|op| (op.register_index(), op.value.after))
    }

    /// Iterate over the memory values after the syscall.
    pub fn iter_mem_values(&self) -> impl Iterator<Item = (WordAddr, Word)> + '_ {
        self.witness
            .mem_ops
            .iter()
            .map(|op| (op.addr, op.value.after))
    }

    /// Keep track of the cycles of registers and memory accesses.
    pub fn finalize<T: TraceDriver>(mut self, tracer: &mut T) -> SyscallWitness {
        for op in &mut self.witness.reg_ops {
            op.previous_cycle = tracer.track_access(op.addr, T::SUBCYCLE_RD);
        }
        for op in &mut self.witness.mem_ops {
            op.previous_cycle = tracer.track_access(op.addr, T::SUBCYCLE_MEM);
        }
        self.witness
    }
}
