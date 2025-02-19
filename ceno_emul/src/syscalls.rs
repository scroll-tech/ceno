use crate::{RegIdx, Tracer, VMState, Word, WordAddr, WriteOp};
use anyhow::Result;

pub mod keccak_permute;
pub mod secp256k1;
pub mod sha256;

// Using the same function codes as sp1:
// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/code.rs

pub use ceno_rt::syscalls::{
    KECCAK_PERMUTE, SECP256K1_ADD, SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SHA_EXTEND,
};

pub trait SyscallSpec {
    const NAME: &'static str;

    const REG_OPS_COUNT: usize;
    const MEM_OPS_COUNT: usize;
    const CODE: u32;
}

/// Trace the inputs and effects of a syscall.
pub fn handle_syscall(vm: &VMState, function_code: u32) -> Result<SyscallEffects> {
    match function_code {
        KECCAK_PERMUTE => Ok(keccak_permute::keccak_permute(vm)),
        SECP256K1_ADD => Ok(secp256k1::secp256k1_add(vm)),
        SECP256K1_DOUBLE => Ok(secp256k1::secp256k1_double(vm)),
        SECP256K1_DECOMPRESS => Ok(secp256k1::secp256k1_decompress(vm)),
        SHA_EXTEND => Ok(sha256::extend(vm)),
        // TODO: introduce error types.
        _ => Err(anyhow::anyhow!("Unknown syscall: {}", function_code)),
    }
}

/// A syscall event, available to the circuit witness generators.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallWitness {
    pub mem_ops: Vec<WriteOp>,
    pub reg_ops: Vec<WriteOp>,
    _marker: (),
}

impl SyscallWitness {
    fn new(mem_ops: Vec<WriteOp>, reg_ops: Vec<WriteOp>) -> SyscallWitness {
        for (i, op) in mem_ops.iter().enumerate() {
            assert_eq!(
                op.addr,
                mem_ops[0].addr + i,
                "Dummy circuit expects that mem_ops addresses are consecutive."
            );
        }
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
    pub fn finalize(mut self, tracer: &mut Tracer) -> SyscallWitness {
        for op in &mut self.witness.reg_ops {
            op.previous_cycle = tracer.track_access(op.addr, Tracer::SUBCYCLE_RD);
        }
        for op in &mut self.witness.mem_ops {
            op.previous_cycle = tracer.track_access(op.addr, Tracer::SUBCYCLE_MEM);
        }
        self.witness
    }
}
