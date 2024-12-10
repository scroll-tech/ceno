use crate::{
    Change, EmuContext, Platform, RegIdx, Tracer, VMState, WORD_SIZE, Word, WordAddr, WriteOp,
};
use anyhow::Result;
use itertools::{Itertools, chain, izip};
use tiny_keccak::keccakf;

/// A syscall event, available to the circuit witness generators.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallWitness {
    pub mem_writes: Vec<WriteOp>,
    pub reg_accesses: Vec<WriteOp>,
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
            .reg_accesses
            .iter()
            .map(|op| (op.register_index(), op.value.after))
    }

    /// Iterate over the memory values after the syscall.
    pub fn iter_mem_values(&self) -> impl Iterator<Item = (WordAddr, Word)> + '_ {
        self.witness
            .mem_writes
            .iter()
            .map(|op| (op.addr, op.value.after))
    }

    /// Keep track of the cycles of registers and memory accesses.
    pub fn finalize(mut self, tracer: &mut Tracer) -> SyscallWitness {
        for op in chain(&mut self.witness.reg_accesses, &mut self.witness.mem_writes) {
            op.previous_cycle = tracer.track_access(op.addr, 0);
        }
        self.witness
    }
}

pub const KECCAK_PERMUTE: u32 = 0x00_01_01_09;

/// Trace the inputs and effects of a syscall.
pub fn handle_syscall(vm: &VMState, function_code: u32) -> Result<SyscallEffects> {
    match function_code {
        KECCAK_PERMUTE => Ok(keccak_permute(vm)),
        _ => Err(anyhow::anyhow!("Unknown syscall: {}", function_code)),
    }
}

const KECCAK_CELLS: usize = 25; // u64 cells
const KECCAK_WORDS: usize = KECCAK_CELLS * 2; // u32 words

/// Trace the execution of a Keccak permutation.
///
/// Compatible with:
/// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/precompiles/keccak256/permute.rs
///
/// TODO: test compatibility.
fn keccak_permute(vm: &VMState) -> SyscallEffects {
    let state_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument `state_ptr`.
    let reg_accesses = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(state_ptr, state_ptr),
        0, // Set later by Tracer.
    )];

    let addrs = (state_ptr..)
        .step_by(WORD_SIZE)
        .take(KECCAK_WORDS)
        .map(WordAddr::from)
        .collect_vec();

    // Read Keccak state.
    let input = addrs
        .iter()
        .map(|&addr| vm.peek_memory(addr))
        .collect::<Vec<_>>();

    // Compute Keccak permutation.
    let output = {
        let mut state = [0_u64; KECCAK_CELLS];
        izip!(state.iter_mut(), input.chunks_exact(2)).for_each(|(cell, chunk)| {
            let lo = chunk[0] as u64;
            let hi = chunk[1] as u64;
            *cell = lo | hi << 32;
        });
        keccakf(&mut state);
        state.into_iter().flat_map(|c| [c as u32, (c >> 32) as u32])
    };

    // Write permuted state.
    let mem_writes = izip!(addrs, input, output)
        .map(|(addr, before, after)| WriteOp {
            addr,
            value: Change { before, after },
            previous_cycle: 0, // Set later by Tracer.
        })
        .collect_vec();

    assert_eq!(mem_writes.len(), KECCAK_WORDS);
    SyscallEffects {
        witness: SyscallWitness {
            mem_writes,
            reg_accesses,
        },
        next_pc: None,
    }
}
