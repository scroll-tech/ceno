use crate::{Change, EmuContext, VMState, WORD_SIZE, WordAddr, WriteOp};
use anyhow::Result;
use itertools::{Itertools, izip};
use tiny_keccak::keccakf;

/// A syscall event, available to the circuit witness generators.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallWitness {
    pub mem_writes: Vec<WriteOp>,
}

/// The effects of a syscall to apply on the VM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallEffects {
    pub witness: SyscallWitness,
    pub return_value: Option<u32>,
    pub next_pc: Option<u32>,
}

pub const KECCAK_PERMUTE: u32 = 0x00_01_01_09;

/// Trace the inputs and effects of a syscall.
pub fn handle_syscall(vm: &VMState, function_code: u32, arg0: u32) -> Result<SyscallEffects> {
    match function_code {
        KECCAK_PERMUTE => Ok(keccak_permute(vm, arg0)),
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
fn keccak_permute(vm: &VMState, state_ptr: u32) -> SyscallEffects {
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
        witness: SyscallWitness { mem_writes },
        return_value: None,
        next_pc: None,
    }
}
