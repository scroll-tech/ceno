use crate::{Change, EmuContext, VMState, WORD_SIZE, WordAddr, WriteOp};
use anyhow::Result;
use itertools::{Itertools, izip};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallEvent {
    pub mem_writes: Vec<WriteOp>,
}

pub const KECCAK_PERMUTE: u32 = 0x00_01_01_09;

/// Trace the inputs and effects of a syscall.
pub fn handle_syscall(vm: &VMState, function_code: u32, arg0: u32) -> Result<SyscallEvent> {
    match function_code {
        KECCAK_PERMUTE => Ok(keccak_permute(vm, arg0)),
        _ => Err(anyhow::anyhow!("Unknown syscall: {}", function_code)),
    }
}

const KECCAK_WORDS: usize = 25 * 2;

/// Trace the execution of a Keccak permutation.
///
/// Compatible with:
/// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/precompiles/keccak256/permute.rs
///
/// TODO: test compatibility.
fn keccak_permute(vm: &VMState, state_ptr: u32) -> SyscallEvent {
    let addrs = (state_ptr..)
        .step_by(WORD_SIZE as usize)
        .take(KECCAK_WORDS)
        .map(WordAddr::from)
        .collect_vec();

    // Read Keccak state.
    let input = addrs
        .iter()
        .map(|&addr| vm.peek_memory(addr))
        .collect::<Vec<_>>();

    // TODO: Compute Keccak permutation.
    let output = input.clone();

    // Write permuted state.
    let mem_writes = izip!(addrs, input, output)
        .map(|(addr, before, after)| WriteOp {
            addr,
            value: Change { before, after },
            previous_cycle: 0, // Set later by Tracer.
        })
        .collect_vec();

    SyscallEvent { mem_writes }
}
