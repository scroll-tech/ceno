use itertools::{Itertools, izip};
use tiny_keccak::keccakf;

use crate::{Change, EmuContext, Platform, VMState, WORD_SIZE, WordAddr, WriteOp};

use super::{SyscallEffects, SyscallWitness};

const KECCAK_CELLS: usize = 25; // u64 cells
const KECCAK_WORDS: usize = KECCAK_CELLS * 2; // u32 words

/// Trace the execution of a Keccak permutation.
///
/// Compatible with:
/// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/precompiles/keccak256/permute.rs
///
/// TODO: test compatibility.
pub fn keccak_permute(vm: &VMState) -> SyscallEffects {
    let state_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument `state_ptr`.
    let reg_accesses = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(state_ptr, state_ptr),
        0, // Cycle set later in finalize().
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
            previous_cycle: 0, // Cycle set later in finalize().
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
