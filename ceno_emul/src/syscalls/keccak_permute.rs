use itertools::{Itertools, izip};
use tiny_keccak::keccakf;

use crate::{Change, EmuContext, Platform, VMState, WriteOp, utils::MemoryView};

use super::{SyscallEffects, SyscallWitness};

const KECCAK_CELLS: usize = 25; // u64 cells
pub const KECCAK_WORDS: usize = KECCAK_CELLS * 2; // u32 words

/// Trace the execution of a Keccak permutation.
///
/// Compatible with:
/// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/precompiles/keccak256/permute.rs
///
/// TODO: test compatibility.
pub fn keccak_permute(vm: &VMState) -> SyscallEffects {
    let state_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument `state_ptr`.
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(state_ptr, state_ptr),
        0, // Cycle set later in finalize().
    )];

    // Create a u64 view of length = KECCAK_CELLS
    let state_view = MemoryView::<u64>::new(vm, state_ptr, KECCAK_CELLS, true);

    // Interpret memory as u64 array
    let mut state: [u64; KECCAK_CELLS] = state_view.interpret().try_into().unwrap();
    keccakf(&mut state);
    let output_words = MemoryView::<u64>::into_words(state.to_vec());

    // Write permuted state.
    let mem_ops = izip!(state_view.addrs(), state_view.words(), output_words)
        .map(|(addr, before, after)| WriteOp {
            addr,
            value: Change { before, after },
            previous_cycle: 0, // Cycle set later in finalize().
        })
        .collect_vec();

    assert_eq!(mem_ops.len(), KECCAK_WORDS);
    SyscallEffects {
        witness: SyscallWitness { mem_ops, reg_ops },
        next_pc: None,
    }
}
