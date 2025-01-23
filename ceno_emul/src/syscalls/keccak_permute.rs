use itertools::{Itertools, izip};
use tiny_keccak::keccakf;

use crate::{Change, EmuContext, Platform, VMState, Word, WriteOp, utils::MemoryView};

use super::{SyscallEffects, SyscallWitness};

const KECCAK_CELLS: usize = 25; // u64 cells
pub const KECCAK_WORDS: usize = KECCAK_CELLS * 2; // u32 words

/// Wrapper type for the keccak_permute argument that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct KeccakState(pub [u64; KECCAK_CELLS]);

impl From<[Word; KECCAK_WORDS]> for KeccakState {
    fn from(words: [Word; KECCAK_WORDS]) -> Self {
        KeccakState(
            words
                .chunks_exact(2)
                .map(|chunk| (chunk[0] as u64 | (chunk[1] as u64) << 32))
                .collect_vec()
                .try_into()
                .expect("failed to parse words into [u64; 25]"),
        )
    }
}

impl From<KeccakState> for [Word; KECCAK_WORDS] {
    fn from(state: KeccakState) -> [Word; KECCAK_WORDS] {
        state
            .0
            .iter()
            .flat_map(|&elem| [elem as u32, (elem >> 32) as u32])
            .collect_vec()
            .try_into()
            .unwrap()
    }
}

/// Trace the execution of a Keccak permutation.
///
/// Compatible with:
/// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/precompiles/keccak256/permute.rs
pub fn keccak_permute(vm: &VMState) -> SyscallEffects {
    let state_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument `state_ptr`.
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(state_ptr, state_ptr),
        0, // Cycle set later in finalize().
    )];

    let state_view = MemoryView::<KECCAK_WORDS>::new(vm, state_ptr);
    let mut state = KeccakState::from(state_view.words());
    keccakf(&mut state.0);
    let output_words: [Word; KECCAK_WORDS] = state.into();

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
