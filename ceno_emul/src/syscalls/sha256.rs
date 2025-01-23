use itertools::{Itertools, izip};

use crate::{Change, EmuContext, Platform, VMState, Word, WriteOp, utils::MemoryView};

use super::{SyscallEffects, SyscallWitness};

pub const SHA_EXTEND_WORDS: usize = 64; // u64 cells
const SHA_EXTEND_INITIAL_WORDS: usize = 16;

/// Wrapper type for the sha_extend argument that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct ShaExtendWords(pub [Word; SHA_EXTEND_WORDS]);

impl From<[Word; SHA_EXTEND_WORDS]> for ShaExtendWords {
    fn from(value: [Word; SHA_EXTEND_WORDS]) -> Self {
        ShaExtendWords(value)
    }
}
impl From<ShaExtendWords> for [Word; SHA_EXTEND_WORDS] {
    fn from(state: ShaExtendWords) -> [Word; SHA_EXTEND_WORDS] {
        state.0
    }
}

/// Based on: https://github.com/succinctlabs/sp1/blob/2aed8fea16a67a5b2983ffc471b2942c2f2512c8/crates/core/machine/src/syscall/precompiles/sha256/extend/mod.rs#L22
pub fn sha_extend(w: &mut [u32]) {
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
        // TODO: why doesn't sp1 use wrapping_add?
    }
}

pub fn extend(vm: &VMState) -> SyscallEffects {
    let state_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument `state_ptr`.
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(state_ptr, state_ptr),
        0, // Cycle set later in finalize().
    )];

    let state_view = MemoryView::<SHA_EXTEND_WORDS>::new(vm, state_ptr);
    let mut sha_extend_words = ShaExtendWords::from(state_view.words());
    sha_extend(&mut sha_extend_words.0);
    let output_words: [Word; SHA_EXTEND_WORDS] = sha_extend_words.into();

    // Write state changes. Note that the first 16 words do not change.
    let mem_ops = izip!(
        state_view.addrs()[SHA_EXTEND_INITIAL_WORDS..].into_iter(),
        state_view.words()[SHA_EXTEND_INITIAL_WORDS..].into_iter(),
        output_words[SHA_EXTEND_INITIAL_WORDS..].into_iter()
    )
    .map(|(&addr, &before, &after)| WriteOp {
        addr,
        value: Change { before, after },
        previous_cycle: 0, // Cycle set later in finalize().
    })
    .collect_vec();

    assert_eq!(mem_ops.len(), SHA_EXTEND_WORDS - SHA_EXTEND_INITIAL_WORDS);
    SyscallEffects {
        witness: SyscallWitness { mem_ops, reg_ops },
        next_pc: None,
    }
}
