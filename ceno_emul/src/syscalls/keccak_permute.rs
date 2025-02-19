use itertools::Itertools;
use tiny_keccak::keccakf;

use crate::{Change, EmuContext, Platform, VMState, Word, WriteOp, utils::MemoryView};

use super::{SyscallEffects, SyscallSpec, SyscallWitness};

const KECCAK_CELLS: usize = 25; // u64 cells
pub const KECCAK_WORDS: usize = KECCAK_CELLS * 2; // u32 words

pub struct KeccakSpec;

impl SyscallSpec for KeccakSpec {
    const NAME: &'static str = "KECCAK";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = KECCAK_WORDS;
    const CODE: u32 = ceno_rt::syscalls::KECCAK_PERMUTE;
}

/// Wrapper type for the keccak_permute argument that implements conversions
/// from and to VM word-representations according to the syscall spec
pub struct KeccakState(pub [u64; KECCAK_CELLS]);

impl From<[Word; KECCAK_WORDS]> for KeccakState {
    fn from(words: [Word; KECCAK_WORDS]) -> Self {
        KeccakState(
            words
                .chunks_exact(2)
                .map(|chunk| (chunk[0] as u64 | ((chunk[1] as u64) << 32)))
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

    // for compatibility with sp1 spec
    assert_eq!(vm.peek_register(Platform::reg_arg1()), 0);

    // Read the argument `state_ptr`.
    let reg_ops = vec![
        WriteOp::new_register_op(
            Platform::reg_arg0(),
            Change::new(state_ptr, state_ptr),
            0, // Cycle set later in finalize().
        ),
        WriteOp::new_register_op(
            Platform::reg_arg1(),
            Change::new(0, 0),
            0, // Cycle set later in finalize().
        ),
    ];

    let mut state_view = MemoryView::<KECCAK_WORDS>::new(vm, state_ptr);
    let mut state = KeccakState::from(state_view.words());
    keccakf(&mut state.0);
    let output_words: [Word; KECCAK_WORDS] = state.into();

    state_view.write(output_words);
    let mem_ops: Vec<WriteOp> = state_view.mem_ops().to_vec();

    assert_eq!(mem_ops.len(), KECCAK_WORDS);
    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
