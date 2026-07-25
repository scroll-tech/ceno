use itertools::Itertools;

use crate::{Change, EmuContext, Platform, Tracer, VMState, WORD_SIZE, WriteOp, utils::MemoryView};

use super::{SyscallEffects, SyscallSpec, SyscallWitness};

pub const KECCAK_RATE_WORDS: usize = 34;

pub struct KeccakXorinSpec;

impl SyscallSpec for KeccakXorinSpec {
    const NAME: &'static str = "KECCAK_XORIN";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = KECCAK_RATE_WORDS * 2;
    const CODE: u32 = ceno_syscall::KECCAK_XORIN;
    const HAS_LOOKUPS: bool = true;
}

/// XOR a fixed 136-byte block into the Keccak rate portion of the state.
pub fn keccak_xorin<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let state_ptr = vm.peek_register(Platform::reg_arg0());
    let block_ptr = vm.peek_register(Platform::reg_arg1());
    let rate_bytes = (KECCAK_RATE_WORDS * WORD_SIZE) as u32;
    let state_bytes = (ceno_syscall::KECCAK_STATE_WORDS * 2 * WORD_SIZE) as u32;
    let state_end = state_ptr
        .checked_add(state_bytes)
        .expect("state range overflow");
    let block_end = block_ptr
        .checked_add(rate_bytes)
        .expect("block range overflow");
    assert!(
        state_end <= block_ptr || block_end <= state_ptr,
        "Keccak state and XOR-in block must not overlap"
    );

    let reg_ops = vec![
        WriteOp::new_register_op(Platform::reg_arg0(), Change::new(state_ptr, state_ptr), 0),
        WriteOp::new_register_op(Platform::reg_arg1(), Change::new(block_ptr, block_ptr), 0),
    ];

    let block_view = MemoryView::<_, KECCAK_RATE_WORDS>::new(vm, block_ptr);
    let block = block_view.words();
    let mut state_view = MemoryView::<_, KECCAK_RATE_WORDS>::new(vm, state_ptr);
    let state = state_view.words();
    let output = std::array::from_fn(|i| state[i] ^ block[i]);
    state_view.write(output);

    // The circuit relies on this exact ordering: all scratch reads, then all state writes.
    let mem_ops = block_view
        .mem_ops()
        .into_iter()
        .chain(state_view.mem_ops())
        .collect_vec();

    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
