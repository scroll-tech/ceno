use crate::{
    ByteAddr, Change, EmuContext, Platform, Tracer, VMState, WORD_SIZE, Word, WordAddr, WriteOp,
    utils::MemoryView,
};

use super::{SyscallEffects, SyscallSpec, SyscallWitness};

pub const SHA_EXTEND_WORDS: usize = 64; // u64 cells
pub const SHA_EXTEND_ROUND_MEM_OPS: usize = 5;

pub struct Sha256ExtendSpec;

impl SyscallSpec for Sha256ExtendSpec {
    const NAME: &'static str = "SHA256_EXTEND";

    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = SHA_EXTEND_ROUND_MEM_OPS;
    const CODE: u32 = ceno_syscall::SHA_EXTEND;
}

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

pub fn extend<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let state_ptr = vm.peek_register(Platform::reg_arg0());

    // Read the argument `state_ptr`.
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(state_ptr, state_ptr),
        0,
    )];

    let w_i_minus_2 = MemoryView::<_, 1>::new(vm, state_ptr - 2 * WORD_SIZE as u32).words()[0];
    let w_i_minus_7 = MemoryView::<_, 1>::new(vm, state_ptr - 7 * WORD_SIZE as u32).words()[0];
    let w_i_minus_15 = MemoryView::<_, 1>::new(vm, state_ptr - 15 * WORD_SIZE as u32).words()[0];
    let w_i_minus_16 = MemoryView::<_, 1>::new(vm, state_ptr - 16 * WORD_SIZE as u32).words()[0];
    let old_word = MemoryView::<_, 1>::new(vm, state_ptr).words()[0];

    let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);
    let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);
    let new_word = w_i_minus_16
        .wrapping_add(s0)
        .wrapping_add(w_i_minus_7)
        .wrapping_add(s1);

    let base = ByteAddr::from(state_ptr).waddr();
    let mem_ops = vec![
        WriteOp {
            addr: WordAddr(base.0 - 2),
            value: Change::new(w_i_minus_2, w_i_minus_2),
            previous_cycle: 0,
        },
        WriteOp {
            addr: WordAddr(base.0 - 7),
            value: Change::new(w_i_minus_7, w_i_minus_7),
            previous_cycle: 0,
        },
        WriteOp {
            addr: WordAddr(base.0 - 15),
            value: Change::new(w_i_minus_15, w_i_minus_15),
            previous_cycle: 0,
        },
        WriteOp {
            addr: WordAddr(base.0 - 16),
            value: Change::new(w_i_minus_16, w_i_minus_16),
            previous_cycle: 0,
        },
        WriteOp {
            addr: base,
            value: Change::new(old_word, new_word),
            previous_cycle: 0,
        },
    ];

    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
