use crate::{
    ByteAddr, Change, Platform, Tracer, VMState, Word, WriteOp, rv32im::EmuContext,
    utils::MemoryView,
};

use super::{SyscallEffects, SyscallSpec, SyscallWitness};

pub const SHA_EXTEND_WORDS: usize = 64; // u64 cells

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

pub const SHA_EXTEND_ROUND_MEM_OPS: usize = 5;

pub struct ShaExtendState {
    state_ptr: Word,
    words: [Word; SHA_EXTEND_WORDS],
    round: usize,
}

impl ShaExtendState {
    pub fn new<T: Tracer>(vm: &VMState<T>) -> Self {
        let state_ptr = vm.peek_register(Platform::reg_arg0());
        let state_view = MemoryView::<_, SHA_EXTEND_WORDS>::new(vm, state_ptr);
        let words = state_view.words();
        Self {
            state_ptr,
            words,
            round: 16,
        }
    }

    pub fn is_done(&self) -> bool {
        self.round >= SHA_EXTEND_WORDS
    }

    pub fn next_round_effects(&mut self) -> Option<SyscallEffects> {
        if self.is_done() {
            return None;
        }

        let i = self.round;
        let w_i_minus_2 = self.words[i - 2];
        let w_i_minus_7 = self.words[i - 7];
        let w_i_minus_15 = self.words[i - 15];
        let w_i_minus_16 = self.words[i - 16];

        let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);
        let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);
        let new_word = w_i_minus_16
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7)
            .wrapping_add(s1);
        let old_word = self.words[i];

        self.words[i] = new_word;
        self.round += 1;

        let base = ByteAddr::from(self.state_ptr).waddr();
        let mem_ops = vec![
            WriteOp {
                addr: base + (i - 2) as u32,
                value: Change::new(w_i_minus_2, w_i_minus_2),
                previous_cycle: 0,
            },
            WriteOp {
                addr: base + (i - 7) as u32,
                value: Change::new(w_i_minus_7, w_i_minus_7),
                previous_cycle: 0,
            },
            WriteOp {
                addr: base + (i - 15) as u32,
                value: Change::new(w_i_minus_15, w_i_minus_15),
                previous_cycle: 0,
            },
            WriteOp {
                addr: base + (i - 16) as u32,
                value: Change::new(w_i_minus_16, w_i_minus_16),
                previous_cycle: 0,
            },
            WriteOp {
                addr: base + i as u32,
                value: Change::new(old_word, new_word),
                previous_cycle: 0,
            },
        ];

        let reg_ops = vec![WriteOp::new_register_op(
            Platform::reg_arg0(),
            Change::new(self.state_ptr, self.state_ptr),
            0,
        )];

        Some(SyscallEffects {
            witness: SyscallWitness::new(mem_ops, reg_ops),
            next_pc: None,
        })
    }
}

pub fn extend<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let mut state = ShaExtendState::new(vm);
    state
        .next_round_effects()
        .expect("sha_extend requires at least one round")
}
