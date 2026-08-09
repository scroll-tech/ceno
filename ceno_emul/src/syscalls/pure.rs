//! Benchmark-only, value-only syscall kernels for Pure AOT execution.
//!
//! This path deliberately does not create proof witnesses or update access
//! metadata. It may only replace a generic syscall after all pointer and shape
//! preconditions have been checked; otherwise the caller must use the normal
//! emulator path so traps and errors retain their production semantics.

use super::{
    BN254_FP_ADD, BN254_FP_MUL, BN254_FP2_ADD, BN254_FP2_MUL, KECCAK_PERMUTE, KECCAK_XORIN,
    SECP256K1_ADD, SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SECP256K1_SCALAR_INVERT,
    SECP256R1_SCALAR_INVERT, SHA_EXTEND,
    bn254::{self, BN254_FP_WORDS, BN254_FP2_WORDS},
    keccak_permute::{self, KECCAK_WORDS},
    keccak_xorin::KECCAK_RATE_WORDS,
    secp256k1::{self, COORDINATE_WORDS, SECP256K1_ARG_WORDS},
    secp256r1, sha256,
};
use crate::{Platform, WORD_SIZE, Word};

const VALUE_MASK: u64 = u32::MAX as u64;

struct PureMemory {
    cells: *mut u64,
    base_word: u32,
    end_word: u32,
}

impl PureMemory {
    fn index<const N: usize>(&self, byte_addr: u32) -> Option<usize> {
        if !byte_addr.is_multiple_of(WORD_SIZE as u32) {
            return None;
        }
        let word = byte_addr / WORD_SIZE as u32;
        let end = word.checked_add(N as u32)?;
        (word >= self.base_word && end <= self.end_word).then_some((word - self.base_word) as usize)
    }

    unsafe fn read<const N: usize>(&self, byte_addr: u32) -> Option<[Word; N]> {
        let index = self.index::<N>(byte_addr)?;
        Some(std::array::from_fn(|offset| unsafe {
            *self.cells.add(index + offset) as Word
        }))
    }

    unsafe fn write<const N: usize>(&mut self, byte_addr: u32, words: [Word; N]) -> Option<()> {
        let index = self.index::<N>(byte_addr)?;
        for (offset, word) in words.into_iter().enumerate() {
            let cell = unsafe { self.cells.add(index + offset) };
            unsafe {
                *cell = (*cell & !VALUE_MASK) | u64::from(word);
            }
        }
        Some(())
    }
}

/// Execute one supported ECALL directly against register values and packed
/// memory. Returns `false` without mutation when the generic path is required.
#[inline(never)]
pub(crate) unsafe fn execute(
    code: Word,
    registers: *mut Word,
    memory_cells: *mut u64,
    memory_base_word: u32,
    memory_end_word: u32,
) -> bool {
    let arg0 = unsafe { *registers.add(Platform::reg_arg0() as usize) };
    let arg1 = unsafe { *registers.add(Platform::reg_arg1() as usize) };
    let mut memory = PureMemory {
        cells: memory_cells,
        base_word: memory_base_word,
        end_word: memory_end_word,
    };

    match code {
        SECP256K1_DOUBLE => {
            let Some(input) = (unsafe { memory.read::<SECP256K1_ARG_WORDS>(arg0) }) else {
                return false;
            };
            unsafe { memory.write(arg0, secp256k1::double_words(input)) }.is_some()
        }
        SECP256K1_ADD => {
            let (Some(p), Some(q)) = (unsafe { memory.read(arg0) }, unsafe { memory.read(arg1) })
            else {
                return false;
            };
            unsafe { memory.write(arg0, secp256k1::add_words(p, q)) }.is_some()
        }
        KECCAK_PERMUTE => {
            let Some(input) = (unsafe { memory.read::<KECCAK_WORDS>(arg0) }) else {
                return false;
            };
            unsafe { memory.write(arg0, keccak_permute::permute_words(input)) }.is_some()
        }
        KECCAK_XORIN => {
            let state_bytes = (KECCAK_WORDS * WORD_SIZE) as u32;
            let block_bytes = (KECCAK_RATE_WORDS * WORD_SIZE) as u32;
            let (Some(state_end), Some(block_end)) =
                (arg0.checked_add(state_bytes), arg1.checked_add(block_bytes))
            else {
                return false;
            };
            if !(state_end <= arg1 || block_end <= arg0) {
                return false;
            }
            let (Some(mut state), Some(block)) =
                (unsafe { memory.read::<KECCAK_RATE_WORDS>(arg0) }, unsafe {
                    memory.read::<KECCAK_RATE_WORDS>(arg1)
                })
            else {
                return false;
            };
            for (state, block) in state.iter_mut().zip(block) {
                *state ^= block;
            }
            unsafe { memory.write(arg0, state) }.is_some()
        }
        SECP256K1_DECOMPRESS => {
            let Some(x) = (unsafe { memory.read::<COORDINATE_WORDS>(arg0) }) else {
                return false;
            };
            if arg1 > 1 {
                return false;
            }
            let Some(output_ptr) = arg0.checked_add((COORDINATE_WORDS * WORD_SIZE) as u32) else {
                return false;
            };
            if memory.index::<COORDINATE_WORDS>(output_ptr).is_none() {
                return false;
            }
            unsafe { memory.write(output_ptr, secp256k1::decompress_words(x, arg1)) }.is_some()
        }
        SECP256K1_SCALAR_INVERT => {
            let Some(input) = (unsafe { memory.read::<COORDINATE_WORDS>(arg0) }) else {
                return false;
            };
            unsafe { memory.write(arg0, secp256k1::invert_words(input)) }.is_some()
        }
        BN254_FP_ADD => binary::<BN254_FP_WORDS>(&mut memory, arg0, arg1, bn254::fp_add_words),
        BN254_FP_MUL => binary::<BN254_FP_WORDS>(&mut memory, arg0, arg1, bn254::fp_mul_words),
        BN254_FP2_ADD => binary::<BN254_FP2_WORDS>(&mut memory, arg0, arg1, bn254::fp2_add_words),
        BN254_FP2_MUL => binary::<BN254_FP2_WORDS>(&mut memory, arg0, arg1, bn254::fp2_mul_words),
        SECP256R1_SCALAR_INVERT => {
            let Some(input) = (unsafe { memory.read::<{ secp256r1::COORDINATE_WORDS }>(arg0) })
            else {
                return false;
            };
            unsafe { memory.write(arg0, secp256r1::invert_words(input)) }.is_some()
        }
        SHA_EXTEND => {
            let Some(base) = arg0.checked_sub(16 * WORD_SIZE as u32) else {
                return false;
            };
            let Some(words) = (unsafe { memory.read::<17>(base) }) else {
                return false;
            };
            let output = sha256::extend_word(words[14], words[9], words[1], words[0]);
            unsafe { memory.write(arg0, [output]) }.is_some()
        }
        _ => false,
    }
}

fn binary<const N: usize>(
    memory: &mut PureMemory,
    p_ptr: Word,
    q_ptr: Word,
    operation: fn([Word; N], [Word; N]) -> [Word; N],
) -> bool {
    let (Some(p), Some(q)) = (unsafe { memory.read(p_ptr) }, unsafe { memory.read(q_ptr) }) else {
        return false;
    };
    unsafe { memory.write(p_ptr, operation(p, q)) }.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ByteAddr, CENO_PLATFORM, EmuContext, InsnKind, Program, VMState, aot::PureAotTracer,
        encode_rv32,
    };
    use std::sync::Arc;

    fn syscall_program() -> Arc<Program> {
        Arc::new(Program::new(
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.heap.start,
            vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)],
            Default::default(),
        ))
    }

    fn compare<const N: usize>(code: Word, arg0_words: [Word; N], arg1: Word, arg1_words: &[Word]) {
        let p_ptr = CENO_PLATFORM.heap.start;
        let q_ptr = p_ptr + 0x100;
        let mut generic =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program());
        let mut direct =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program());
        for vm in [&mut generic, &mut direct] {
            vm.init_register_unsafe(Platform::reg_ecall(), code);
            vm.init_register_unsafe(Platform::reg_arg0(), p_ptr);
            vm.init_register_unsafe(
                Platform::reg_arg1(),
                if arg1_words.is_empty() { arg1 } else { q_ptr },
            );
            for (offset, word) in arg0_words.into_iter().enumerate() {
                vm.init_memory(ByteAddr(p_ptr).waddr() + offset, word);
            }
            for (offset, &word) in arg1_words.iter().enumerate() {
                vm.init_memory(ByteAddr(q_ptr).waddr() + offset, word);
            }
        }

        generic.next_step_record().unwrap();
        let direct_base = direct.memory_base_word().0;
        let direct_end = direct.memory_end_word().0;
        let handled = unsafe {
            execute(
                code,
                direct.registers_mut_ptr(),
                direct.memory_cells_mut_ptr(),
                direct_base,
                direct_end,
            )
        };
        assert!(handled);
        for offset in 0..N {
            assert_eq!(
                direct.peek_memory(ByteAddr(p_ptr).waddr() + offset),
                generic.peek_memory(ByteAddr(p_ptr).waddr() + offset),
                "code={code:#x} word={offset}",
            );
        }
    }

    #[test]
    fn direct_kernels_match_generic_syscalls() {
        compare::<KECCAK_WORDS>(KECCAK_PERMUTE, std::array::from_fn(|i| i as u32), 0, &[]);
        compare::<KECCAK_RATE_WORDS>(
            KECCAK_XORIN,
            std::array::from_fn(|i| i as u32),
            0,
            &std::array::from_fn::<_, KECCAK_RATE_WORDS, _>(|i| !(i as u32)),
        );

        let generator: [Word; SECP256K1_ARG_WORDS] =
            secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();
        let doubled = secp256k1::double_words(generator);
        compare(SECP256K1_DOUBLE, generator, 0, &[]);
        compare(SECP256K1_ADD, generator, 0, &doubled);
        let uncompressed = secp::Point::generator().serialize_uncompressed();
        let mut decompress_input = [0; SECP256K1_ARG_WORDS];
        let compressed_x: [u8; 32] = uncompressed[1..33].try_into().unwrap();
        let x_words: [Word; COORDINATE_WORDS] = unsafe { std::mem::transmute(compressed_x) };
        decompress_input[..COORDINATE_WORDS].copy_from_slice(&x_words);
        compare(
            SECP256K1_DECOMPRESS,
            decompress_input,
            Word::from(uncompressed[64] & 1),
            &[],
        );
        compare(SECP256K1_SCALAR_INVERT, [1; COORDINATE_WORDS], 0, &[]);

        compare(BN254_FP_ADD, [1; BN254_FP_WORDS], 0, &[2; BN254_FP_WORDS]);
        compare(BN254_FP_MUL, [1; BN254_FP_WORDS], 0, &[2; BN254_FP_WORDS]);
        compare(
            BN254_FP2_ADD,
            [1; BN254_FP2_WORDS],
            0,
            &[2; BN254_FP2_WORDS],
        );
        compare(
            BN254_FP2_MUL,
            [1; BN254_FP2_WORDS],
            0,
            &[2; BN254_FP2_WORDS],
        );
        compare(
            SECP256R1_SCALAR_INVERT,
            [1; secp256r1::COORDINATE_WORDS],
            0,
            &[],
        );

        let mut sha = [0; 17];
        for (index, word) in sha.iter_mut().enumerate() {
            *word = index as u32;
        }
        // SHA_EXTEND's arg0 points 16 words into its input window.
        let p_ptr = CENO_PLATFORM.heap.start;
        let mut generic =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program());
        let mut direct =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program());
        for vm in [&mut generic, &mut direct] {
            vm.init_register_unsafe(Platform::reg_ecall(), SHA_EXTEND);
            vm.init_register_unsafe(Platform::reg_arg0(), p_ptr + 16 * WORD_SIZE as u32);
            for (offset, word) in sha.into_iter().enumerate() {
                vm.init_memory(ByteAddr(p_ptr).waddr() + offset, word);
            }
        }
        generic.next_step_record().unwrap();
        let direct_base = direct.memory_base_word().0;
        let direct_end = direct.memory_end_word().0;
        assert!(unsafe {
            execute(
                SHA_EXTEND,
                direct.registers_mut_ptr(),
                direct.memory_cells_mut_ptr(),
                direct_base,
                direct_end,
            )
        });
        assert_eq!(
            direct.peek_memory(ByteAddr(p_ptr).waddr() + 16usize),
            generic.peek_memory(ByteAddr(p_ptr).waddr() + 16usize),
        );
    }

    #[test]
    fn invalid_or_unsupported_calls_require_generic_fallback() {
        let mut vm =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program());
        vm.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start + 1);
        let base = vm.memory_base_word().0;
        let end = vm.memory_end_word().0;
        assert!(!unsafe {
            execute(
                KECCAK_PERMUTE,
                vm.registers_mut_ptr(),
                vm.memory_cells_mut_ptr(),
                base,
                end,
            )
        });
        assert!(!unsafe {
            execute(
                u32::MAX,
                vm.registers_mut_ptr(),
                vm.memory_cells_mut_ptr(),
                base,
                end,
            )
        });
    }
}
