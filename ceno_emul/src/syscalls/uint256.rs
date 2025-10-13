use crate::{
    Change, EmuContext, Platform, SyscallSpec, VMState, Word, WriteOp,
    syscalls::{SyscallEffects, SyscallWitness},
    utils::MemoryView,
};

use super::UINT256_MUL;
use itertools::Itertools;
use num::{BigUint, One, Zero};
use sp1_curves::{params::NumWords, uint256::U256Field};
use typenum::marker_traits::Unsigned;

type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
pub const UINT256_WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;
const WORD_SIZE: usize = 4;

pub(crate) struct Uint256MulSpec;

impl SyscallSpec for Uint256MulSpec {
    const NAME: &'static str = "UINT256_MUL";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 3 * UINT256_WORDS_FIELD_ELEMENT; // x, y, modulus
    const CODE: u32 = ceno_rt::syscalls::UINT256_MUL;
}

pub fn uint256_mul(vm: &VMState) -> SyscallEffects {
    let x_ptr = vm.peek_register(Platform::reg_arg0());
    let y_ptr = vm.peek_register(Platform::reg_arg1());
    let mod_ptr = y_ptr + UINT256_WORDS_FIELD_ELEMENT as u32 * WORD_SIZE as u32;

    // Read the argument pointers
    let reg_ops = vec![
        WriteOp::new_register_op(
            Platform::reg_arg0(),
            Change::new(x_ptr, x_ptr),
            0, // Cycle set later in finalize().
        ),
        WriteOp::new_register_op(
            Platform::reg_arg1(),
            Change::new(y_ptr, y_ptr),
            0, // Cycle set later in finalize().
        ),
    ];

    // Memory segments of x, y, and modulus
    let [mut x_view, y_view, mod_view] =
        [x_ptr, y_ptr, mod_ptr].map(|start| MemoryView::<UINT256_WORDS_FIELD_ELEMENT>::new(vm, start));

    // Read x and y from words via wrapper type
    let [x, y, modulus] = [&x_view, &y_view, &mod_view].map(|view| {
        BigUint::from_bytes_le(
            &view
                .words()
                .into_iter()
                .flat_map(|w| w.to_le_bytes())
                .collect_vec(),
        )
    });

    // Perform the multiplication and take the result modulo the modulus.
    let result: BigUint = if modulus.is_zero() {
        let modulus = BigUint::one() << 256;
        (x * y) % modulus
    } else {
        (x * y) % modulus
    };
    let mut result_bytes = result.to_bytes_le();
    result_bytes.resize(32, 0u8); // Pad the result to 32 bytes.

    // Convert the result to little endian u32 words.
    let result: [u32; 8] = {
        let mut iter = result_bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()));
        core::array::from_fn(|_| iter.next().unwrap())
    };
    x_view.write(result);

    let mem_ops = x_view
        .mem_ops()
        .into_iter()
        .chain(y_view.mem_ops())
        .chain(mod_view.mem_ops())
        .collect_vec();

    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
