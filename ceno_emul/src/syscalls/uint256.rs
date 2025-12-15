use crate::{
    Change, EmuContext, Platform, SyscallSpec, Tracer, VMState, WriteOp,
    syscalls::{SyscallEffects, SyscallWitness},
    utils::MemoryView,
};

use itertools::Itertools;
use num::{BigUint, One, Zero};
use sp1_curves::{
    params::NumWords,
    uint256::U256Field,
    utils::{biguint_from_le_words, biguint_to_words},
};
use typenum::marker_traits::Unsigned;

type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
pub const UINT256_WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

pub struct Uint256MulSpec;

impl SyscallSpec for Uint256MulSpec {
    const NAME: &'static str = "UINT256_MUL";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 3 * UINT256_WORDS_FIELD_ELEMENT; // x, y, modulus
    const CODE: u32 = ceno_syscall::UINT256_MUL;
}

pub fn uint256_mul<T: Tracer>(vm: &VMState<T>) -> SyscallEffects {
    let x_ptr = vm.peek_register(Platform::reg_arg0());
    let y_ptr = vm.peek_register(Platform::reg_arg1());

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
    let mut x_view = MemoryView::<_, UINT256_WORDS_FIELD_ELEMENT>::new(vm, x_ptr);
    let y_and_modulus_view = MemoryView::<_, { UINT256_WORDS_FIELD_ELEMENT * 2 }>::new(vm, y_ptr);

    // Read x, y, and modulus from words via wrapper type
    let x = biguint_from_le_words(&x_view.words());
    let y = biguint_from_le_words(&y_and_modulus_view.words()[..UINT256_WORDS_FIELD_ELEMENT]);
    let modulus = biguint_from_le_words(&y_and_modulus_view.words()[UINT256_WORDS_FIELD_ELEMENT..]);

    // Perform the multiplication and take the result modulo the modulus.
    let result: BigUint = if modulus.is_zero() {
        let modulus = BigUint::one() << 256;
        (x * y) % modulus
    } else {
        (x * y) % modulus
    };

    // Convert the result to little endian u32 words.
    let result_words = biguint_to_words(&result, UINT256_WORDS_FIELD_ELEMENT)
        .try_into()
        .unwrap();
    x_view.write(result_words);

    let mem_ops = x_view
        .mem_ops()
        .into_iter()
        .chain(y_and_modulus_view.mem_ops())
        .collect_vec();

    SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    }
}
