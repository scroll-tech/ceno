use goldilocks::SmallField;

use super::i256::{i256_cmp, i256_sign_compl, two_compl, Sign};
use crate::{
    gas,
    primitives::{Spec, U256},
    Host, InstructionResult, Interpreter,
};
use core::cmp::Ordering;

pub fn lt<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = U256::from(op1.0 < *op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn gt<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = U256::from(op1.0 > *op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn slt<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = U256::from(i256_cmp(&op1.0, op2.0) == Ordering::Less);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn sgt<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = U256::from(i256_cmp(&op1.0, op2.0) == Ordering::Greater);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn eq<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = U256::from(op1.0 == *op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn iszero<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1);
    let operands = vec![*op1.0];
    let timestamps = vec![*op1.1];
    *op1.0 = U256::from(*op1.0 == U256::ZERO);
    *op1.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn bitand<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = op1.0 & *op2.0;
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn bitor<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = op1.0 | *op2.0;
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn bitxor<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = op1.0 ^ *op2.0;
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn not<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1);
    let operands = vec![*op1.0];
    let timestamps = vec![*op1.1];
    *op1.0 = !*op1.0;
    *op1.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn byte<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];

    let o1 = as_usize_saturated!(op1.0);
    *op2.0 = if o1 < 32 {
        // `31 - o1` because `byte` returns LE, while we want BE
        U256::from(op2.0.byte(31 - o1))
    } else {
        U256::ZERO
    };
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn shl<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 <<= as_usize_saturated!(op1.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn shr<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 >>= as_usize_saturated!(op1.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn sar<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];

    let value_sign = i256_sign_compl(op2.0);

    *op2.0 = if *op2.0 == U256::ZERO || op1.0 >= U256::from(256) {
        match value_sign {
            // value is 0 or >=1, pushing 0
            Sign::Plus | Sign::Zero => U256::ZERO,
            // value is <0, pushing -1
            Sign::Minus => U256::MAX,
        }
    } else {
        const ONE: U256 = U256::from_limbs([1, 0, 0, 0]);
        let shift = usize::try_from(op1.0).unwrap();
        match value_sign {
            Sign::Plus | Sign::Zero => op2.0.wrapping_shr(shift),
            Sign::Minus => two_compl(
                op2.0
                    .wrapping_sub(ONE)
                    .wrapping_shr(shift)
                    .wrapping_add(ONE),
            ),
        }
    };
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}
