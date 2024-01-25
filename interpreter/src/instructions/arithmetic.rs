use goldilocks::SmallField;

use super::i256::{i256_div, i256_mod};
use crate::{
    gas,
    primitives::{Spec, U256},
    Host, InstructionResult, Interpreter,
};

pub fn wrapped_add<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = op1.0.wrapping_add(*op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn wrapping_mul<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = op1.0.wrapping_mul(*op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn wrapping_sub<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = op1.0.wrapping_sub(*op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn div<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    if *op2.0 != U256::ZERO {
        *op2.0 = op1.0.wrapping_div(*op2.0);
    }
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn sdiv<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = i256_div(op1.0, *op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn rem<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    if *op2.0 != U256::ZERO {
        *op2.0 = op1.0.wrapping_rem(*op2.0);
    }
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn smod<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    if *op2.0 != U256::ZERO {
        *op2.0 = i256_mod(op1.0, *op2.0);
    }
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn addmod<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::MID);
    pop_top!(interpreter, op1, op2, op3);
    let operands = vec![op1.0, op2.0, *op3.0];
    let timestamps = vec![op1.1, op2.1, *op3.1];
    *op3.0 = op1.0.add_mod(op2.0, *op3.0);
    *op3.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn mulmod<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::MID);
    pop_top!(interpreter, op1, op2, op3);
    let operands = vec![op1.0, op2.0, *op3.0];
    let timestamps = vec![op1.1, op2.1, *op3.1];
    *op3.0 = op1.0.mul_mod(op2.0, *op3.0);
    *op3.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

pub fn exp<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    pop_top!(interpreter, op1, op2);
    gas_or_fail!(interpreter, gas::exp_cost::<SPEC>(*op2.0));
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    *op2.0 = op1.0.pow(*op2.0);
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}

/// In the yellow paper `SIGNEXTEND` is defined to take two inputs, we will call them
/// `x` and `y`, and produce one output. The first `t` bits of the output (numbering from the
/// left, starting from 0) are equal to the `t`-th bit of `y`, where `t` is equal to
/// `256 - 8(x + 1)`. The remaining bits of the output are equal to the corresponding bits of `y`.
/// Note: if `x >= 32` then the output is equal to `y` since `t <= 0`. To efficiently implement
/// this algorithm in the case `x < 32` we do the following. Let `b` be equal to the `t`-th bit
/// of `y` and let `s = 255 - t = 8x + 7` (this is effectively the same index as `t`, but
/// numbering the bits from the right instead of the left). We can create a bit mask which is all
/// zeros up to and including the `t`-th bit, and all ones afterwards by computing the quantity
/// `2^s - 1`. We can use this mask to compute the output depending on the value of `b`.
/// If `b == 1` then the yellow paper says the output should be all ones up to
/// and including the `t`-th bit, followed by the remaining bits of `y`; this is equal to
/// `y | !mask` where `|` is the bitwise `OR` and `!` is bitwise negation. Similarly, if
/// `b == 0` then the yellow paper says the output should start with all zeros, then end with
/// bits from `b`; this is equal to `y & mask` where `&` is bitwise `AND`.
pub fn signextend<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::LOW);
    pop_top!(interpreter, op1, op2);
    let operands = vec![op1.0, *op2.0];
    let timestamps = vec![op1.1, *op2.1];
    if op1.0 < U256::from(32) {
        // `low_u32` works since op1 < 32
        let bit_index = (8 * op1.0.as_limbs()[0] + 7) as usize;
        let bit = op2.0.bit(bit_index);
        let mask = (U256::from(1) << bit_index) - U256::from(1);
        *op2.0 = if bit { *op2.0 | !mask } else { *op2.0 & mask };
    }
    *op2.1 = interpreter.stack_timestamp;
    host.record(&interpreter.generate_record(&operands, &timestamps));
}
