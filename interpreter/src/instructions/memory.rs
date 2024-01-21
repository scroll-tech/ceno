use goldilocks::SmallField;

use crate::{
    gas,
    primitives::{Spec, U256},
    Host, InstructionResult, Interpreter,
};
use core::cmp::max;

pub fn mload<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, index);
    let index = as_usize_or_fail!(interpreter, index.0);
    shared_memory_resize!(interpreter, index, 32);
    push!(
        interpreter,
        interpreter
            .shared_memory
            .get_u256_mut(index, interpreter.timestamp)
            .0
    );
}

pub fn mstore<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, index, value);
    let index = as_usize_or_fail!(interpreter, index.0);
    shared_memory_resize!(interpreter, index, 32);
    interpreter
        .shared_memory
        .set_u256(index, value.0, interpreter.timestamp);
}

pub fn mstore8<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, index, value);
    let index = as_usize_or_fail!(interpreter, index.0);
    shared_memory_resize!(interpreter, index, 1);
    interpreter
        .shared_memory
        .set_byte(index, value.0.byte(0), interpreter.timestamp);
}

pub fn msize<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.shared_memory.len()));
}

// EIP-5656: MCOPY - Memory copying instruction
pub fn mcopy<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    check!(interpreter, CANCUN);
    pop!(interpreter, dst, src, len);

    // into usize or fail
    let len = as_usize_or_fail!(interpreter, len.0);
    // deduce gas
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    if len == 0 {
        return;
    }

    let dst = as_usize_or_fail!(interpreter, dst.0);
    let src = as_usize_or_fail!(interpreter, src.0);
    // resize memory
    shared_memory_resize!(interpreter, max(dst, src), len);
    // copy memory in place
    interpreter
        .shared_memory
        .copy(dst, src, len, interpreter.timestamp);
}
