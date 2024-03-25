use goldilocks::SmallField;

use crate::{
    gas,
    primitives::{Spec, U256},
    Host, InstructionResult, Interpreter,
};
use core::cmp::max;

pub fn mload<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, index);
    let timestamps = vec![index.1];
    let index = as_usize_or_fail!(interpreter, index.0);
    shared_memory_resize!(interpreter, index, 32);
    let value = interpreter
        .shared_memory
        .read_u256(index, interpreter.memory_timestamp)
        .0;
    push!(interpreter, value);
    let operands = vec![U256::from(index), value];
    host.record(&interpreter.generate_record(&operands, &timestamps));
    interpreter.memory_timestamp += 1;
}

pub fn mstore<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, index, value);
    let mut timestamps = vec![index.1, value.1];
    let index = as_usize_or_fail!(interpreter, index.0);
    shared_memory_resize!(interpreter, index, 32);
    let (old_value, old_timestamps) =
        interpreter
            .shared_memory
            .set_u256(index, value.0, interpreter.memory_timestamp);
    timestamps.extend(old_timestamps);
    let operands = vec![U256::from(index), value.0, old_value];
    host.record(&interpreter.generate_record(&operands, &timestamps));
    interpreter.memory_timestamp += 1;
}

pub fn mstore8<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, index, value);
    let timestamps = vec![index.1, value.1];
    let index = as_usize_or_fail!(interpreter, index.0);
    shared_memory_resize!(interpreter, index, 1);
    interpreter
        .shared_memory
        .set_byte(index, value.0.byte(0), interpreter.memory_timestamp);
    let operands = vec![U256::from(index), value.0];
    host.record(&interpreter.generate_record(&operands, &timestamps));
    interpreter.memory_timestamp += 1;
}

pub fn msize<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.shared_memory.len()));
    let operands = vec![U256::from(interpreter.shared_memory.len())];
    host.record(&interpreter.generate_record(&operands, &Vec::new()));
    interpreter.memory_timestamp += 1;
}

// EIP-5656: MCOPY - Memory copying instruction
pub fn mcopy<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, CANCUN);
    pop!(interpreter, dst, src, len);

    // into usize or fail
    let len = as_usize_or_fail!(interpreter, len.0);
    // deduce gas
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    if len == 0 {
        host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
        return;
    }

    let dst = as_usize_or_fail!(interpreter, dst.0);
    let src = as_usize_or_fail!(interpreter, src.0);
    // resize memory
    shared_memory_resize!(interpreter, max(dst, src), len);
    // copy memory in place
    interpreter
        .shared_memory
        .copy(dst, src, len, interpreter.memory_timestamp);

    let operands = vec![U256::from(dst), U256::from(src), U256::from(len)];
    host.record(&interpreter.generate_record(&operands, &Vec::new()));
    interpreter.memory_timestamp += 1;
}
