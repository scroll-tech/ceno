use goldilocks::SmallField;

use crate::{
    gas,
    primitives::{Spec, U256},
    Host, InstructionResult, Interpreter,
};

pub fn pop<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    if let Err(result) = interpreter.stack.pop() {
        interpreter.instruction_result = result;
    }
    let operands = if interpreter.stack.len() > 0 {
        unsafe { vec![*interpreter.stack.top_unsafe().0] }
    } else {
        Vec::new()
    };
    host.record(&interpreter.generate_record(&operands));
}

/// EIP-3855: PUSH0 instruction
///
/// Introduce a new instruction which pushes the constant value 0 onto the stack.
pub fn push0<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, SHANGHAI);
    gas!(interpreter, gas::BASE);
    if let Err(result) = interpreter.stack.push(U256::ZERO, interpreter.timestamp) {
        interpreter.instruction_result = result;
    }
    host.record(&interpreter.generate_record(&Vec::new()));
}

pub fn push<const N: usize, H: Host, F: SmallField>(
    interpreter: &mut Interpreter<F>,
    host: &mut H,
) {
    gas!(interpreter, gas::VERYLOW);
    // SAFETY: In analysis we append trailing bytes to the bytecode so that this is safe to do
    // without bounds checking.
    let ip = interpreter.instruction_pointer;
    if let Err(result) = interpreter.stack.push_slice(
        unsafe { core::slice::from_raw_parts(ip, N) },
        interpreter.timestamp,
    ) {
        interpreter.instruction_result = result;
        host.record(&interpreter.generate_record(&Vec::new()));
        return;
    }
    interpreter.instruction_pointer = unsafe { ip.add(N) };
    let n_words = (N + 31) / 32;
    let operands = interpreter.stack.data()[interpreter.stack.len() - n_words..].to_vec();
    host.record(&interpreter.generate_record(&operands));
}

pub fn dup<const N: usize, H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    if let Err(result) = interpreter.stack.dup::<N>(interpreter.timestamp) {
        interpreter.instruction_result = result;
        host.record(&interpreter.generate_record(&Vec::new()));
    } else {
        let operands = interpreter.stack.data()[interpreter.stack.len() - N..].to_vec();
        host.record(&interpreter.generate_record(&operands));
    }
}

pub fn swap<const N: usize, H: Host, F: SmallField>(
    interpreter: &mut Interpreter<F>,
    host: &mut H,
) {
    gas!(interpreter, gas::VERYLOW);
    if let Err(result) = interpreter.stack.swap::<N>(interpreter.timestamp) {
        interpreter.instruction_result = result;
        host.record(&interpreter.generate_record(&Vec::new()));
    } else {
        let operands = vec![
            interpreter.stack.data()[interpreter.stack.len() - 1 - N],
            interpreter.stack.data()[interpreter.stack.len() - 1],
        ];
        host.record(&interpreter.generate_record(&operands));
    }
}
