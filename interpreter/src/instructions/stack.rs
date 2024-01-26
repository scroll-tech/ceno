use goldilocks::SmallField;

use crate::{
    gas,
    primitives::{Spec, U256},
    Host, InstructionResult, Interpreter,
};

pub fn pop<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    let result = interpreter.stack.pop();
    interpreter.stack_timestamp += 1;
    match result {
        Ok(result) => {
            let operands = vec![result.0];
            let timestamps = vec![result.1];
            host.record(&interpreter.generate_record(&operands, &timestamps));
        }
        Err(result) => {
            interpreter.instruction_result = result;
            host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
        }
    }
}

/// EIP-3855: PUSH0 instruction
///
/// Introduce a new instruction which pushes the constant value 0 onto the stack.
pub fn push0<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, SHANGHAI);
    gas!(interpreter, gas::BASE);
    if let Err(result) = interpreter
        .stack
        .push(U256::ZERO, interpreter.stack_timestamp)
    {
        interpreter.instruction_result = result;
    }
    host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
    interpreter.stack_timestamp += 1;
}

pub fn push<const N: usize, H: Host, F: SmallField>(
    interpreter: &mut Interpreter<F>,
    host: &mut H,
) {
    gas!(interpreter, gas::VERYLOW);
    // SAFETY: In analysis we append trailing bytes to the bytecode so that this is safe to do
    // without bounds checking.
    let ip = interpreter.instruction_pointer;
    let pushed_data = unsafe { core::slice::from_raw_parts(ip, N) };
    if let Err(result) = interpreter
        .stack
        .push_slice(pushed_data, interpreter.stack_timestamp)
    {
        interpreter.instruction_result = result;
        host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
        return;
    }
    interpreter.instruction_pointer = unsafe { ip.add(N) };
    let operands = pushed_data.to_vec().into_iter().map(U256::from).collect();
    host.record(&interpreter.generate_record(&operands, &Vec::new()));
    interpreter.stack_timestamp += 1;
}

pub fn dup<const N: usize, H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    let result = interpreter.stack.dup::<N>(interpreter.stack_timestamp);
    interpreter.stack_timestamp += 1;
    match result {
        Ok(result) => {
            let operands = vec![result.0];
            let timestamps = vec![result.1];
            host.record(&interpreter.generate_record(&operands, &timestamps));
        }
        Err(result) => {
            interpreter.instruction_result = result;
            host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
        }
    }
}

pub fn swap<const N: usize, H: Host, F: SmallField>(
    interpreter: &mut Interpreter<F>,
    host: &mut H,
) {
    gas!(interpreter, gas::VERYLOW);
    let result = interpreter.stack.swap::<N>(interpreter.stack_timestamp);
    interpreter.stack_timestamp += 1;
    match result {
        Ok(result) => {
            let operands = vec![result.0, result.2];
            let timestamps = vec![result.1, result.3];
            host.record(&interpreter.generate_record(&operands, &timestamps));
        }
        Err(result) => {
            interpreter.instruction_result = result;
            host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
        }
    }
}
