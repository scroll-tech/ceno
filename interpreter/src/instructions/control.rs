use goldilocks::SmallField;
use itertools::Itertools;
use revm_primitives::Bytes;

use crate::{
    gas,
    primitives::{Spec, U256},
    Host, InstructionResult, Interpreter, InterpreterResult,
};

pub fn jump<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::MID);
    pop!(interpreter, dest);
    let timestamps = vec![dest.1];
    let dest = as_usize_or_fail!(interpreter, dest.0, InstructionResult::InvalidJump);
    let operands = vec![U256::from(dest)];
    host.record(&interpreter.generate_record(&operands, &timestamps));
    if interpreter.contract.is_valid_jump(dest) {
        // SAFETY: In analysis we are checking create our jump table and we do check above to be
        // sure that jump is safe to execute.
        interpreter.instruction_pointer =
            unsafe { interpreter.contract.bytecode.as_ptr().add(dest) };
    } else {
        interpreter.instruction_result = InstructionResult::InvalidJump;
    }
}

pub fn jumpi<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::HIGH);
    pop!(interpreter, dest, value);
    assert!(interpreter.program_counter() < interpreter.contract.bytecode.len());
    let operands = vec![
        dest.0,
        value.0,
        U256::from(unsafe { *interpreter.instruction_pointer }),
    ];
    let timestamps = vec![dest.1, value.1];
    host.record(&interpreter.generate_record(&operands, &timestamps));
    if value.0 != U256::ZERO {
        let dest = as_usize_or_fail!(interpreter, dest.0, InstructionResult::InvalidJump);
        if interpreter.contract.is_valid_jump(dest) {
            // SAFETY: In analysis we are checking if jump is valid destination and
            // this `if` makes this unsafe block safe.
            interpreter.instruction_pointer =
                unsafe { interpreter.contract.bytecode.as_ptr().add(dest) };
        } else {
            interpreter.instruction_result = InstructionResult::InvalidJump
        }
    }
}

pub fn jumpdest<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::JUMPDEST);
    host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
}

pub fn pc<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    // - 1 because we have already advanced the instruction pointer in `Interpreter::step`
    let operands = vec![U256::from(interpreter.program_counter() - 1)];
    host.record(&interpreter.generate_record(&operands, &Vec::new()));
    push!(interpreter, U256::from(interpreter.program_counter() - 1));
}

#[inline(always)]
fn return_inner<H: Host, F: SmallField>(
    interpreter: &mut Interpreter<F>,
    instruction_result: InstructionResult,
    host: &mut H,
) {
    // zero gas cost
    // gas!(interpreter, gas::ZERO);
    pop!(interpreter, offset, len);
    let mut timestamps: Vec<u64> = vec![offset.1, len.1];
    let mut output_timestamps: Vec<u64> = vec![];
    let len = as_usize_or_fail!(interpreter, len.0);
    // important: offset must be ignored if len is zeros
    let mut output = Bytes::default();
    if len != 0 {
        let offset = as_usize_or_fail!(interpreter, offset.0);
        shared_memory_resize!(interpreter, offset, len);

        output = interpreter
            .shared_memory
            .slice(offset, len)
            .0
            .to_vec()
            .into();
        output_timestamps = interpreter
            .shared_memory
            .slice(offset, len)
            .1
            .to_vec()
            .into();
    }
    let mut operands = vec![U256::from(offset.0), U256::from(len)];
    operands.extend(output.iter().map(|b| U256::from(*b)));
    timestamps.extend(output_timestamps);
    host.record(&interpreter.generate_record(&operands, &timestamps));
    interpreter.instruction_result = instruction_result;
    interpreter.next_action = Some(crate::InterpreterAction::Return {
        result: InterpreterResult {
            output,
            gas: interpreter.gas,
            result: instruction_result,
        },
    });
}

pub fn ret<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    return_inner(interpreter, InstructionResult::Return, host);
}

/// EIP-140: REVERT instruction
pub fn revert<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, BYZANTIUM);
    return_inner(interpreter, InstructionResult::Revert, host);
}

/// Stop opcode. This opcode halts the execution.
pub fn stop<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    interpreter.instruction_result = InstructionResult::Stop;
    host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
}

/// Invalid opcode. This opcode halts the execution.
pub fn invalid<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    interpreter.instruction_result = InstructionResult::InvalidFEOpcode;
    host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
}

/// Unknown opcode. This opcode halts the execution.
pub fn unknown<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    interpreter.instruction_result = InstructionResult::OpcodeNotFound;
    host.record(&interpreter.generate_record(&Vec::new(), &Vec::new()));
}
