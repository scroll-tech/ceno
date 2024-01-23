use goldilocks::SmallField;

use crate::{
    gas,
    primitives::{Spec, B256, KECCAK_EMPTY, U256},
    Host, InstructionResult, Interpreter,
};

pub fn keccak256<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    pop!(interpreter, from, len);
    let len = as_usize_or_fail!(interpreter, len.0);
    gas_or_fail!(interpreter, gas::keccak256_cost(len as u64));
    let hash = if len == 0 {
        KECCAK_EMPTY
    } else {
        let from = as_usize_or_fail!(interpreter, from.0);
        shared_memory_resize!(interpreter, from, len);
        crate::primitives::keccak256(interpreter.shared_memory.slice(from, len).0)
    };

    push_b256!(interpreter, hash);
}

pub fn address<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push_b256!(interpreter, interpreter.contract.address.into_word());
}

pub fn caller<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push_b256!(interpreter, interpreter.contract.caller.into_word());
}

pub fn codesize<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.contract.bytecode.len()));
}

pub fn codecopy<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    pop!(interpreter, memory_offset, code_offset, len);
    let len = as_usize_or_fail!(interpreter, len.0);
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    if len == 0 {
        return;
    }
    let memory_offset = as_usize_or_fail!(interpreter, memory_offset.0);
    let code_offset = as_usize_saturated!(code_offset.0);
    shared_memory_resize!(interpreter, memory_offset, len);

    // Note: this can't panic because we resized memory to fit.
    interpreter.shared_memory.set_data(
        memory_offset,
        code_offset,
        len,
        interpreter.contract.bytecode.original_bytecode_slice(),
        interpreter.timestamp,
    );
}

pub fn calldataload<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::VERYLOW);
    pop!(interpreter, index);
    let index = as_usize_saturated!(index.0);
    let load = if index < interpreter.contract.input.len() {
        let have_bytes = 32.min(interpreter.contract.input.len() - index);
        let mut bytes = [0u8; 32];
        bytes[..have_bytes].copy_from_slice(&interpreter.contract.input[index..index + have_bytes]);
        B256::new(bytes)
    } else {
        B256::ZERO
    };

    push_b256!(interpreter, load);
}

pub fn calldatasize<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.contract.input.len()));
}

pub fn callvalue<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, interpreter.contract.value);
}

pub fn calldatacopy<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    pop!(interpreter, memory_offset, data_offset, len);
    let len = as_usize_or_fail!(interpreter, len.0);
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    if len == 0 {
        return;
    }
    let memory_offset = as_usize_or_fail!(interpreter, memory_offset.0);
    let data_offset = as_usize_saturated!(data_offset.0);
    shared_memory_resize!(interpreter, memory_offset, len);

    // Note: this can't panic because we resized memory to fit.
    interpreter.shared_memory.set_data(
        memory_offset,
        data_offset,
        len,
        &interpreter.contract.input,
        interpreter.timestamp,
    );
}

/// EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
pub fn returndatasize<H: Host, F: SmallField, SPEC: Spec>(
    interpreter: &mut Interpreter<F>,
    _host: &mut H,
) {
    check!(interpreter, BYZANTIUM);
    gas!(interpreter, gas::BASE);
    push!(
        interpreter,
        U256::from(interpreter.return_data_buffer.len())
    );
}

/// EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
pub fn returndatacopy<H: Host, F: SmallField, SPEC: Spec>(
    interpreter: &mut Interpreter<F>,
    _host: &mut H,
) {
    check!(interpreter, BYZANTIUM);
    pop!(interpreter, memory_offset, offset, len);
    let len = as_usize_or_fail!(interpreter, len.0);
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    let data_offset = as_usize_saturated!(offset.0);
    let (data_end, overflow) = data_offset.overflowing_add(len);
    if overflow || data_end > interpreter.return_data_buffer.len() {
        interpreter.instruction_result = InstructionResult::OutOfOffset;
        return;
    }
    if len != 0 {
        let memory_offset = as_usize_or_fail!(interpreter, memory_offset.0);
        shared_memory_resize!(interpreter, memory_offset, len);
        interpreter.shared_memory.set(
            memory_offset,
            &interpreter.return_data_buffer[data_offset..data_end],
            interpreter.timestamp,
        );
    }
}

pub fn gas<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, _host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.gas.remaining()));
}
