use goldilocks::SmallField;

use crate::{
    gas,
    primitives::{Spec, SpecId::*, U256},
    Host, InstructionResult, Interpreter,
};

/// EIP-1344: ChainID opcode
pub fn chainid<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, ISTANBUL);
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(host.env().cfg.chain_id));
    let operands = vec![U256::from(host.env().cfg.chain_id)];
    host.record(&interpreter.generate_record(&operands));
}

pub fn coinbase<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push_b256!(interpreter, host.env().block.coinbase.into_word());
    let operands = vec![U256::try_from(host.env().block.coinbase.into_word()).unwrap()];
    host.record(&interpreter.generate_record(&operands));
}

pub fn timestamp<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, host.env().block.timestamp);
    let operands = vec![host.env().block.timestamp];
    host.record(&interpreter.generate_record(&operands));
}

pub fn number<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, host.env().block.number);
    let operands = vec![host.env().block.number];
    host.record(&interpreter.generate_record(&operands));
}

pub fn difficulty<H: Host, F: SmallField, SPEC: Spec>(
    interpreter: &mut Interpreter<F>,
    host: &mut H,
) {
    gas!(interpreter, gas::BASE);
    if SPEC::enabled(MERGE) {
        push_b256!(interpreter, host.env().block.prevrandao.unwrap());
        let operands = vec![U256::try_from(host.env().block.prevrandao.unwrap()).unwrap()];
        host.record(&interpreter.generate_record(&operands));
    } else {
        push!(interpreter, host.env().block.difficulty);
        let operands = vec![host.env().block.difficulty];
        host.record(&interpreter.generate_record(&operands));
    }
}

pub fn gaslimit<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, host.env().block.gas_limit);
    let operands = vec![host.env().block.gas_limit];
    host.record(&interpreter.generate_record(&operands));
}

pub fn gasprice<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, host.env().effective_gas_price());
    let operands = vec![host.env().effective_gas_price()];
    host.record(&interpreter.generate_record(&operands));
}

/// EIP-3198: BASEFEE opcode
pub fn basefee<H: Host, F: SmallField, SPEC: Spec>(interpreter: &mut Interpreter<F>, host: &mut H) {
    check!(interpreter, LONDON);
    gas!(interpreter, gas::BASE);
    push!(interpreter, host.env().block.basefee);
    let operands = vec![host.env().block.basefee];
    host.record(&interpreter.generate_record(&operands));
}

pub fn origin<H: Host, F: SmallField>(interpreter: &mut Interpreter<F>, host: &mut H) {
    gas!(interpreter, gas::BASE);
    push_b256!(interpreter, host.env().tx.caller.into_word());
    let operands = vec![U256::try_from(host.env().tx.caller.into_word()).unwrap()];
    host.record(&interpreter.generate_record(&operands));
}

// EIP-4844: Shard Blob Transactions
pub fn blob_hash<H: Host, F: SmallField, SPEC: Spec>(
    interpreter: &mut Interpreter<F>,
    host: &mut H,
) {
    check!(interpreter, CANCUN);
    gas!(interpreter, gas::VERYLOW);
    pop_top!(interpreter, index);
    let i = as_usize_saturated!(index.0);
    *index.0 = match host.env().tx.blob_hashes.get(i) {
        Some(hash) => U256::from_be_bytes(hash.0),
        None => U256::ZERO,
    };
    *index.1 = interpreter.stack_timestamp;
    let operands = vec![U256::from(i), *index.0];
    host.record(&interpreter.generate_record(&operands));
}

/// EIP-7516: BLOBBASEFEE opcode
pub fn blob_basefee<H: Host, F: SmallField, SPEC: Spec>(
    interpreter: &mut Interpreter<F>,
    host: &mut H,
) {
    check!(interpreter, CANCUN);
    gas!(interpreter, gas::BASE);
    push!(
        interpreter,
        U256::from(host.env().block.get_blob_gasprice().unwrap_or_default())
    );
    let operands = vec![U256::from(
        host.env().block.get_blob_gasprice().unwrap_or_default(),
    )];
    host.record(&interpreter.generate_record(&operands));
}
