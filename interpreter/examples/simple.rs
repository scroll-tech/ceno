use revm_interpreter::{
    analysis::to_analysed, opcode::make_instruction_table, BytecodeLocked, Contract, DummyHost,
    Interpreter, SharedMemory, EMPTY_SHARED_MEMORY,
};
use revm_primitives::{BerlinSpec, Bytecode, Bytes, Env};

fn main() {
    let contract = Contract {
        input: Bytes::new(),
        bytecode: BytecodeLocked::try_from(to_analysed(Bytecode::new_raw(Bytes::from([
            0x60, 0x01, 0x50, 0xf3,
        ]))))
        .unwrap(),
        ..Default::default()
    };
    let mut shared_memory = SharedMemory::new();
    let mut host = DummyHost::new(Env::default());
    let instruction_table = make_instruction_table::<DummyHost, BerlinSpec>();
    // replace memory with empty memory to use it inside interpreter.
    // Later return memory back.
    let temp = core::mem::replace(&mut shared_memory, EMPTY_SHARED_MEMORY);
    let mut interpreter = Interpreter::new(Box::new(contract.clone()), u64::MAX, false);
    let _ = interpreter.run(temp, &instruction_table, &mut host);
    shared_memory = interpreter.take_memory();
    host.clear();
}
