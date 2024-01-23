use goldilocks::Goldilocks;
use revm_interpreter::{
    analysis::to_analysed, opcode::make_instruction_table, BytecodeLocked, Contract, DummyHost,
    Interpreter, SharedMemory, EMPTY_SHARED_MEMORY,
};
use revm_primitives::{BerlinSpec, Bytecode, Bytes, Env};

fn main() {
    let contract = Contract {
        input: Bytes::new(),
        bytecode: BytecodeLocked::try_from(to_analysed(Bytecode::new_raw(Bytes::from([
            0x60, 0x01, // Push 1
            0x60, 0x02, // Push 2
            0x01, // Add
            0x60, 0x01, // Push 1
            0x53, // MStore 8 (offset = 1, add result)
            0x60, 0x01, // Push 1
            0x60, 0x01, // Push 1
            0xf3, // Return (offset = 1, length = 1)
        ]))))
        .unwrap(),
        ..Default::default()
    };
    let mut shared_memory = SharedMemory::new();
    let mut host = DummyHost::new(Env::default());
    let instruction_table = make_instruction_table::<DummyHost, Goldilocks, BerlinSpec>();
    // replace memory with empty memory to use it inside interpreter.
    // Later return memory back.
    let temp = core::mem::replace(&mut shared_memory, EMPTY_SHARED_MEMORY);
    let mut interpreter = Interpreter::new(Box::new(contract.clone()), u64::MAX, false);
    let result = interpreter.run(temp, &instruction_table, &mut host);
    shared_memory = interpreter.take_memory();
    println!("Result: {:?}", result);
    println!(
        "Shared memory: {:?}",
        shared_memory.slice(0, shared_memory.len())
    );
    println!("Final stack: {:?}", interpreter.stack());
    println!("Final records: {:?}", host.records);

    host.clear();
}
