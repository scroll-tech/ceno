use std::collections::HashMap;

use frontend::structs::CircuitBuilder;
use gkr::structs::Circuit;
use goldilocks::SmallField;

pub enum OpcodeLayout {
    PC,
    StackTimestamp,
    MemoryTimestamp,
    StackTop,

    NextPC,
    NextStackTimestamp,
    NextMemoryTimestamp,
    NextStackTop,

    StackIn,
    Witness,

    StackOut,
    BytecodeCheck,
    RangeCheck,
    MemCheck,
    BitOpCheck,
    HashCheck,
}

pub struct OpcodeProcessor<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment corresponding to the opcode layout.
    wire_in: HashMap<OpcodeLayout, usize>,
    wire_out: HashMap<OpcodeLayout, usize>,
}

pub struct Stack<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment of push operations for each opcode (If applicable).
    opcode_push: HashMap<usize, usize>,
    /// The witness segment of pop operations for each opcode (If applicable).
    opcode_pop: HashMap<usize, usize>,
}

pub struct Memory<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment of load operations for each opcode (If applicable).
    opcode_load: HashMap<usize, usize>,
    /// The witness segment of store operations for each opcode (If applicable).
    opcode_store: HashMap<usize, usize>,
}

pub struct GlobalStateChecker<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment of input state for each opcode (or block).
    state_in: Vec<usize>,
    /// The witness segment of output state for each opcode (or block).
    state_out: Vec<usize>,
}

pub struct BytecodeChecker<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment of bytecode.
    bytecode: usize,
    /// The witness segment of code hash.
    code_hash: usize,
    /// The witness segment of bytecode checking item from each opcode.
    opcode_check: Vec<usize>,
}

pub struct RangeChecker<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment of range check for each opcode (If applicable).
    opcode_check: HashMap<usize, usize>,
}

pub struct BitOpProcessor<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment of bit operations for each opcode (If applicable).
    opcode_check: HashMap<usize, usize>,
}

pub struct Hasher<F: SmallField> {
    circuit: Circuit<F>,

    /// The witness segment of hash check for each opcode (If applicable).
    opcode_check: HashMap<usize, usize>,
}

pub struct OpcodeProcessorBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}

pub struct StackBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}

pub struct MemoryBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}

pub struct GlobalStateCheckerBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}

pub struct BytecodeCheckerBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}

pub struct RangeCheckerBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}

pub struct BitOpProcessorBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}

pub struct HasherBuilder<F: SmallField> {
    circuit_builder: CircuitBuilder<F>,
}
