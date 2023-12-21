use std::collections::HashMap;

use gkr::structs::CircuitWitness;
use goldilocks::SmallField;

use crate::structs::OpcodeType;
use crate::zkvm_basic::vm_builder::structs::{
    BitOpProcessor, BytecodeChecker, GlobalStateChecker, Hasher, Memory, OpcodeProcessor,
    RangeChecker, Stack,
};
use crate::zkvm_basic::vm_builder::structs::{
    BitOpProcessorBuilder, BytecodeCheckerBuilder, GlobalStateCheckerBuilder, HasherBuilder,
    MemoryBuilder, OpcodeProcessorBuilder, RangeCheckerBuilder, StackBuilder,
};
use crate::zkvm_basic::vm_interpreter::structs::{GlobalStats, OpcodeStats};

pub struct VMBasic<F: SmallField> {
    pub opcode_processor: HashMap<OpcodeType, OpcodeProcessor<F>>,
    pub stack: Stack<F>,
    pub memory: Memory<F>,

    pub global_state_checker: GlobalStateChecker<F>,

    pub bytecode: BytecodeChecker<F>,
    pub bit_op_processor: BitOpProcessor<F>,
    pub range_checker: RangeChecker<F>,
    pub hasher: Hasher<F>,
}

pub struct VMBasicWitness<F: SmallField> {
    pub opcode_processor: HashMap<OpcodeType, CircuitWitness<F>>,
    pub stack: CircuitWitness<F>,
    pub memory: CircuitWitness<F>,
    pub global_state_checker: CircuitWitness<F>,
    pub bytecode: CircuitWitness<F>,
    pub bit_op_processor: CircuitWitness<F>,
    pub range_checker: CircuitWitness<F>,
    pub hasher: CircuitWitness<F>,
}

// VM Builder includes builder for each component.
pub struct VMBasicBuilder<F: SmallField> {
    /// Build each type of opcode.
    opcode_processor_builders: HashMap<OpcodeType, OpcodeProcessorBuilder<F>>,
    stack_builder: StackBuilder<F>,
    memory_builder: Option<MemoryBuilder<F>>,

    global_state_checker_builder: GlobalStateCheckerBuilder<F>,

    bytecode_builder: BytecodeCheckerBuilder<F>,
    bit_op_builder: Option<BitOpProcessorBuilder<F>>,
    range_checker_builder: Option<RangeCheckerBuilder<F>>,
    hasher_builder: Option<HasherBuilder<F>>,
}

pub(crate) type U256 = [u8; 32];

/// VM interpreter to running trace for bytecode with given input.
pub struct VMBasicInterpreter<F: SmallField> {
    pub(crate) program_counter: usize,
    pub(crate) stack: Vec<U256>,
    pub(crate) memory: HashMap<U256, U256>,

    pub(crate) opcode_stats: HashMap<OpcodeType, OpcodeStats<F>>,
    pub(crate) global_stats: GlobalStats,
}
