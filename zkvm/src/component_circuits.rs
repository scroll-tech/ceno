use std::collections::HashMap;

use gkr_graph::structs::{NodeWireIn, NodeWireOut};

use crate::circuit_gadgets::{OpcodeLayoutIn, OpcodeLayoutOut};
pub struct OpcodeWiresIndices {
    wires_in: HashMap<OpcodeLayoutIn, NodeWireIn>,
    wires_out: HashMap<OpcodeLayoutOut, NodeWireOut>,
}

pub struct StackWiresIndices {
    push_rlc: Vec<NodeWireIn>, // For each opcode
    pop_rlc: Vec<NodeWireIn>,  // For each opcode
}

pub struct MemoryWiresIndices {
    read_rlc: Vec<NodeWireIn>,  // For each opcode
    write_rlc: Vec<NodeWireIn>, // For each opcode
}

pub struct BytecodeChipWiresIndices {
    lookup_input_items: Vec<NodeWireIn>, // For each opcode
    lookup_table_item: NodeWireIn,
}

pub struct GlobalStateChipWiresIndices {
    state_in: Vec<NodeWireIn>,   // For each opcode
    state_out: Vec<NodeWireOut>, // For each opcode
}

pub struct RangeChipWiresIndices {
    lookup_input_items: Vec<NodeWireIn>, // For each opcode
}

pub struct BitOpChipWiresIndices {
    lookup_input_items: Vec<NodeWireIn>, // For each opcode
    lookup_table_item: NodeWireIn,
}

pub struct HashChipWiresIndices {
    lookup_input_items: Vec<NodeWireIn>, // For each opcode
    compute_table_input: NodeWireIn,
}
