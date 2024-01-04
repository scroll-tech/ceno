use std::collections::HashMap;

use frontend::structs::CircuitBuilder;
use gkr_graph::structs::{WireInIndex, WireOutIndex};
use goldilocks::SmallField;

use self::utils::{
    FracSumCircuitBuilder, InvSumCircuitBuilder, PadWithConstCircuitBuilder, ProductCircuitBuilder,
};

// opcodes
pub mod pop;
pub mod push;

pub mod lookup;
pub mod set_equality;
pub mod utils;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpcodeLayoutIn {
    PC,
    StackTS,
    MemoryTS,
    StackTop,

    StackPop,
    Witness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpcodeLayoutOut {
    NextPC,
    NextStackTS,
    NextMemoryTS,
    NextStackTop,

    StackPush,
    BytecodeChip,
    RangeChip,
    Memory,
    BitOpChip,
    HashChip,
}

pub struct OpcodeCircuitBuilder<F: SmallField> {
    pub(crate) circuit_builder: CircuitBuilder<F>,

    // Index of `other_witness` for each layout element.
    pub(crate) layout_in: HashMap<OpcodeLayoutIn, WireInIndex>,
    pub(crate) layout_out: HashMap<OpcodeLayoutOut, WireOutIndex>,
}

pub struct CircuitBuilderDepot<F: SmallField> {
    pub pad_with_zero: PadWithConstCircuitBuilder<F>,
    pub pad_with_one: PadWithConstCircuitBuilder<F>,
    pub inv_sum: InvSumCircuitBuilder<F>,
    pub frac_sum: FracSumCircuitBuilder<F>,
    pub product: ProductCircuitBuilder<F>,

    // basic opcodes
    pub push: OpcodeCircuitBuilder<F>,
    pub pop: OpcodeCircuitBuilder<F>,
}

impl<F: SmallField> CircuitBuilderDepot<F> {
    pub fn new_basic() -> Self {
        Self {
            pad_with_zero: PadWithConstCircuitBuilder::new(0),
            pad_with_one: PadWithConstCircuitBuilder::new(1),
            inv_sum: InvSumCircuitBuilder::new(),
            frac_sum: FracSumCircuitBuilder::new(),
            product: ProductCircuitBuilder::new(),
            push: OpcodeCircuitBuilder::push_basic(0),
            pop: OpcodeCircuitBuilder::pop_basic(0),
        }
    }

    pub fn new_pro() -> Self {
        todo!()
    }
}
