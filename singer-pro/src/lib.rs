#![feature(generic_const_exprs)]
#![feature(const_trait_impl)]

use basic_block::SingerBasicBlockBuilder;
use chips::LookupChipType;
use chips::SingerChipBuilder;
use component::ChipChallenges;
use component::ChipType;
use error::ZKVMError;
use gkr_graph::structs::CircuitGraph;
use gkr_graph::structs::CircuitGraphBuilder;
use gkr_graph::structs::CircuitGraphWitness;
use gkr_graph::structs::NodeOutputType;
use goldilocks::SmallField;
use std::mem;

#[macro_use]
mod macros;

pub mod basic_block;
pub mod chips;
pub mod component;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod scheme;
pub(crate) mod utils;

// Process sketch:
// 1. Construct instruction circuits and circuit gadgets => circuit gadgets
// 2. (bytecode + input) => Run revm interpreter, generate all wires in
//      2.1 phase 0 wire in + commitment
//      2.2 phase 1 wire in + commitment
//      2.3 phase 2 wire in + commitment
// 3. (circuit gadgets + wires in) => gkr graph + gkr witness
// 4. (gkr graph + gkr witness) => (gkr proof + point)
// 5. (commitments + point) => pcs proof

/// Circuit graph builder for Singer pro. `output_wires_id` is indexed by
/// ChipType, corresponding to the product of summation of the chip check
/// records. `public_output_size` is the wire id stores the size of public
/// output.
pub struct SingerGraphBuilder<F: SmallField> {
    graph_builder: CircuitGraphBuilder<F>,
    bb_builder: SingerBasicBlockBuilder<F>,
    chip_builder: SingerChipBuilder<F>,
    public_output_size: Option<NodeOutputType>,
    challenges: ChipChallenges,
}

impl<F: SmallField> SingerGraphBuilder<F> {
    pub fn new(
        bb_builder: SingerBasicBlockBuilder<F>,
        chip_builder: SingerChipBuilder<F>,
        challenges: ChipChallenges,
    ) -> Result<Self, ZKVMError> {
        Ok(Self {
            graph_builder: CircuitGraphBuilder::new(),
            bb_builder,
            chip_builder,
            challenges,
            public_output_size: None,
        })
    }

    pub fn construct(
        mut self,
        singer_wires_in: SingerWiresIn<F::BaseField>,
        program_input: &[u8],
        program_output: &[u8],
        real_challenges: &[F],
        params: SingerParams,
    ) -> Result<
        (
            SingerCircuit<F>,
            SingerWitness<F::BaseField>,
            SingerWiresOutID,
        ),
        ZKVMError,
    > {
        let basic_blocks = self.bb_builder.basic_block_bytecode();
        // Construct tables for lookup arguments, including bytecode, range and
        self.bb_builder.construct_gkr_graph(
            &mut self.graph_builder,
            &mut self.chip_builder,
            singer_wires_in.basic_blocks,
            real_challenges,
            params,
        )?;
        // calldata.
        let table_out_node_id = self.chip_builder.construct_chip_tables(
            &mut self.graph_builder,
            &basic_blocks,
            program_input,
            singer_wires_in.table_count_witnesses,
            &self.challenges,
            real_challenges,
        )?;

        let mut output_wires_id = self.chip_builder.output_wires_id;

        let singer_wire_out_id = SingerWiresOutID {
            global_state_in: mem::take(&mut output_wires_id[ChipType::GlobalStateIn as usize]),
            global_state_out: mem::take(&mut output_wires_id[ChipType::GlobalStateOut as usize]),
            bytecode_chip_input: mem::take(&mut output_wires_id[ChipType::BytecodeChip as usize]),
            bytecode_chip_table: table_out_node_id[LookupChipType::BytecodeChip as usize],
            stack_push: mem::take(&mut output_wires_id[ChipType::StackPush as usize]),
            stack_pop: mem::take(&mut output_wires_id[ChipType::StackPop as usize]),
            range_chip_input: mem::take(&mut output_wires_id[ChipType::RangeChip as usize]),
            range_chip_table: table_out_node_id[LookupChipType::RangeChip as usize],
            calldata_chip_input: mem::take(&mut output_wires_id[ChipType::CalldataChip as usize]),
            calldata_chip_table: table_out_node_id[LookupChipType::CalldataChip as usize],
            public_output_size: self.public_output_size,
        };

        let (graph, graph_witness) = self.graph_builder.finalize();
        Ok((
            SingerCircuit(graph),
            SingerWitness(graph_witness),
            singer_wire_out_id,
        ))
    }
}

pub struct SingerCircuit<F: SmallField>(CircuitGraph<F>);

pub struct SingerWitness<F: SmallField>(CircuitGraphWitness<F>);

#[derive(Clone, Copy, Debug)]
pub struct SingerParams {
    pub n_public_output_bytes: usize,
    pub n_mem_initialize: usize,
    pub n_mem_finalize: usize,
    pub n_stack_finalize: usize,
}

#[derive(Clone, Debug, Default)]
pub struct SingerWiresIn<F: SmallField> {
    basic_blocks: Vec<BasicBlockWiresIn<F>>,
    table_count_witnesses: Vec<WirsInValues<F>>,
}

#[derive(Clone, Debug)]
pub struct SingerWiresOutID {
    global_state_in: Vec<NodeOutputType>,
    global_state_out: Vec<NodeOutputType>,
    bytecode_chip_input: Vec<NodeOutputType>,
    bytecode_chip_table: NodeOutputType,
    stack_push: Vec<NodeOutputType>,
    stack_pop: Vec<NodeOutputType>,
    range_chip_input: Vec<NodeOutputType>,
    range_chip_table: NodeOutputType,
    calldata_chip_input: Vec<NodeOutputType>,
    calldata_chip_table: NodeOutputType,

    public_output_size: Option<NodeOutputType>,
}

pub(crate) type WirsInValues<F> = Vec<Vec<F>>;
// Indexed by 1. wires_in id (or phase); 2. instance id; 3. wire id.
pub(crate) type CircuitWiresInValues<F> = Vec<WirsInValues<F>>;

#[derive(Clone, Debug, Default)]
pub struct BasicBlockWiresIn<F: SmallField> {
    real_n_instance: usize,
    bb_start: CircuitWiresInValues<F>,
    opcodes: Vec<Vec<CircuitWiresInValues<F>>>,
    bb_final: CircuitWiresInValues<F>,
    bb_accs: Vec<CircuitWiresInValues<F>>,
}
