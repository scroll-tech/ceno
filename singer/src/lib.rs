#![feature(generic_const_exprs)]

use chips::LookupChipType;
use chips::SingerChipBuilder;
use error::ZKVMError;
use gkr::structs::LayerWitness;
use gkr_graph::structs::CircuitGraph;
use gkr_graph::structs::CircuitGraphBuilder;
use gkr_graph::structs::CircuitGraphWitness;
use gkr_graph::structs::NodeOutputType;
use goldilocks::SmallField;
use instructions::construct_inst_circuit_graph;
use instructions::construct_instruction_circuits;
use instructions::ChipChallenges;
use instructions::InstCircuit;
use instructions::InstOutputType;
use std::mem;

#[macro_use]
mod macros;

pub mod chips;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod scheme;
pub mod test;
pub mod utils;

// Process sketch:
// 1. Construct instruction circuits and circuit gadgets => circuit gadgets
// 2. (bytecode + input) => Run revm interpreter, generate all wires in
//      2.1 phase 0 wire in + commitment
//      2.2 phase 1 wire in + commitment
//      2.3 phase 2 wire in + commitment
// 3. (circuit gadgets + wires in) => gkr graph + gkr witness
// 4. (gkr graph + gkr witness) => (gkr proof + point)
// 5. (commitments + point) => pcs proof

#[derive(Clone, Debug)]
pub struct SingerCircuitBuilder<F: SmallField> {
    /// Opcode circuits
    insts_circuits: [Vec<InstCircuit<F>>; 256],
    challenges: ChipChallenges,
}

impl<F: SmallField> SingerCircuitBuilder<F> {
    pub fn new(challenges: ChipChallenges) -> Result<Self, ZKVMError> {
        let mut insts_circuits = Vec::with_capacity(256);
        for opcode in 0..=255 {
            insts_circuits.push(construct_instruction_circuits(opcode, challenges)?);
        }
        let insts_circuits: [Vec<InstCircuit<F>>; 256] = insts_circuits
            .try_into()
            .map_err(|_| ZKVMError::CircuitError)?;
        Ok(Self {
            insts_circuits,
            challenges,
        })
    }
}

/// Circuit graph builder for Singer. `output_wires_id` is indexed by
/// InstOutputType, corresponding to the product of summation of the chip check
/// records. `public_output_size` is the wire id stores the size of public
/// output.
pub struct SingerGraphBuilder<F: SmallField> {
    graph_builder: CircuitGraphBuilder<F>,
    chip_builder: SingerChipBuilder<F>,
    public_output_size: Option<NodeOutputType>,
}

impl<F: SmallField> SingerGraphBuilder<F> {
    pub fn new() -> Result<Self, ZKVMError> {
        Ok(Self {
            graph_builder: CircuitGraphBuilder::new(),
            chip_builder: SingerChipBuilder::new(),
            public_output_size: None,
        })
    }

    pub fn construct(
        mut self,
        circuit_builder: &SingerCircuitBuilder<F>,
        singer_wires_in: SingerWiresIn<F::BaseField>,
        bytecode: &[u8],
        program_input: &[u8],
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
        // Add instruction and its extension (if any) circuits to the graph.
        for inst_wires_in in singer_wires_in.instructions.into_iter() {
            let InstWiresIn {
                opcode,
                real_n_instances,
                wires_in,
            } = inst_wires_in;
            let inst_circuits = &circuit_builder.insts_circuits[opcode as usize];
            let pub_out_id = construct_inst_circuit_graph(
                opcode,
                &mut self.graph_builder,
                &mut self.chip_builder,
                &inst_circuits,
                wires_in,
                real_challenges,
                real_n_instances,
                params,
            )?;
            if pub_out_id.is_some() {
                self.public_output_size = pub_out_id;
            }
        }

        // Construct tables for lookup arguments, including bytecode, range and
        // calldata.
        let mut table_out_node_id = self.chip_builder.construct_chip_tables(
            &mut self.graph_builder,
            bytecode,
            program_input,
            singer_wires_in.table_count,
            &circuit_builder.challenges,
            real_challenges,
        )?;

        let SingerGraphBuilder {
            graph_builder,
            chip_builder,
            public_output_size,
        } = self;

        let mut output_wires_id = chip_builder.output_wires_id;

        let singer_wire_out_id = SingerWiresOutID {
            global_state_in: mem::take(
                &mut output_wires_id[InstOutputType::GlobalStateIn as usize],
            ),
            global_state_out: mem::take(
                &mut output_wires_id[InstOutputType::GlobalStateOut as usize],
            ),
            bytecode_chip_input: mem::take(
                &mut output_wires_id[InstOutputType::BytecodeChip as usize],
            ),
            bytecode_chip_table: table_out_node_id[LookupChipType::BytecodeChip as usize],
            stack_push: mem::take(&mut output_wires_id[InstOutputType::StackPush as usize]),
            stack_pop: mem::take(&mut output_wires_id[InstOutputType::StackPop as usize]),
            range_chip_input: mem::take(&mut output_wires_id[InstOutputType::RangeChip as usize]),
            range_chip_table: table_out_node_id[LookupChipType::RangeChip as usize],
            calldata_chip_input: mem::take(
                &mut output_wires_id[InstOutputType::CalldataChip as usize],
            ),
            calldata_chip_table: table_out_node_id[LookupChipType::CalldataChip as usize],
            public_output_size: public_output_size,
        };

        let (graph, graph_witness) = graph_builder.finalize();
        Ok((
            SingerCircuit(graph),
            SingerWitness(graph_witness),
            singer_wire_out_id,
        ))
    }
}

pub struct SingerCircuit<F: SmallField>(CircuitGraph<F>);

pub struct SingerWitness<F: SmallField>(CircuitGraphWitness<F>);

#[derive(Clone, Debug, Default)]
pub struct SingerWiresIn<F: SmallField> {
    instructions: Vec<InstWiresIn<F>>,
    table_count: Vec<LayerWitness<F>>,
}

impl<F: SmallField> SingerWiresIn<F> {
    pub fn new() -> Self {
        let mut opcodes = Vec::with_capacity(256);
        for opcode in 0..=255 {
            opcodes.push(InstWiresIn::default());
        }
        let table_count = Vec::new();
        Self {
            instructions: opcodes,
            table_count,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SingerParams {
    pub n_public_output_bytes: usize,
    pub n_mem_initialize: usize,
    pub n_mem_finalize: usize,
    pub n_stack_finalize: usize,
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

// Indexed by 1. wires_in id (or phase); 2. instance id; 3. wire id.
pub(crate) type CircuitWiresIn<F> = Vec<LayerWitness<F>>;

#[derive(Clone, Debug, Default)]
pub struct InstWiresIn<F: SmallField> {
    pub opcode: u8,
    pub real_n_instances: usize,
    pub wires_in: Vec<CircuitWiresIn<F>>,
}
