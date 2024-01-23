#![feature(generic_const_exprs)]

use chips::ChipCircuitGadgets;
use chips::LookupChipType;
use error::ZKVMError;
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
use revm_interpreter::Interpreter;
use std::mem;
use strum::IntoEnumIterator;

use crate::chips::construct_table_circuits;

pub mod chips;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod scheme;

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
    chip_circuit_gadgets: ChipCircuitGadgets<F>,

    challenges: ChipChallenges,
}

impl<F: SmallField> SingerCircuitBuilder<F> {
    pub fn new(challenges: ChipChallenges) -> Result<Self, ZKVMError> {
        let mut opcode_circuits = Vec::with_capacity(256);
        for opcode in 0..=255 {
            opcode_circuits.push(construct_instruction_circuits(opcode, challenges)?);
        }
        let opcode_circuits: [Vec<InstCircuit<F>>; 256] = opcode_circuits
            .try_into()
            .map_err(|_| ZKVMError::CircuitError)?;

        let chip_circuit_gadgets = ChipCircuitGadgets::new();
        Ok(Self {
            insts_circuits: opcode_circuits,
            chip_circuit_gadgets,
            challenges,
        })
    }

    pub fn execute(bytecode: &[u8], input: &[u8]) -> SingerWiresIn<F> {
        let records = Interpreter::<F>::execute(bytecode, input);
        let mut opcode_wires_in = Vec::new();
        SingerWiresIn { opcode_wires_in }
    }
}

/// Circuit graph builder for Singer. `output_wires_id` is indexed by
/// InstOutputType, corresponding to the product of summation of the chip check
/// records. `public_output_size` is the wire id stores the size of public
/// output.
pub struct SingerGraphBuilder<F: SmallField> {
    graph_builder: CircuitGraphBuilder<F>,
    output_wires_id: Vec<Vec<NodeOutputType>>,
    public_output_size: Option<NodeOutputType>,
}

impl<F: SmallField> SingerGraphBuilder<F> {
    pub fn new() -> Result<Self, ZKVMError> {
        Ok(Self {
            graph_builder: CircuitGraphBuilder::new(),
            output_wires_id: vec![vec![]; InstOutputType::iter().count()],
            public_output_size: None,
        })
    }

    pub fn construct(
        mut self,
        circuit_builder: &SingerCircuitBuilder<F>,
        mut singer_wires_in: SingerWiresIn<F>,
        bytecode: &[u8],
        program_input: &[u8],
        real_challenges: &[F],
    ) -> Result<(SingerCircuit<F>, SingerWitness<F>, SingerWiresOutID), ZKVMError> {
        // Add instruction and its extension (if any) circuits to the graph.
        for (opcode, opcode_wires_in) in singer_wires_in.opcode_wires_in.iter_mut() {
            let inst_circuits = &circuit_builder.insts_circuits[*opcode as usize];
            construct_inst_circuit_graph(
                *opcode,
                &mut self,
                &inst_circuits,
                &circuit_builder.chip_circuit_gadgets,
                mem::take(opcode_wires_in),
                real_challenges,
            )?;
        }

        // Construct tables for lookup arguments, including bytecode, range and
        // calldata.
        let mut table_out_node_id = Vec::new();
        for table_type in LookupChipType::iter() {
            table_out_node_id.push(construct_table_circuits(
                table_type,
                &mut self.graph_builder,
                bytecode,
                program_input,
                &circuit_builder.challenges,
                real_challenges,
                &circuit_builder.chip_circuit_gadgets,
            )?);
        }

        let SingerGraphBuilder {
            graph_builder,
            mut output_wires_id,
            public_output_size,
        } = self;

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

/// The structure for storing the input values for an instruction. The values
/// are stored in a three-dimensional array, where
/// - the first dimension is indexed by the phase index, so the outmost vector
///   usually has length only 2, each for one phase;
/// - the second dimension is indexed by the number of repetitions this opcode appears
///   during the execution;
/// - the last dimension is indexed by the offsets of the input wire values for this opcode,
///   in another word, the innermost vector is the input for this opcode for a particular
///   execution
pub(crate) type CircuitWiresIn<F> = Vec<Vec<Vec<F>>>;

pub struct SingerWiresIn<F: SmallField> {
    opcode_wires_in: Vec<(u8, Vec<CircuitWiresIn<F>>)>,
}

impl<F: SmallField> SingerWiresIn<F> {
    pub fn new() -> Self {
        let mut opcode_wires_in = Vec::with_capacity(256);
        for opcode in 0..=255 {
            opcode_wires_in.push((opcode, Vec::new()));
        }
        Self { opcode_wires_in }
    }
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
