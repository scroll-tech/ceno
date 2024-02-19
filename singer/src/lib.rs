//! The singer crate implements the entire workflow from EVM bytecode and input to
//! the proof of the computation. Specifically, it implements the following procedures:
//! 1. Generate the circuits for each instruction. Note that only these circuits are used
//!    as templates, so each distinct circuit only needs to be constructed once. Note that
//!    this step only executes once and the result can be reused by different EVM programs.
//!    Also note that for each instruction, there is potentially more than one circuits
//!    that function together. So the result of this step is a 256-sized array, each entry
//!    for an instruction (the EVM opcode is a byte, i.e., 0 to 255), and the entry is a
//!    vector of circuits.
//! 2. Given the bytecode and the input to EVM, generate the inputs to the instruction
//!    circuits and the lookup argument circuits.
//!    2.1 For the instruction circuits, note that each instruction is potentially executed
//!        multiple times, each time with different inputs, so this step should provide the
//!        input values (wire in values) for all these repetitions. However, because of the
//!        way the inputs are processed in the parallel circuit, the values are organized in
//!        a way that all the instances of the same wire in (one circuit has multiple wire in),
//!        are grouped together in a vector, then the different wire in are grouped together
//!        in another level of vector. Overall, for this part, the result is a five dimensional
//!        vector:
//!        (1) The out-most vector is an array of size 256. Each entry is of type
//!            Vec<CircuitWiresIn>.
//!        (2) This vector is of size equal to the number of circuits implementing the instruction.
//!        (3) CircuitWiresIn is a vector of size equal to the number of wire in for this circuit.
//!        (4) The entry of CircuitWiresIn is a vector, where each entry corresponds to a single
//!            instance, i.e., one execution, of this instruction.
//!        (5) The entry of this vector is a Vec<F>, i.e., the values of this instance for this
//!            wire in.
//!    2.2 For the lookup circuit, the result is a three dimensional vector:
//!        (1) The out-most vector consists of entries of type WirsInValue, each corresponding
//!            to one table type, i.e., one table in the entire circuit.
//!        (2) WirsInValue is a two dimensional array that is the same as the inner-most two
//!            dimensional array for the instruction circuits, i.e., indexed by the instance id,
//!            and each entry is a Vec<F>, the values for this instance.
//!        Note that we only need to provide one wire in for the lookup: the count of the table
//!        entries appeared in the lookup vector. The lookup circuit is a tree-like circuit that
//!        consists of two types of small circuits. Both small circuits are used for computing
//!        addition of fractions, but on the leafs, the fractions come from a particular formula
//!        and the inputs to the fraction addition circuit on the leaf is different from the
//!        inputs to the circuit computing the inner layers.
//!        We only need to provide the wire in to the leaf circuits. Suppose the table size is
//!        N, then there are N/2 leaf circuits for adding the leaves in pair. Each circuit has
//!        its own input, corresponding to the different instances.
//!        Precisely, the value of [table_type][instance_id] is a vector of two values
//!        storing how many times the 2*instance_id-th entry and the (2*instance_id+1)-th entry
//!        in the table `table_type` is looked up in the `instance_id`-th invocation of the
//!        lookup circuit.
//!  3. Given the instruction circuits and their wires in values, construct the entire GKR graph.
//!     This graph consists of several tree-like circuits for the lookup argument, and several
//!     parallel circuits, each one (or more) for checking one instruction.
//!  4. Use the GKR graph and the wires in values to generate the GKR proof. This proof reduces
//!     the problem of proving "given these inputs, the output is 1" into the problem of proving
//!     "given these multivariate polynomial commitments and one evaluation point, the polynomials
//!     evaluate to these values at this point".
//!  5. Generate a PCS proof for this statement.
#![feature(generic_const_exprs)]

use chips::LookupChipType;
use chips::SingerChipBuilder;
use constants::OpcodeType;
use error::ZKVMError;
use gkr_graph::structs::CircuitGraph;
use gkr_graph::structs::CircuitGraphBuilder;
use gkr_graph::structs::CircuitGraphWitness;
use gkr_graph::structs::NodeOutputType;
use goldilocks::SmallField;
use instructions::construct_inst_circuit_graph;
use instructions::construct_instruction_circuits;
use instructions::ret::ReturnPublicOutLoad;
use instructions::ret::ReturnRestMemLoad;
use instructions::ret::ReturnRestMemStore;
use instructions::ChipChallenges;
use instructions::InstCircuit;
use instructions::InstOutputType;
use instructions::Instruction;
use instructions::{
    add::AddInstruction, calldataload::CalldataloadInstruction, dup::DupInstruction,
    gt::GtInstruction, jump::JumpInstruction, jumpdest::JumpdestInstruction,
    jumpi::JumpiInstruction, mstore::MstoreInstruction, pop::PopInstruction, push::PushInstruction,
    ret::ReturnInstruction, swap::SwapInstruction,
};
use num_traits::FromPrimitive;
use rand::RngCore;
use revm_interpreter::{Interpreter, Record};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::mem;

#[macro_use]
mod macros;

pub mod chips;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod scheme;
pub mod utils;

// Process sketch:
// 1. Construct instruction circuits and circuit gadgets => circuit gadgets
// 2. (bytecode + input) => Run revm interpreter, generate all wires in
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

    pub fn execute<EF: SmallField<BaseField = F>, Rng: RngCore + Clone>(
        bytecode: &[u8],
        input: &[u8],
    ) -> SingerWiresIn<F>
    where
        F: SmallField<BaseField = F> + Serialize + DeserializeOwned + Into<EF>,
        EF: Serialize + DeserializeOwned + TryInto<F>,
        <EF as TryInto<F>>::Error: core::fmt::Debug,
    {
        let records = Interpreter::<F>::execute(bytecode, input);
        let mut opcode_wires_in = HashMap::<u8, InstWiresIn<F>>::new();
        for record in records.iter() {
            let wires_in = circuit_wires_in_from_record(record);
            let wires = opcode_wires_in.entry(record.opcode).or_insert(InstWiresIn {
                opcode: record.opcode,
                real_n_instances: 0,
                wires_in: Vec::new(),
            });
            wires.real_n_instances += 1;
            // wires is a four-dimensional array indexed by
            // 1. Different circuits for one opcode
            // 2. Different wire_in for one circuit
            // 3. Different repetitions/instances for one circuit
            // 4. Different wire values for one wire_in
            // The wires_in from the `circuit_wires_in_from_record` is also arranged in this order.
            // The merge of the wires_in into the final result happens in the third (instance) dimension:
            // the first two dimensions should match, then merge the third dimension, i.e., concatenate the
            // instances.
            assert_eq!(wires.wires_in.len(), wires_in.len()); // The number of circuits should match
            wires
                .wires_in
                .iter_mut()
                .zip(wires_in)
                .for_each(|(wires_in, to_add)| {
                    assert_eq!(wires_in.len(), to_add.len()); // The number of wires in should match
                    wires_in.iter_mut().zip(to_add).for_each(
                        |(wires_in_instance, to_add_instance)| {
                            wires_in_instance.extend(to_add_instance);
                        },
                    );
                });
        }

        let table_count = Vec::new();

        SingerWiresIn {
            instructions: opcode_wires_in.into_iter().map(|x| x.1).collect(),
            table_count,
        }
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

fn circuit_wires_in_from_record<F: SmallField>(record: &Record) -> Vec<CircuitWiresIn<F>> {
    match OpcodeType::from_u8(record.opcode) {
        Some(OpcodeType::ADD) => vec![AddInstruction::generate_wires_in(record)],
        Some(OpcodeType::GT) => vec![GtInstruction::generate_wires_in(record)],
        Some(OpcodeType::CALLDATALOAD) => vec![CalldataloadInstruction::generate_wires_in(record)],
        Some(OpcodeType::POP) => vec![PopInstruction::generate_wires_in(record)],
        Some(OpcodeType::MSTORE) => vec![MstoreInstruction::generate_wires_in(record)],
        Some(OpcodeType::JUMP) => vec![JumpInstruction::generate_wires_in(record)],
        Some(OpcodeType::JUMPI) => vec![JumpiInstruction::generate_wires_in(record)],
        Some(OpcodeType::JUMPDEST) => vec![JumpdestInstruction::generate_wires_in(record)],
        Some(OpcodeType::PUSH1) => vec![PushInstruction::<1>::generate_wires_in(record)],
        Some(OpcodeType::DUP1) => vec![DupInstruction::<1>::generate_wires_in(record)],
        Some(OpcodeType::DUP2) => vec![DupInstruction::<2>::generate_wires_in(record)],
        Some(OpcodeType::SWAP2) => vec![SwapInstruction::<2>::generate_wires_in(record)],
        Some(OpcodeType::SWAP4) => vec![SwapInstruction::<4>::generate_wires_in(record)],
        Some(OpcodeType::RETURN) => {
            vec![
                ReturnInstruction::generate_wires_in(record),
                ReturnPublicOutLoad::generate_wires_in(record),
                ReturnRestMemLoad::generate_wires_in(record),
                ReturnRestMemStore::generate_wires_in(record),
            ]
        }
        None => panic!("Unsupported opcode: {}", record.opcode),
        _ => unimplemented!(),
    }
}

/// The information used to generate the wires in values once the challenge
/// is ready.
pub struct PrepareSingerWiresIn<F: SmallField> {
    opcode_wires_in: Vec<(u8, Vec<CircuitWiresIn<F>>)>,
}

#[derive(Clone, Debug, Default)]
pub struct SingerWiresIn<F: SmallField> {
    instructions: Vec<InstWiresIn<F>>,
    table_count: Vec<WirsInValues<F>>,
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

#[derive(Clone, Debug, Default)]
pub struct InstWiresIn<F: SmallField> {
    pub opcode: u8,
    pub real_n_instances: usize,
    pub wires_in: Vec<CircuitWiresIn<F>>,
}

pub(crate) type WirsInValues<F> = Vec<Vec<F>>;
// Indexed by 1. wires_in id (or phase); 2. instance id; 3. wire id.
pub(crate) type CircuitWiresInValues<F> = Vec<WirsInValues<F>>;
