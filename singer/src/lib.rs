#![feature(generic_const_exprs)]

use chips::LookupChipType;

use constants::OpcodeType;

use chips::SingerChipBuilder;

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
use mpcs::poly::multilinear::MultilinearPolynomial;
use mpcs::PolynomialCommitmentScheme;
use mpcs::StandardBasefold;
use mpcs::StandardBasefoldProverParam;
use num_traits::FromPrimitive;
use rand::RngCore;
use revm_interpreter::{Interpreter, Record};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::mem;
use strum::IntoEnumIterator;
use transcript::Transcript;

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

    pub fn execute<EF: SmallField<BaseField = F>, Rng: RngCore + Clone>(
        bytecode: &[u8],
        input: &[u8],
    ) -> PrepareSingerWiresIn<F>
    where
        F: SmallField<BaseField = F> + Serialize + DeserializeOwned + Into<EF>,
        EF: Serialize + DeserializeOwned + TryInto<F>,
        <EF as TryInto<F>>::Error: core::fmt::Debug,
    {
        let records = Interpreter::<F>::execute(bytecode, input);
        let mut opcode_wires_in = HashMap::<u8, Vec<CircuitWiresIn<F>>>::new();
        for phase_index in 0.. {
            let mut has_wires_in_in_this_phase = false;
            for record in records.iter() {
                let wires_in = circuit_wires_in_from_record(record, phase_index);
                if let Some(wires_in) = wires_in {
                    let wires = opcode_wires_in
                        .entry(record.opcode)
                        .or_insert(vec![Vec::new(); wires_in.len()]);
                    // wires is a four-dimensional array indexed by
                    // 1. Different circuits for one opcode
                    // 2. Different phase/wire_in for one circuit
                    // 3. Different repetitions/instances for one circuit
                    // 4. Different wire values for one wire_in
                    for (wires_in, wires) in wires_in.iter().zip(wires.iter_mut()) {
                        wires.resize(phase_index + 1, Vec::new());
                        let wire = &mut wires[phase_index];
                        wire.push(wires_in.clone());
                        has_wires_in_in_this_phase = true;
                    }
                }
            }
            if !has_wires_in_in_this_phase {
                break;
            }
        }
        PrepareSingerWiresIn {
            opcode_wires_in: opcode_wires_in.into_iter().collect(),
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

fn circuit_wires_in_from_record<F: SmallField>(
    record: &Record,
    index: usize,
) -> Option<Vec<Vec<F>>> {
    match OpcodeType::from_u8(record.opcode) {
        Some(OpcodeType::ADD) => {
            AddInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::GT) => {
            GtInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::CALLDATALOAD) => {
            CalldataloadInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::POP) => {
            PopInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::MSTORE) => {
            MstoreInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::JUMP) => {
            JumpInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::JUMPI) => {
            JumpiInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::JUMPDEST) => {
            JumpdestInstruction::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::PUSH1) => {
            PushInstruction::<1>::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::DUP1) => {
            DupInstruction::<1>::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::DUP2) => {
            DupInstruction::<2>::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::SWAP2) => {
            SwapInstruction::<2>::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::SWAP4) => {
            SwapInstruction::<4>::generate_pre_wires_in(record, index).map(|x| vec![x])
        }
        Some(OpcodeType::RETURN) => {
            let results = vec![
                ReturnInstruction::generate_pre_wires_in(record, index),
                ReturnPublicOutLoad::generate_pre_wires_in(record, index),
                ReturnRestMemLoad::generate_pre_wires_in(record, index),
                ReturnRestMemStore::generate_pre_wires_in(record, index),
            ];
            if results.iter().all(|x: &Option<Vec<F>>| x.is_none()) {
                None
            } else {
                Some(
                    results
                        .into_iter()
                        .map(|result| {
                            if let Some(result) = result {
                                result
                            } else {
                                Vec::new()
                            }
                        })
                        .collect(),
                )
            }
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
