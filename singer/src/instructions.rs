use std::{mem, sync::Arc};

use frontend::structs::WireId;
use gkr::structs::Circuit;
use gkr_graph::structs::{NodeOutputType, PredType};
use goldilocks::SmallField;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{
    chips::{construct_inst_chip_circuits, ChipCircuitGadgets},
    error::ZKVMError,
    CircuitWiresIn, SingerGraphBuilder,
};

use self::{
    add::AddInstruction, calldataload::CalldataloadInstruction, dup::DupInstruction,
    gt::GtInstruction, jump::JumpInstruction, jumpdest::JumpdestInstruction,
    jumpi::JumpiInstruction, mstore::MstoreInstruction, pop::PopInstruction, push::PushInstruction,
    ret::ReturnInstruction, swap::SwapInstruction,
};

#[macro_use]
mod macros;

// arithmetic
pub mod add;

// bitwise
pub mod gt;

// control
pub mod jump;
pub mod jumpdest;
pub mod jumpi;
pub mod ret;

// stack
pub mod dup;
pub mod pop;
pub mod push;
pub mod swap;

// memory
pub mod mstore;

// system
pub mod calldataload;

pub mod utils;

/// Construct instruction circuits and its extensions.
pub(crate) fn construct_instruction_circuits<F: SmallField>(
    opcode: u8,
    challenges: ChipChallenges,
) -> Result<Vec<InstCircuit<F>>, ZKVMError> {
    match opcode {
        0x01 => AddInstruction::construct_circuits(challenges),
        0x11 => GtInstruction::construct_circuits(challenges),
        0x35 => CalldataloadInstruction::construct_circuits(challenges),
        0x50 => PopInstruction::construct_circuits(challenges),
        0x52 => MstoreInstruction::construct_circuits(challenges),
        0x56 => JumpInstruction::construct_circuits(challenges),
        0x57 => JumpiInstruction::construct_circuits(challenges),
        0x5B => JumpdestInstruction::construct_circuits(challenges),
        0x60 => PushInstruction::<1>::construct_circuits(challenges),
        0x80 => DupInstruction::<1>::construct_circuits(challenges),
        0x81 => DupInstruction::<2>::construct_circuits(challenges),
        0x91 => SwapInstruction::<2>::construct_circuits(challenges),
        0x93 => SwapInstruction::<4>::construct_circuits(challenges),
        0xF3 => ReturnInstruction::construct_circuits(challenges),
        _ => unimplemented!(),
    }
}

pub(crate) fn construct_inst_circuit_graph<F: SmallField>(
    opcode: u8,
    builder: &mut SingerGraphBuilder<F>,
    inst_circuits: &[InstCircuit<F>],
    chip_gadgets: &ChipCircuitGadgets<F>,
    sources: Vec<CircuitWiresIn<F>>,
    real_challenges: &[F],
) -> Result<(), ZKVMError> {
    let construct_circuit_graph = match opcode {
        0x01 => AddInstruction::construct_circuit_graph,
        0x11 => GtInstruction::construct_circuit_graph,
        0x35 => CalldataloadInstruction::construct_circuit_graph,
        0x50 => PopInstruction::construct_circuit_graph,
        0x52 => MstoreInstruction::construct_circuit_graph,
        0x56 => JumpInstruction::construct_circuit_graph,
        0x57 => JumpiInstruction::construct_circuit_graph,
        0x5B => JumpdestInstruction::construct_circuit_graph,
        0x60 => PushInstruction::<1>::construct_circuit_graph,
        0x80 => DupInstruction::<1>::construct_circuit_graph,
        0x81 => DupInstruction::<2>::construct_circuit_graph,
        0x91 => SwapInstruction::<2>::construct_circuit_graph,
        0x93 => SwapInstruction::<4>::construct_circuit_graph,
        0xF3 => ReturnInstruction::construct_circuit_graph,
        _ => unimplemented!(),
    };

    construct_circuit_graph(
        builder,
        inst_circuits,
        chip_gadgets,
        sources,
        real_challenges,
    )
}

#[derive(Clone, Copy, Debug)]
pub struct ChipChallenges {
    // Challenges for multiple-tuple chip records
    record_rlc: usize,
    // Challenges for multiple-cell values
    record_item_rlc: usize,
}

impl Default for ChipChallenges {
    fn default() -> Self {
        Self {
            record_rlc: 2,
            record_item_rlc: 1,
        }
    }
}

impl ChipChallenges {
    pub fn new(record_rlc: usize, record_item_rlc: usize) -> Self {
        Self {
            record_rlc,
            record_item_rlc,
        }
    }
    pub fn bytecode(&self) -> usize {
        self.record_rlc
    }
    pub fn stack(&self) -> usize {
        self.record_rlc
    }
    pub fn global_state(&self) -> usize {
        self.record_rlc
    }
    pub fn mem(&self) -> usize {
        self.record_rlc
    }
    pub fn range(&self) -> usize {
        self.record_rlc
    }
    pub fn calldata(&self) -> usize {
        self.record_rlc
    }
    pub fn record_item_rlc(&self) -> usize {
        self.record_item_rlc
    }
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub(crate) enum InstOutputType {
    GlobalStateIn,
    GlobalStateOut,
    BytecodeChip,
    StackPop,
    StackPush,
    RangeChip,
    MemoryLoad,
    MemoryStore,
    CalldataChip,
}

#[derive(Clone, Debug)]
pub struct InstCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) layout: InstCircuitLayout,
}

/// The structure for storing the input values for an instruction. The values
/// are stored in a three-dimensional array, where
/// - the first dimension is indexed by the phase index, so the outmost vector
///   usually has length only 2, each for one phase;
/// - the second dimension is indexed by the number of repetitions this opcode appears
///   during the execution;
/// - the last dimension is indexed by the offsets of the input values for this opcode,
///   in another word, the innermost vector is the input for this opcode for a particular
///   execution
#[derive(Clone, Debug)]
pub struct InstWireIn<F: SmallField> {
    values: Vec<Vec<Vec<F>>>,
}

#[derive(Clone, Debug, Default)]
pub struct InstCircuitLayout {
    // Will be connected to the chips.
    pub(crate) chip_check_wire_id: [Option<WireId>; 9],
    // Target. Especially for return the size of public output.
    pub(crate) target_wire_id: Option<WireId>,
    // Will be connected to the extension circuit.
    pub(crate) succ_wires_id: Vec<WireId>,

    // Wires in index
    pub(crate) phases_wire_id: [Option<WireId>; 2],
    // wire id fetched from pred circuit.
    pub(crate) pred_wire_id: Option<WireId>,
    // wire id fetched from public_io.
    pub(crate) public_io_wire_id: Option<WireId>,
}

pub(crate) trait Instruction {
    fn witness_size(phase: usize) -> usize;
    fn output_size(inst_out: InstOutputType) -> usize;

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError>;
}

/// Construct the part of the circuit graph for an instruction.
pub(crate) trait InstructionGraph {
    type InstType: Instruction;

    /// Construct instruction circuits and its extensions. Mostly there is no
    /// extensions.
    fn construct_circuits<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<Vec<InstCircuit<F>>, ZKVMError> {
        let circuits = vec![Self::InstType::construct_circuit(challenges)?];
        Ok(circuits)
    }

    /// Add instruction circuits and its extensions to the graph. Besides,
    /// Generate the tree-structured circuit to compute the product or fraction
    /// summation of the chip check wires.
    fn construct_circuit_graph<F: SmallField>(
        builder: &mut SingerGraphBuilder<F>,
        inst_circuits: &[InstCircuit<F>],
        chip_gadgets: &ChipCircuitGadgets<F>,
        mut sources: Vec<CircuitWiresIn<F>>,
        real_challenges: &[F],
    ) -> Result<(), ZKVMError> {
        let inst_circuit = &inst_circuits[0];
        let inst_wires_in = mem::take(&mut sources[0]);
        let n_instances = inst_wires_in[0].len();
        let graph_builder = &mut builder.graph_builder;
        let inst_id = graph_builder.add_node_with_witness(
            stringify!(Self::InstType),
            &inst_circuits[0].circuit,
            vec![PredType::Source; inst_wires_in.len()],
            real_challenges.to_vec(),
            inst_wires_in,
        )?;

        // Add chip circuits to the graph, generate witness correspondingly.
        for output_type in InstOutputType::iter() {
            if let Some(output_wire_id) =
                inst_circuit.layout.chip_check_wire_id[output_type as usize]
            {
                let chip_out_id = construct_inst_chip_circuits(
                    graph_builder,
                    output_type,
                    NodeOutputType::WireOut(inst_id, output_wire_id),
                    n_instances,
                    &chip_gadgets,
                    real_challenges,
                )?;
                builder.output_wires_id[output_type as usize].push(chip_out_id);
            }
        }
        Ok(())
    }
}
