use num_traits::FromPrimitive;
use revm_interpreter::Record;
use std::{mem, sync::Arc};

use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use simple_frontend::structs::{ChallengeId, WireId};

use strum_macros::EnumIter;

use crate::{constants::OpcodeType, error::ZKVMError, CircuitWiresIn};

use crate::{chips::SingerChipBuilder, SingerParams};

use self::{
    add::AddInstruction, calldataload::CalldataloadInstruction, dup::DupInstruction,
    gt::GtInstruction, jump::JumpInstruction, jumpdest::JumpdestInstruction,
    jumpi::JumpiInstruction, mstore::MstoreInstruction, pop::PopInstruction, push::PushInstruction,
    ret::ReturnInstruction, swap::SwapInstruction,
};

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

/// Construct instruction circuits and its extensions.
pub(crate) fn construct_instruction_circuits<F: SmallField>(
    opcode: u8,
    challenges: ChipChallenges,
) -> Result<Vec<InstCircuit<F>>, ZKVMError> {
    match OpcodeType::from_u8(opcode) {
        Some(OpcodeType::ADD) => AddInstruction::construct_circuits(challenges),
        Some(OpcodeType::GT) => GtInstruction::construct_circuits(challenges),
        Some(OpcodeType::CALLDATALOAD) => CalldataloadInstruction::construct_circuits(challenges),
        Some(OpcodeType::POP) => PopInstruction::construct_circuits(challenges),
        Some(OpcodeType::MSTORE) => MstoreInstruction::construct_circuits(challenges),
        Some(OpcodeType::JUMP) => JumpInstruction::construct_circuits(challenges),
        Some(OpcodeType::JUMPI) => JumpiInstruction::construct_circuits(challenges),
        Some(OpcodeType::JUMPDEST) => JumpdestInstruction::construct_circuits(challenges),
        Some(OpcodeType::PUSH1) => PushInstruction::<1>::construct_circuits(challenges),
        Some(OpcodeType::DUP1) => DupInstruction::<1>::construct_circuits(challenges),
        Some(OpcodeType::DUP2) => DupInstruction::<2>::construct_circuits(challenges),
        Some(OpcodeType::SWAP2) => SwapInstruction::<2>::construct_circuits(challenges),
        Some(OpcodeType::SWAP4) => SwapInstruction::<4>::construct_circuits(challenges),
        Some(OpcodeType::RETURN) => ReturnInstruction::construct_circuits(challenges),
        _ => unimplemented!(),
    }
}

pub(crate) fn construct_inst_circuit_graph<F: SmallField>(
    opcode: u8,
    graph_builder: &mut CircuitGraphBuilder<F>,
    chip_builder: &mut SingerChipBuilder<F>,
    inst_circuits: &[InstCircuit<F>],
    sources: Vec<CircuitWiresIn<F::BaseField>>,
    real_challenges: &[F],
    real_n_instances: usize,
    params: SingerParams,
) -> Result<Option<NodeOutputType>, ZKVMError> {
    let construct_circuit_graph = match OpcodeType::from_u8(opcode) {
        Some(OpcodeType::ADD) => AddInstruction::construct_circuit_graph,
        Some(OpcodeType::GT) => GtInstruction::construct_circuit_graph,
        Some(OpcodeType::CALLDATALOAD) => CalldataloadInstruction::construct_circuit_graph,
        Some(OpcodeType::POP) => PopInstruction::construct_circuit_graph,
        Some(OpcodeType::MSTORE) => MstoreInstruction::construct_circuit_graph,
        Some(OpcodeType::JUMP) => JumpInstruction::construct_circuit_graph,
        Some(OpcodeType::JUMPI) => JumpiInstruction::construct_circuit_graph,
        Some(OpcodeType::JUMPDEST) => JumpdestInstruction::construct_circuit_graph,
        Some(OpcodeType::PUSH1) => PushInstruction::<1>::construct_circuit_graph,
        Some(OpcodeType::DUP1) => DupInstruction::<1>::construct_circuit_graph,
        Some(OpcodeType::DUP2) => DupInstruction::<2>::construct_circuit_graph,
        Some(OpcodeType::SWAP2) => SwapInstruction::<2>::construct_circuit_graph,
        Some(OpcodeType::SWAP4) => SwapInstruction::<4>::construct_circuit_graph,
        Some(OpcodeType::RETURN) => ReturnInstruction::construct_circuit_graph,
        _ => unimplemented!(),
    };

    construct_circuit_graph(
        graph_builder,
        chip_builder,
        inst_circuits,
        sources,
        real_challenges,
        real_n_instances,
        params,
    )
}

#[derive(Clone, Copy, Debug)]
pub struct ChipChallenges {
    // Challenges for multiple-tuple chip records
    record_rlc: ChallengeId,
    // Challenges for multiple-cell values
    record_item_rlc: ChallengeId,
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
    pub fn new(record_rlc: ChallengeId, record_item_rlc: ChallengeId) -> Self {
        Self {
            record_rlc,
            record_item_rlc,
        }
    }
    pub fn bytecode(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn stack(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn global_state(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn mem(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn range(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn calldata(&self) -> ChallengeId {
        self.record_rlc
    }
    pub fn record_item_rlc(&self) -> ChallengeId {
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

#[derive(Clone, Debug, Default)]
pub struct InstCircuitLayout {
    // Will be connected to the chips.
    pub(crate) chip_check_wire_id: [Option<(WireId, usize)>; 9],
    // Target. Especially for return the size of public output.
    pub(crate) target_wire_id: Option<WireId>,
    // Will be connected to the accessory circuits.
    pub(crate) succ_dup_wires_id: Vec<WireId>,
    pub(crate) succ_ooo_wires_id: Vec<WireId>,

    // Wires in index
    pub(crate) phases_wire_id: Vec<WireId>,
    // wire id fetched from pred circuit.
    pub(crate) pred_dup_wire_id: Option<WireId>,
    pub(crate) pred_ooo_wire_id: Option<WireId>,
}

pub(crate) trait Instruction {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError>;

    fn generate_pre_wires_in<F: SmallField>(record: &Record, index: usize) -> Option<Vec<F>>;
    fn complete_wires_in<F: SmallField>(
        pre_wires_in: &CircuitWiresIn<F>,
        challenges: &Vec<F>,
    ) -> CircuitWiresIn<F>;
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
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        inst_circuits: &[InstCircuit<F>],
        mut sources: Vec<CircuitWiresIn<F::BaseField>>,
        real_challenges: &[F],
        real_n_instances: usize,
        _: SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        let inst_circuit = &inst_circuits[0];
        let inst_wires_in = mem::take(&mut sources[0]);
        let node_id = graph_builder.add_node_with_witness(
            stringify!(Self::InstType),
            &inst_circuits[0].circuit,
            vec![PredType::Source; inst_wires_in.len()],
            real_challenges.to_vec(),
            inst_wires_in,
        )?;

        chip_builder.construct_chip_checks(
            graph_builder,
            node_id,
            &inst_circuit.layout.chip_check_wire_id,
            real_challenges,
            real_n_instances,
        )?;
        Ok(None)
    }
}
