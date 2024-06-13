use std::{mem, sync::Arc};

use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use simple_frontend::structs::WitnessId;

use singer_utils::{chips::SingerChipBuilder, constants::OpcodeType, structs::ChipChallenges};
use strum_macros::EnumIter;

use crate::{error::ZKVMError, CircuitWiresIn, SingerParams};

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

#[derive(Clone, Debug)]
pub struct SingerCircuitBuilder<E: ExtensionField> {
    /// Opcode circuits
    pub insts_circuits: [Vec<InstCircuit<E>>; 256],
    pub challenges: ChipChallenges,
}

impl<E: ExtensionField> SingerCircuitBuilder<E> {
    pub fn new(challenges: ChipChallenges) -> Result<Self, ZKVMError> {
        let mut insts_circuits = Vec::with_capacity(256);
        for opcode in 0..=255 {
            insts_circuits.push(construct_instruction_circuits(opcode, challenges)?);
        }
        let insts_circuits: [Vec<InstCircuit<E>>; 256] = insts_circuits
            .try_into()
            .map_err(|_| ZKVMError::CircuitError)?;
        Ok(Self {
            insts_circuits,
            challenges,
        })
    }
}

/// Construct instruction circuits and its extensions.
pub(crate) fn construct_instruction_circuits<E: ExtensionField>(
    opcode: u8,
    challenges: ChipChallenges,
) -> Result<Vec<InstCircuit<E>>, ZKVMError> {
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
        _ => Ok(vec![]), // TODO: Add more instructions.
    }
}

pub(crate) fn construct_inst_graph_and_witness<E: ExtensionField>(
    opcode: u8,
    graph_builder: &mut CircuitGraphBuilder<E>,
    chip_builder: &mut SingerChipBuilder<E>,
    inst_circuits: &[InstCircuit<E>],
    sources: Vec<CircuitWiresIn<E::BaseField>>,
    real_challenges: &[E],
    real_n_instances: usize,
    params: &SingerParams,
) -> Result<Option<NodeOutputType>, ZKVMError> {
    let construct_circuit_graph = match opcode {
        0x01 => AddInstruction::construct_graph_and_witness,
        0x11 => GtInstruction::construct_graph_and_witness,
        0x35 => CalldataloadInstruction::construct_graph_and_witness,
        0x50 => PopInstruction::construct_graph_and_witness,
        0x52 => MstoreInstruction::construct_graph_and_witness,
        0x56 => JumpInstruction::construct_graph_and_witness,
        0x57 => JumpiInstruction::construct_graph_and_witness,
        0x5B => JumpdestInstruction::construct_graph_and_witness,
        0x60 => PushInstruction::<1>::construct_graph_and_witness,
        0x80 => DupInstruction::<1>::construct_graph_and_witness,
        0x81 => DupInstruction::<2>::construct_graph_and_witness,
        0x91 => SwapInstruction::<2>::construct_graph_and_witness,
        0x93 => SwapInstruction::<4>::construct_graph_and_witness,
        0xF3 => ReturnInstruction::construct_graph_and_witness,
        _ => return Ok(None), // TODO: Add more instructions.
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

pub(crate) fn construct_inst_graph<E: ExtensionField>(
    opcode: u8,
    graph_builder: &mut CircuitGraphBuilder<E>,
    chip_builder: &mut SingerChipBuilder<E>,
    inst_circuits: &[InstCircuit<E>],
    real_n_instances: usize,
    params: &SingerParams,
) -> Result<Option<NodeOutputType>, ZKVMError> {
    let construct_graph = match opcode {
        0x01 => AddInstruction::construct_graph,
        0x11 => GtInstruction::construct_graph,
        0x35 => CalldataloadInstruction::construct_graph,
        0x50 => PopInstruction::construct_graph,
        0x52 => MstoreInstruction::construct_graph,
        0x56 => JumpInstruction::construct_graph,
        0x57 => JumpiInstruction::construct_graph,
        0x5B => JumpdestInstruction::construct_graph,
        0x60 => PushInstruction::<1>::construct_graph,
        0x80 => DupInstruction::<1>::construct_graph,
        0x81 => DupInstruction::<2>::construct_graph,
        0x91 => SwapInstruction::<2>::construct_graph,
        0x93 => SwapInstruction::<4>::construct_graph,
        0xF3 => ReturnInstruction::construct_graph,
        _ => unimplemented!(),
    };

    construct_graph(
        graph_builder,
        chip_builder,
        inst_circuits,
        real_n_instances,
        params,
    )
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub(crate) enum InstOutputType {
    RAMLoad,
    RAMStore,
    ROMInput,
}

#[derive(Clone, Debug)]
pub struct InstCircuit<E: ExtensionField> {
    pub(crate) circuit: Arc<Circuit<E>>,
    pub(crate) layout: InstCircuitLayout,
}

#[derive(Clone, Debug, Default)]
pub struct InstCircuitLayout {
    // Will be connected to the chips.
    pub(crate) chip_check_wire_id: [Option<(WitnessId, usize)>; 3],
    // Target. Especially for return the size of public output.
    pub(crate) target_wire_id: Option<WitnessId>,
    // Will be connected to the accessory circuits.
    pub(crate) succ_dup_wires_id: Vec<WitnessId>,
    pub(crate) succ_ooo_wires_id: Vec<WitnessId>,

    // Wires in index
    pub(crate) phases_wire_id: Vec<WitnessId>,
    // wire id fetched from pred circuit.
    pub(crate) pred_dup_wire_id: Option<WitnessId>,
    pub(crate) pred_ooo_wire_id: Option<WitnessId>,
}

pub trait Instruction<E: ExtensionField> {
    const OPCODE: OpcodeType;
    const NAME: &'static str;
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError>;
}

/// Construct the part of the circuit graph for an instruction.
pub trait InstructionGraph<E: ExtensionField> {
    type InstType: Instruction<E>;

    /// Construct instruction circuits and its extensions. Mostly there is no
    /// extensions.
    fn construct_circuits(challenges: ChipChallenges) -> Result<Vec<InstCircuit<E>>, ZKVMError> {
        let circuits = vec![Self::InstType::construct_circuit(challenges)?];
        Ok(circuits)
    }

    /// Add instruction circuits, its accessories and corresponding witnesses to
    /// the graph. Besides, Generate the tree-structured circuit to compute the
    /// product or fraction summation of the chip check wires.
    fn construct_graph_and_witness(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuits: &[InstCircuit<E>],
        mut sources: Vec<CircuitWiresIn<E::BaseField>>,
        real_challenges: &[E],
        real_n_instances: usize,
        _: &SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        let inst_circuit = &inst_circuits[0];
        let inst_wires_in = mem::take(&mut sources[0]);
        let node_id = graph_builder.add_node_with_witness(
            Self::InstType::NAME,
            &inst_circuits[0].circuit,
            vec![PredType::Source; inst_wires_in.len()],
            real_challenges.to_vec(),
            inst_wires_in,
            real_n_instances.next_power_of_two(),
        )?;

        chip_builder.construct_chip_check_graph_and_witness(
            graph_builder,
            node_id,
            &inst_circuit.layout.chip_check_wire_id,
            real_challenges,
            real_n_instances,
        )?;
        Ok(None)
    }

    /// Add instruction circuits, its accessories and corresponding witnesses to
    /// the graph. Besides, Generate the tree-structured circuit to compute the
    /// product or fraction summation of the chip check wires.
    fn construct_graph(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuits: &[InstCircuit<E>],
        real_n_instances: usize,
        _: &SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        let inst_circuit = &inst_circuits[0];
        let node_id = graph_builder.add_node(
            stringify!(Self::InstType),
            &inst_circuits[0].circuit,
            vec![PredType::Source; inst_circuit.circuit.n_witness_in],
        )?;

        chip_builder.construct_chip_check_graph(
            graph_builder,
            node_id,
            &inst_circuit.layout.chip_check_wire_id,
            real_n_instances,
        )?;
        Ok(None)
    }
}
