use std::{collections::HashMap, mem};

use ff_ext::ExtensionField;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use itertools::Itertools;
use singer_utils::{chips::SingerChipBuilder, structs::ChipChallenges};

use crate::{
    component::{AccessoryCircuit, InstCircuit},
    error::ZKVMError,
    CircuitWitnessIn, SingerParams,
};

use self::{
    add::AddInstruction, calldataload::CalldataloadInstruction, gt::GtInstruction,
    jump::JumpInstruction, jumpi::JumpiInstruction, mstore::MstoreInstruction,
};

// arithmetic
pub mod add;

// bitwise
pub mod gt;

// control
pub mod jump;
pub mod jumpi;

// memory
pub mod mstore;

// system
pub mod calldataload;
pub mod ret;

pub mod unknown;

#[derive(Clone, Debug)]
pub struct SingerInstCircuitBuilder<E: ExtensionField> {
    /// Opcode circuits
    pub(crate) insts_circuits: HashMap<u8, (InstCircuit<E>, Vec<AccessoryCircuit<E>>)>,
    pub(crate) challenges: ChipChallenges,
}

impl<E: ExtensionField> SingerInstCircuitBuilder<E> {
    pub fn new(challenges: ChipChallenges) -> Result<Self, ZKVMError> {
        let mut insts_circuits = HashMap::new();
        insts_circuits.insert(0x01, AddInstruction::construct_circuits(challenges)?);
        insts_circuits.insert(0x11, GtInstruction::construct_circuits(challenges)?);
        insts_circuits.insert(
            0x35,
            CalldataloadInstruction::construct_circuits(challenges)?,
        );
        insts_circuits.insert(0x52, MstoreInstruction::construct_circuits(challenges)?);
        insts_circuits.insert(0x56, JumpInstruction::construct_circuits(challenges)?);
        insts_circuits.insert(0x57, JumpiInstruction::construct_circuits(challenges)?);

        Ok(Self {
            insts_circuits,
            challenges,
        })
    }
}

pub(crate) fn construct_inst_graph_and_witness<E: ExtensionField>(
    opcode: u8,
    graph_builder: &mut CircuitGraphBuilder<E>,
    chip_builder: &mut SingerChipBuilder<E>,
    inst_circuit: &InstCircuit<E>,
    acc_circuits: &[AccessoryCircuit<E>],
    preds: Vec<PredType>,
    sources: Vec<CircuitWitnessIn<E::BaseField>>,
    real_challenges: &[E],
    real_n_instances: usize,
    params: &SingerParams,
) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
    let method = match opcode {
        0x01 => AddInstruction::construct_graph_and_witness,
        0x11 => GtInstruction::construct_graph_and_witness,
        0x35 => CalldataloadInstruction::construct_graph_and_witness,
        0x52 => MstoreInstruction::construct_graph_and_witness,
        0x56 => JumpInstruction::construct_graph_and_witness,
        0x57 => JumpiInstruction::construct_graph_and_witness,
        _ => unknown::UnknownInstruction::construct_graph_and_witness,
    };
    method(
        graph_builder,
        chip_builder,
        inst_circuit,
        acc_circuits,
        preds,
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
    inst_circuit: &InstCircuit<E>,
    acc_circuits: &[AccessoryCircuit<E>],
    preds: Vec<PredType>,
    real_n_instances: usize,
    params: &SingerParams,
) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
    let method = match opcode {
        0x01 => AddInstruction::construct_graph,
        0x11 => GtInstruction::construct_graph,
        0x35 => CalldataloadInstruction::construct_graph,
        0x52 => MstoreInstruction::construct_graph,
        0x56 => JumpInstruction::construct_graph,
        0x57 => JumpiInstruction::construct_graph,
        _ => unknown::UnknownInstruction::construct_graph,
    };
    method(
        graph_builder,
        chip_builder,
        inst_circuit,
        acc_circuits,
        preds,
        real_n_instances,
        params,
    )
}

pub(crate) trait Instruction<E: ExtensionField> {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError>;
}

/// Construct the part of the circuit graph for an instruction.
pub(crate) trait InstructionGraph<E: ExtensionField> {
    type InstType: Instruction<E>;

    /// Construct instruction circuits and its extensions. Mostly there is no
    /// extensions.
    fn construct_circuits(
        challenges: ChipChallenges,
    ) -> Result<(InstCircuit<E>, Vec<AccessoryCircuit<E>>), ZKVMError> {
        Ok((Self::InstType::construct_circuit(challenges)?, vec![]))
    }

    /// Add instruction circuits, accessories and witnesses to the graph.
    /// Besides, Generate the tree-structured circuit to compute the product or
    /// fraction summation of the chip check wires.
    fn construct_graph_and_witness(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuit: &InstCircuit<E>,
        _acc_circuits: &[AccessoryCircuit<E>],
        preds: Vec<PredType>,
        mut sources: Vec<CircuitWitnessIn<E::BaseField>>,
        real_challenges: &[E],
        real_n_instances: usize,
        _params: &SingerParams,
    ) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
        let node_id = graph_builder.add_node_with_witness(
            stringify!(Self::InstType),
            &inst_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[0]),
            real_n_instances.next_power_of_two(),
        )?;
        let stack = inst_circuit
            .layout
            .to_succ_inst
            .stack_result_ids
            .iter()
            .map(|&wire_id| NodeOutputType::WireOut(node_id, wire_id))
            .collect_vec();
        chip_builder.construct_chip_check_graph_and_witness(
            graph_builder,
            node_id,
            &inst_circuit.layout.to_chip_ids,
            real_challenges,
            real_n_instances,
        )?;
        Ok((vec![node_id], stack, None))
    }

    /// Add instruction circuits and accessories to the graph. Besides, Generate
    /// the tree-structured circuit to compute the product or fraction summation
    /// of the chip check wires.
    fn construct_graph(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuit: &InstCircuit<E>,
        _acc_circuits: &[AccessoryCircuit<E>],
        preds: Vec<PredType>,
        real_n_instances: usize,
        _params: &SingerParams,
    ) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
        let node_id =
            graph_builder.add_node(stringify!(Self::InstType), &inst_circuit.circuit, preds)?;
        let stack = inst_circuit
            .layout
            .to_succ_inst
            .stack_result_ids
            .iter()
            .map(|&wire_id| NodeOutputType::WireOut(node_id, wire_id))
            .collect_vec();
        chip_builder.construct_chip_check_graph(
            graph_builder,
            node_id,
            &inst_circuit.layout.to_chip_ids,
            real_n_instances,
        )?;
        Ok((vec![node_id], stack, None))
    }
}
