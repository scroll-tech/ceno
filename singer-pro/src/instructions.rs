use std::{collections::HashMap, mem};

use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;

use crate::{
    chips::SingerChipBuilder,
    component::{AccessoryCircuit, ChipChallenges, InstCircuit},
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
pub struct SingerInstCircuitBuilder<F: SmallField> {
    /// Opcode circuits
    pub(crate) insts_circuits: HashMap<u8, (InstCircuit<F>, Vec<AccessoryCircuit<F>>)>,
    pub(crate) challenges: ChipChallenges,
}

impl<F: SmallField> SingerInstCircuitBuilder<F> {
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

pub(crate) fn insts_graph_method<F: SmallField>(
    opcode: u8,
    graph_builder: &mut CircuitGraphBuilder<F>,
    chip_builder: &mut SingerChipBuilder<F>,
    inst_circuit: &InstCircuit<F>,
    acc_circuits: &[AccessoryCircuit<F>],
    preds: Vec<PredType>,
    sources: Vec<CircuitWitnessIn<F::BaseField>>,
    real_challenges: &[F],
    real_n_instances: usize,
    params: SingerParams,
) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
    let method = match opcode {
        0x01 => AddInstruction::construct_circuit_graph,
        0x11 => GtInstruction::construct_circuit_graph,
        0x35 => CalldataloadInstruction::construct_circuit_graph,
        0x52 => MstoreInstruction::construct_circuit_graph,
        0x56 => JumpInstruction::construct_circuit_graph,
        0x57 => JumpiInstruction::construct_circuit_graph,
        _ => unknown::UnknownInstruction::construct_circuit_graph,
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

pub(crate) trait Instruction<F: SmallField> {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError>;
}

/// Construct the part of the circuit graph for an instruction.
pub(crate) trait InstructionGraph<F: SmallField> {
    type InstType: Instruction<F>;

    /// Construct instruction circuits and its extensions. Mostly there is no
    /// extensions.
    fn construct_circuits(
        challenges: ChipChallenges,
    ) -> Result<(InstCircuit<F>, Vec<AccessoryCircuit<F>>), ZKVMError> {
        Ok((Self::InstType::construct_circuit(challenges)?, vec![]))
    }

    /// Add instruction circuits and its extensions to the graph. Besides,
    /// Generate the tree-structured circuit to compute the product or fraction
    /// summation of the chip check wires.
    fn construct_circuit_graph(
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        inst_circuit: &InstCircuit<F>,
        _acc_circuits: &[AccessoryCircuit<F>],
        preds: Vec<PredType>,
        mut sources: Vec<CircuitWitnessIn<F::BaseField>>,
        real_challenges: &[F],
        real_n_instances: usize,
        _params: SingerParams,
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
        chip_builder.construct_chip_checks(
            graph_builder,
            node_id,
            &inst_circuit.layout.to_chip_ids,
            real_challenges,
            real_n_instances,
        )?;
        Ok((vec![node_id], stack, None))
    }
}
