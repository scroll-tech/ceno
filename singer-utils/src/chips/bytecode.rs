use std::{cell::RefCell, rc::Rc, sync::Arc};

use ff_ext::ExtensionField;
use gkr::structs::{Circuit, LayerWitness};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use itertools::Itertools;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use sumcheck::util::ceil_log2;

use crate::{
    chip_handler::{bytecode::BytecodeChip, rom_handler::ROMHandler, ChipHandler},
    error::UtilError,
    structs::{ChipChallenges, PCUInt},
};

use super::ChipCircuitGadgets;

fn construct_circuit<E: ExtensionField>(challenges: &ChipChallenges) -> Arc<Circuit<E>> {
    let mut circuit_builder = CircuitBuilder::<E>::new();
    let (_, pc_cells) = circuit_builder.create_witness_in(PCUInt::N_OPERAND_CELLS);
    let (_, bytecode_cells) = circuit_builder.create_witness_in(1);

    let mut chip_handler = ChipHandler::new(challenges.clone());

    BytecodeChip::bytecode_with_pc_byte(
        &mut chip_handler,
        &mut circuit_builder,
        &pc_cells,
        bytecode_cells[0],
    );
    let _ = chip_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add bytecode table circuit and witness to the circuit graph. Return node id
/// and lookup instance log size.
pub(crate) fn construct_bytecode_table_and_witness<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
    bytecode: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[E],
) -> Result<(PredType, PredType, usize), UtilError> {
    let bytecode_circuit = construct_circuit(challenges);
    let selector = ChipCircuitGadgets::construct_prefix_selector(bytecode.len(), 1);

    let selector_node_id = builder.add_node_with_witness(
        "bytecode selector circuit",
        &selector.circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
        bytecode.len().next_power_of_two(),
    )?;

    let wits_in = vec![
        LayerWitness {
            instances: PCUInt::counter_vector::<E::BaseField>(bytecode.len().next_power_of_two())
        };
        2
    ];

    let table_node_id = builder.add_node_with_witness(
        "bytecode table circuit",
        &bytecode_circuit,
        vec![PredType::Source; 2],
        real_challenges.to_vec(),
        wits_in,
        bytecode.len().next_power_of_two(),
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(bytecode.len()) - 1,
    ))
}

/// Add bytecode table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_bytecode_table<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
    bytecode_len: usize,
    challenges: &ChipChallenges,
) -> Result<(PredType, PredType, usize), UtilError> {
    let bytecode_circuit = construct_circuit(challenges);
    let selector = ChipCircuitGadgets::construct_prefix_selector(bytecode_len, 1);

    let selector_node_id =
        builder.add_node("bytecode selector circuit", &selector.circuit, vec![])?;

    let table_node_id = builder.add_node(
        "bytecode table circuit",
        &bytecode_circuit,
        vec![PredType::Source; 2],
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(bytecode_len) - 1,
    ))
}
