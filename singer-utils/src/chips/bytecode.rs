use std::sync::Arc;

use gkr::{
    structs::{Circuit, LayerWitness},
    utils::ceil_log2,
};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::CircuitBuilder;

use crate::{
    chip_handler::{BytecodeChipOperations, ROMOperations},
    error::UtilError,
    structs::{ChipChallenges, PCUInt, ROMHandler},
};

use super::ChipCircuitGadgets;

fn construct_circuit<F: SmallField>(challenges: &ChipChallenges) -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, pc_cells) = circuit_builder.create_witness_in(PCUInt::N_OPRAND_CELLS);
    let (_, bytecode_cells) = circuit_builder.create_witness_in(1);

    let mut rom_handler = ROMHandler::new(&challenges);
    rom_handler.bytecode_with_pc_byte(&mut circuit_builder, &pc_cells, bytecode_cells[0]);
    let _ = rom_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add bytecode table circuit and witness to the circuit graph. Return node id
/// and lookup instance log size.
pub(crate) fn construct_bytecode_table_and_witness<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bytecode: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[F],
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
            instances: PCUInt::counter_vector::<F::BaseField>(bytecode.len().next_power_of_two())
                .into_iter()
                .map(|x| vec![x])
                .collect_vec(),
        },
        LayerWitness {
            instances: bytecode
                .iter()
                .map(|x| vec![F::BaseField::from(*x as u64)])
                .collect_vec(),
        },
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
pub(crate) fn construct_bytecode_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
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
