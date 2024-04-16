use std::sync::Arc;

use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use simple_frontend::structs::CircuitBuilder;

use crate::{
    chip_handler::{ROMOperations, RangeChipOperations},
    constants::RANGE_CHIP_BIT_WIDTH,
    error::UtilError,
    structs::{ChipChallenges, ROMHandler},
};

fn construct_circuit<F: SmallField>(challenges: &ChipChallenges) -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let cells = circuit_builder.create_counter_in(0);

    let mut rom_handler = ROMHandler::new(&challenges);
    rom_handler.range_check_table_item(&mut circuit_builder, cells[0]);
    let _ = rom_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add range table circuit and witness to the circuit graph. Return node id and
/// lookup instance log size.
pub(crate) fn construct_range_table_and_witness<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bit_with: usize,
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(PredType, usize), UtilError> {
    let range_circuit = construct_circuit(challenges);

    let table_node_id = builder.add_node_with_witness(
        "range table circuit",
        &range_circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
        1 << RANGE_CHIP_BIT_WIDTH,
    )?;
    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        bit_with - 1,
    ))
}

/// Add range table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_range_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bit_with: usize,
    challenges: &ChipChallenges,
) -> Result<(PredType, usize), UtilError> {
    let range_circuit = construct_circuit(challenges);

    let table_node_id = builder.add_node("range table circuit", &range_circuit, vec![])?;
    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        bit_with - 1,
    ))
}
