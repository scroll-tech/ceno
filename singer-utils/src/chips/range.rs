use std::{cell::RefCell, rc::Rc, sync::Arc};

use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use simple_frontend::structs::CircuitBuilder;

use crate::{
    chip_handler::{range::RangeChip, rom_handler::ROMHandler, ChipHandler},
    constants::RANGE_CHIP_BIT_WIDTH,
    error::UtilError,
    structs::ChipChallenges,
};

fn construct_circuit<E: ExtensionField>(challenges: &ChipChallenges) -> Arc<Circuit<E>> {
    let mut circuit_builder = CircuitBuilder::<E>::new();
    let cells = circuit_builder.create_counter_in(0);

    let mut chip_handler = ChipHandler::new(challenges.clone());

    RangeChip::range_check_table_item(&mut chip_handler, &mut circuit_builder, cells[0]);

    let _ = chip_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add range table circuit and witness to the circuit graph. Return node id and
/// lookup instance log size.
pub(crate) fn construct_range_table_and_witness<'a, E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<'a, E>,
    bit_with: usize,
    challenges: &ChipChallenges,
    real_challenges: &[E],
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
pub(crate) fn construct_range_table<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
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
