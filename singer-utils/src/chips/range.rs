use std::sync::Arc;

use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use simple_frontend::structs::{CircuitBuilder, MixedCell};

use crate::{
    constants::RANGE_CHIP_BIT_WIDTH,
    error::UtilError,
    structs::{ChipChallenges, ROMType},
};

/// Add range table circuit and witness to the circuit graph. Return node id and
/// lookup instance log size.
pub(crate) fn construct_range_table_and_witness<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
    bit_with: usize,
    challenges: &ChipChallenges,
    real_challenges: &[E],
) -> Result<(PredType, usize), UtilError> {
    let mut circuit_builder = CircuitBuilder::<E>::new();
    let cells = circuit_builder.create_counter_in(0);
    let items = [
        MixedCell::Constant(E::BaseField::from(ROMType::Range as u64)),
        MixedCell::Cell(cells[0]),
    ];
    let rlc = circuit_builder.create_ext_cell();
    circuit_builder.rlc_mixed(&rlc, &items, challenges.range());
    circuit_builder.configure();
    let range_circuit = Arc::new(Circuit::new(&circuit_builder));

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
    let mut circuit_builder = CircuitBuilder::<E>::new();
    let cells = circuit_builder.create_counter_in(0);
    let items = [
        MixedCell::Constant(E::BaseField::from(ROMType::Range as u64)),
        MixedCell::Cell(cells[0]),
    ];
    let rlc = circuit_builder.create_ext_cell();
    circuit_builder.rlc_mixed(&rlc, &items, challenges.range());
    circuit_builder.configure();
    let range_circuit = Arc::new(Circuit::new(&circuit_builder));

    let table_node_id = builder.add_node("range table circuit", &range_circuit, vec![])?;
    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        bit_with - 1,
    ))
}
