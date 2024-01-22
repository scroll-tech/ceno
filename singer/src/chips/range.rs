use std::sync::Arc;

use frontend::structs::CircuitBuilder;
use gkr::structs::Circuit;
use gkr_graph::structs::CircuitGraphBuilder;
use goldilocks::SmallField;

use crate::error::ZKVMError;
use crate::instructions::ChipChallenges;

/// Add range table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_range_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bit_with: usize,
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(usize, usize), ZKVMError> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let cells = circuit_builder.create_counter_in(0);
    let rlc = circuit_builder.create_cell();
    circuit_builder.rlc(rlc, &[cells[0]], challenges.range());
    circuit_builder.configure();
    let range_circuit = Arc::new(Circuit::new(&circuit_builder));

    let table_node_id = builder.add_node_with_witness(
        "range table circuit",
        &range_circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
    )?;
    Ok((table_node_id, bit_with - 1))
}
