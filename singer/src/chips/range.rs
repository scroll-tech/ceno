use std::sync::Arc;

use frontend::structs::CircuitBuilder;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, PredType};
use goldilocks::SmallField;
use itertools::Itertools;

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
    let (_, cells) = circuit_builder.create_wire_in(1);
    let rlc = circuit_builder.create_cell();
    circuit_builder.rlc(rlc, &[cells[0]], challenges.range());
    circuit_builder.configure();
    let range_circuit = Arc::new(Circuit::new(&circuit_builder));

    let wires_in = vec![(0..(1 << bit_with))
        .map(|x| vec![F::from(x as u64)])
        .collect_vec()];

    let (table_node_id, table_instance_nv) = builder.add_node_with_witness(
        "range table circuit",
        &range_circuit,
        vec![PredType::Source; 2],
        real_challenges.to_vec(),
        wires_in,
    )?;
    Ok((table_node_id, table_instance_nv - 1))
}
