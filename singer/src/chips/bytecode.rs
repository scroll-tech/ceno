use std::sync::Arc;

use frontend::structs::CircuitBuilder;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;

use crate::chips::utils::den_to_frac_circuit;
use crate::instructions::utils::PCUInt;
use crate::{error::ZKVMError, instructions::ChipChallenges};

/// Add bytecode table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_bytecode_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bytecode: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(usize, usize), ZKVMError> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, bytecode_cells) = circuit_builder.create_wire_in(1);
    let (_, pc_cells) = circuit_builder.create_wire_in(PCUInt::N_OPRAND_CELLS);
    let pc_rlc = circuit_builder.create_cell();
    circuit_builder.rlc(pc_rlc, &pc_cells, challenges.record_item_rlc());
    let rlc = circuit_builder.create_cell();
    circuit_builder.rlc(rlc, &[pc_rlc, bytecode_cells[0]], challenges.bytecode());
    circuit_builder.configure();
    let bytecode_circuit = Arc::new(Circuit::new(&circuit_builder));

    let wires_in = vec![
        bytecode
            .iter()
            .map(|x| vec![F::from(*x as u64)])
            .collect_vec(),
        PCUInt::counter_vector(bytecode.len().next_power_of_two())
            .into_iter()
            .map(|x| vec![x])
            .collect_vec(),
    ];

    let table_node_id = builder.add_node_with_witness(
        "bytecode table circuit",
        &bytecode_circuit,
        vec![PredType::Source; 2],
        real_challenges.to_vec(),
        wires_in,
    )?;

    let pad_circuit = Arc::new(den_to_frac_circuit(bytecode.len()));
    let pad_node_id = builder.add_node_with_witness(
        "bytecode table padding circuit",
        &pad_circuit,
        vec![PredType::PredWireTrans(NodeOutputType::OutputLayer(
            table_node_id,
        ))],
        real_challenges.to_vec(),
        vec![vec![]; pad_circuit.n_wires_in],
    )?;

    Ok((pad_node_id, pad_circuit.max_wires_in_num_vars))
}
