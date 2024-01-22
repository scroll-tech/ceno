use std::sync::Arc;

use frontend::structs::CircuitBuilder;
use gkr::structs::Circuit;
use gkr_graph::structs::CircuitGraphBuilder;
use gkr_graph::structs::NodeOutputType;
use gkr_graph::structs::PredType;
use goldilocks::SmallField;
use itertools::Itertools;

use crate::instructions::utils::StackUInt;
use crate::instructions::ChipChallenges;
use crate::ZKVMError;

use super::utils::den_to_frac_circuit;

/// Add calldata table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_calldata_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    program_input: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(usize, usize), ZKVMError> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, calldata_cells) = circuit_builder.create_wire_in(StackUInt::N_OPRAND_CELLS);
    let (_, id_cells) = circuit_builder.create_wire_in(1);
    let data_rlc = circuit_builder.create_cell();
    circuit_builder.rlc(data_rlc, &calldata_cells, challenges.record_item_rlc());
    let rlc = circuit_builder.create_cell();
    circuit_builder.rlc(rlc, &[id_cells[0], data_rlc], challenges.calldata());
    circuit_builder.configure();
    let calldata_circuit = Arc::new(Circuit::new(&circuit_builder));

    let calldata = program_input
        .iter()
        .map(|x| F::from(*x as u64))
        .collect_vec();
    let wires_in = vec![
        (0..calldata.len())
            .step_by(StackUInt::N_OPRAND_CELLS)
            .map(|i| calldata[i..i + StackUInt::N_OPRAND_CELLS].to_vec())
            .collect_vec(),
        (0..calldata.len())
            .map(|x| vec![F::from(x as u64)])
            .collect_vec(),
    ];

    let table_node_id = builder.add_node_with_witness(
        "calldata table circuit",
        &calldata_circuit,
        vec![PredType::Source; 2],
        real_challenges.to_vec(),
        wires_in,
    )?;

    let pad_circuit = Arc::new(den_to_frac_circuit(calldata.len()));
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
