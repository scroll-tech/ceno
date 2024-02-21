use std::sync::Arc;

use gkr::{
    structs::{Circuit, LayerWitness},
    utils::ceil_log2,
};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::CircuitBuilder;

use crate::{utils::uint::StackUInt, ChipChallenges, ZKVMError};

use super::ChipCircuitGadgets;

/// Add calldata table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_calldata_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    program_input: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(PredType, PredType, usize), ZKVMError> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, id_cells) = circuit_builder.create_witness_in(1);
    let (_, calldata_cells) = circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);

    let rlc = circuit_builder.create_ext_cell();
    let mut items = id_cells.clone();
    items.extend(calldata_cells.clone());
    circuit_builder.rlc(&rlc, &items, challenges.calldata());

    circuit_builder.configure();
    let calldata_circuit = Arc::new(Circuit::new(&circuit_builder));
    let selector = ChipCircuitGadgets::construct_prefix_selector(program_input.len(), 1);

    let selector_node_id = builder.add_node_with_witness(
        "calldata selector circuit",
        &selector.circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
        program_input.len().next_power_of_two(),
    )?;

    let calldata = program_input
        .iter()
        .map(|x| F::BaseField::from(*x as u64))
        .collect_vec();
    let wits_in = vec![
        LayerWitness {
            instances: (0..calldata.len())
                .map(|x| vec![F::BaseField::from(x as u64)])
                .collect_vec(),
        },
        LayerWitness {
            instances: (0..calldata.len())
                .step_by(StackUInt::N_OPRAND_CELLS)
                .map(|i| {
                    calldata[i..(i + StackUInt::N_OPRAND_CELLS).min(calldata.len())]
                        .iter()
                        .cloned()
                        .rev()
                        .collect_vec()
                })
                .collect_vec(),
        },
    ];

    let table_node_id = builder.add_node_with_witness(
        "calldata table circuit",
        &calldata_circuit,
        vec![PredType::Source; 2],
        real_challenges.to_vec(),
        wits_in,
        program_input.len().next_power_of_two(),
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(program_input.len()) - 1,
    ))
}
