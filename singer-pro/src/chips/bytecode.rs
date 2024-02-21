use std::sync::Arc;

use gkr::{
    structs::{Circuit, LayerWitness},
    utils::ceil_log2,
};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::CircuitBuilder;

use crate::{component::ChipChallenges, error::ZKVMError, utils::uint::PCUInt};

use super::ChipCircuitGadgets;

/// Add bytecode table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_bytecode_table<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    bytecode: &[Vec<u8>],
    challenges: &ChipChallenges,
    real_challenges: &[F],
) -> Result<(PredType, PredType, usize), ZKVMError> {
    let bytecode = bytecode.concat();
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, pc_cells) = circuit_builder.create_witness_in(PCUInt::N_OPRAND_CELLS);
    let (_, bytecode_cells) = circuit_builder.create_witness_in(1);

    let rlc = circuit_builder.create_ext_cell();
    let mut items = pc_cells.clone();
    items.extend(bytecode_cells.clone());
    circuit_builder.rlc(&rlc, &items, challenges.bytecode());

    circuit_builder.configure();
    let bytecode_circuit = Arc::new(Circuit::new(&circuit_builder));
    let selector = ChipCircuitGadgets::construct_prefix_selector(bytecode.len(), 1);

    let selector_node_id = builder.add_node_with_witness(
        "bytecode selector circuit",
        &selector.circuit,
        vec![],
        real_challenges.to_vec(),
        vec![],
        bytecode.len().next_power_of_two(),
    )?;

    let wires_in = vec![
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
        wires_in,
        bytecode.len().next_power_of_two(),
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(bytecode.len()) - 1,
    ))
}
