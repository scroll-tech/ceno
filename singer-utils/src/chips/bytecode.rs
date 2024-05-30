use std::sync::Arc;

use ff_ext::ExtensionField;
use gkr::structs::{Circuit, LayerWitness};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use itertools::Itertools;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use sumcheck::util::ceil_log2;

use crate::{
    error::UtilError,
    structs::{ChipChallenges, PCUInt, ROMType},
};

use super::ChipCircuitGadgets;

/// Add bytecode table circuit and witness to the circuit graph. Return node id
/// and lookup instance log size.
pub(crate) fn construct_bytecode_table_and_witness<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
    bytecode: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[E],
) -> Result<(PredType, PredType, usize), UtilError> {
    let mut circuit_builder = CircuitBuilder::<E>::new();
    let (_, pc_cells) = circuit_builder.create_witness_in(PCUInt::N_OPRAND_CELLS);
    let (_, bytecode_cells) = circuit_builder.create_witness_in(1);

    let rlc = circuit_builder.create_ext_cell();
    let mut items = vec![MixedCell::Constant(E::BaseField::from(
        ROMType::Bytecode as u64,
    ))];
    items.extend(pc_cells.iter().map(|x| MixedCell::Cell(*x)).collect_vec());
    items.extend(
        bytecode_cells
            .iter()
            .map(|x| MixedCell::Cell(*x))
            .collect_vec(),
    );
    circuit_builder.rlc_mixed(&rlc, &items, challenges.bytecode());

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

    let wits_in = vec![
        LayerWitness {
            instances: PCUInt::counter_vector::<E::BaseField>(bytecode.len().next_power_of_two())
                .into_iter()
                .map(|x| vec![x])
                .collect_vec(),
        },
        LayerWitness {
            instances: bytecode
                .iter()
                .map(|x| vec![E::BaseField::from(*x as u64)])
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
pub(crate) fn construct_bytecode_table<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
    bytecode_len: usize,
    challenges: &ChipChallenges,
) -> Result<(PredType, PredType, usize), UtilError> {
    let mut circuit_builder = CircuitBuilder::<E>::new();
    let (_, pc_cells) = circuit_builder.create_witness_in(PCUInt::N_OPRAND_CELLS);
    let (_, bytecode_cells) = circuit_builder.create_witness_in(1);

    let rlc = circuit_builder.create_ext_cell();
    let mut items = vec![MixedCell::Constant(E::BaseField::from(
        ROMType::Bytecode as u64,
    ))];
    items.extend(pc_cells.iter().map(|x| MixedCell::Cell(*x)).collect_vec());
    items.extend(
        bytecode_cells
            .iter()
            .map(|x| MixedCell::Cell(*x))
            .collect_vec(),
    );
    circuit_builder.rlc_mixed(&rlc, &items, challenges.bytecode());

    circuit_builder.configure();
    let bytecode_circuit = Arc::new(Circuit::new(&circuit_builder));
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
