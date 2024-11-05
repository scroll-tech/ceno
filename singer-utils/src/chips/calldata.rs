use std::sync::Arc;

use crate::{
    error::UtilError,
    structs::{ChipChallenges, StackUInt, UInt64},
};

use super::ChipCircuitGadgets;
use crate::chip_handler::{ChipHandler, calldata::CalldataChip};
use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use simple_frontend::structs::CircuitBuilder;
use sumcheck::util::ceil_log2;

fn construct_circuit<E: ExtensionField>(challenges: &ChipChallenges) -> Arc<Circuit<E>> {
    let mut circuit_builder = CircuitBuilder::<E>::default();
    let (_, id_cells) = circuit_builder.create_witness_in(UInt64::N_OPERAND_CELLS);
    let (_, calldata_cells) = circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);

    let mut chip_handler = ChipHandler::new(*challenges);

    CalldataChip::load(
        &mut chip_handler,
        &mut circuit_builder,
        &id_cells,
        &calldata_cells,
    );

    let _ = chip_handler.finalize(&mut circuit_builder);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Add calldata table circuit and witness to the circuit graph. Return node id
/// and lookup instance log size.
pub(crate) fn construct_calldata_table_and_witness<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
    program_input: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[E],
) -> Result<(PredType, PredType, usize), UtilError> {
    let calldata_circuit = construct_circuit(challenges);
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
        .map(|x| E::BaseField::from(*x as u64))
        .collect_vec();

    let wits_in = vec![
        {
            let len = calldata.len().next_power_of_two();
            DenseMultilinearExtension::from_evaluations_vec(
                ceil_log2(len),
                (0..len).map(|x| E::BaseField::from(x as u64)).collect_vec(),
            )
        },
        {
            let len = calldata.len().next_power_of_two();
            let mut calldata = (0..calldata.len())
                .step_by(StackUInt::N_OPERAND_CELLS)
                .flat_map(|i| {
                    calldata[i..(i + StackUInt::N_OPERAND_CELLS).min(calldata.len())]
                        .iter()
                        .cloned()
                        .rev()
                        .collect_vec()
                })
                .collect_vec();
            calldata.resize(len, E::BaseField::ZERO);
            DenseMultilinearExtension::from_evaluations_vec(ceil_log2(len), calldata)
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

/// Add calldata table circuit to the circuit graph. Return node id and lookup
/// instance log size.
pub(crate) fn construct_calldata_table<E: ExtensionField>(
    builder: &mut CircuitGraphBuilder<E>,
    program_input_len: usize,
    challenges: &ChipChallenges,
) -> Result<(PredType, PredType, usize), UtilError> {
    let calldata_circuit = construct_circuit(challenges);
    let selector = ChipCircuitGadgets::construct_prefix_selector(program_input_len, 1);

    let selector_node_id =
        builder.add_node("calldata selector circuit", &selector.circuit, vec![])?;

    let table_node_id = builder.add_node(
        "calldata table circuit",
        &calldata_circuit,
        vec![PredType::Source; 2],
    )?;

    Ok((
        PredType::PredWire(NodeOutputType::OutputLayer(table_node_id)),
        PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id)),
        ceil_log2(program_input_len) - 1,
    ))
}
