use std::sync::Arc;

use gkr::structs::Circuit;
use gkr::utils::ceil_log2;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use strum_macros::EnumIter;

use crate::chips::bytecode::construct_bytecode_table;
use crate::chips::calldata::construct_calldata_table;
use crate::constants::RANGE_CHIP_BIT_WIDTH;
use crate::ChipChallenges;
use crate::{error::ZKVMError, instructions::InstOutputType};

use self::range::construct_range_table;
use self::utils::{den_to_frac_circuit, pad_with_const_circuit};

mod bytecode;
mod calldata;
mod range;
mod utils;

pub mod circuit_gadgets;

#[derive(Clone, Debug)]
pub struct ChipCircuitGadgets<F: SmallField> {
    frac_sum_circuit: Arc<Circuit<F>>,
    product_circuit: Arc<Circuit<F>>,
}

/// Construct circuits to generate the lookup table for each table, including
/// bytecode, range and calldata. Also generate the tree-structured circuits to
/// fold the summation.
pub(crate) fn construct_table_circuits<F: SmallField>(
    table: LookupChipType,
    graph_builder: &mut CircuitGraphBuilder<F>,
    bytecode: &[u8],
    program_input: &[u8],
    challenges: &ChipChallenges,
    real_challenges: &[F],
    gadgets: &ChipCircuitGadgets<F>,
) -> Result<NodeOutputType, ZKVMError> {
    let leaf = &gadgets.frac_sum_circuit;
    let inner = &gadgets.frac_sum_circuit;

    let (pred, num_vars) = {
        let (id, num_vars) = match table {
            LookupChipType::BytecodeChip => {
                construct_bytecode_table(graph_builder, bytecode, challenges, real_challenges)?
            }

            LookupChipType::CalldataChip => {
                construct_calldata_table(graph_builder, program_input, challenges, real_challenges)?
            }
            LookupChipType::RangeChip => construct_range_table(
                graph_builder,
                RANGE_CHIP_BIT_WIDTH,
                challenges,
                real_challenges,
            )?,
        };
        (
            PredType::PredWireTrans(NodeOutputType::OutputLayer(id)),
            num_vars,
        )
    };
    build_tree_circuits(graph_builder, pred, leaf, inner, real_challenges, num_vars)
}

/// Construct tree-structured frac sum or product circuit for each instruction.
/// Return the node output of the root circuit.
pub(crate) fn construct_inst_chip_circuits<F: SmallField>(
    builder: &mut CircuitGraphBuilder<F>,
    inst_output_type: InstOutputType,
    pred_wire_out_id: NodeOutputType,
    n_instances: usize,
    gadgets: &ChipCircuitGadgets<F>,
    real_challenges: &[F],
) -> Result<NodeOutputType, ZKVMError> {
    let (pred, leaf, inner) = match inst_output_type {
        // Construct a subset circuit in set equality argument.
        InstOutputType::GlobalStateIn
        | InstOutputType::GlobalStateOut
        | InstOutputType::StackPop
        | InstOutputType::StackPush
        | InstOutputType::MemoryLoad
        | InstOutputType::MemoryStore => {
            // Pad the instance to a power of 2 with 1s.
            let pad_circuit = Arc::new(pad_with_const_circuit(n_instances, 1));
            let pad_node_id = builder.add_node_with_witness(
                "instruction pad 1 circuit",
                &pad_circuit,
                vec![PredType::PredWire(pred_wire_out_id)],
                real_challenges.to_vec(),
                vec![vec![]; pad_circuit.n_wires_in],
            )?;
            (
                PredType::PredWire(NodeOutputType::OutputLayer(pad_node_id)),
                &gadgets.product_circuit,
                &gadgets.product_circuit,
            )
        }
        // Construct a input subset in lookup argument.
        InstOutputType::BytecodeChip | InstOutputType::CalldataChip | InstOutputType::RangeChip => {
            // Convert the vector of denominators to a vector of fractions, padded with zero fractions.
            let pad_circuit = Arc::new(den_to_frac_circuit(n_instances));
            let pad_node_id = builder.add_node_with_witness(
                "instruction pad 0 frac circuit",
                &pad_circuit,
                vec![PredType::PredWire(pred_wire_out_id)],
                real_challenges.to_vec(),
                vec![vec![]; pad_circuit.n_wires_in],
            )?;
            (
                PredType::PredWireTrans(NodeOutputType::OutputLayer(pad_node_id)),
                &gadgets.frac_sum_circuit,
                &gadgets.frac_sum_circuit,
            )
        }
    };

    let instance_num_vars = ceil_log2(n_instances);
    build_tree_circuits(
        builder,
        pred,
        leaf,
        inner,
        real_challenges,
        instance_num_vars,
    )
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub(crate) enum LookupChipType {
    BytecodeChip,
    RangeChip,
    CalldataChip,
}

/// Generate the tree-structured circuit to compute the product or summation.
fn build_tree_circuits<F: SmallField>(
    graph_builder: &mut CircuitGraphBuilder<F>,
    first_pred: PredType,
    leaf: &Arc<Circuit<F>>,
    inner: &Arc<Circuit<F>>,
    real_challenges: &[F],
    instance_num_vars: usize,
) -> Result<NodeOutputType, ZKVMError> {
    let last_pred = (0..instance_num_vars).fold(Ok(first_pred), |prev_pred, i| {
        let circuit = if i == 0 { leaf } else { inner };
        match prev_pred {
            Ok(pred) => graph_builder
                .add_node_with_witness(
                    "tree inner node",
                    circuit,
                    vec![pred],
                    real_challenges.to_vec(),
                    vec![vec![]; 1],
                )
                .map(|id| PredType::PredWire(NodeOutputType::OutputLayer(id))),
            Err(err) => Err(err),
        }
    })?;
    match last_pred {
        PredType::PredWire(out) => Ok(out),
        PredType::PredWireTrans(out) => Ok(out),
        _ => unreachable!(),
    }
}
