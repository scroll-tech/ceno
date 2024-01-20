use std::sync::Arc;

use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use strum_macros::EnumIter;

use crate::chips::bytecode::construct_bytecode_table;
use crate::chips::calldata::construct_calldata_table;
use crate::constants::RANGE_CHIP_BIT_WIDTH;
use crate::ChipChallenges;
use crate::{error::ZKVMError, instructions::InstOutputType};

use self::range::construct_range_table;

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

/// Construct tree-structured frac sum or product circuit. Return the node id of
/// the root circuit.
pub(crate) fn construct_chip_circuits<F: SmallField>(
    graph_builder: &mut CircuitGraphBuilder<F>,
    inst_output_type: InstOutputType,
    pred_wire_out_id: NodeOutputType,
    instance_num_vars: usize,
    gadgets: &ChipCircuitGadgets<F>,
    challenges: &[F],
) -> Result<NodeOutputType, ZKVMError> {
    let (leaf, inner) = match inst_output_type {
        // Construct a subset circuit in set equality argument.
        InstOutputType::GlobalStateIn
        | InstOutputType::GlobalStateOut
        | InstOutputType::StackPop
        | InstOutputType::StackPush
        | InstOutputType::MemoryLoad
        | InstOutputType::MemoryStore => (&gadgets.product_circuit, &gadgets.product_circuit),
        // Construct a input subset in lookup argument.
        InstOutputType::BytecodeChip | InstOutputType::CalldataChip | InstOutputType::RangeChip => {
            (&gadgets.frac_sum_circuit, &gadgets.frac_sum_circuit)
        }
    };

    build_tree_circuits(
        graph_builder,
        PredType::PredWire(pred_wire_out_id),
        leaf,
        inner,
        challenges,
        instance_num_vars,
    )
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub(crate) enum LookupChipType {
    BytecodeChip,
    RangeChip,
    CalldataChip,
}

pub(crate) fn construct_table_circuits<F: SmallField>(
    table: LookupChipType,
    builder: &mut CircuitGraphBuilder<F>,
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
                construct_bytecode_table(builder, bytecode, challenges, real_challenges)?
            }

            LookupChipType::CalldataChip => {
                construct_calldata_table(builder, program_input, challenges, real_challenges)?
            }
            LookupChipType::RangeChip => {
                construct_range_table(builder, RANGE_CHIP_BIT_WIDTH, challenges, real_challenges)?
            }
        };
        (
            // TODO: Remove O2O and O2M
            PredType::PredWireTrans(NodeOutputType::OutputLayer(id)),
            num_vars,
        )
    };
    build_tree_circuits(builder, pred, leaf, inner, real_challenges, num_vars)
}

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
                .map(|(id, _)| PredType::PredWire(NodeOutputType::OutputLayer(id))),
            Err(err) => Err(err),
        }
    })?;
    match last_pred {
        PredType::PredWire(out) => Ok(out),
        PredType::PredWireTrans(out) => Ok(out),
        _ => unreachable!(),
    }
}
