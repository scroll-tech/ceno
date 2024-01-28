use std::mem;
use std::sync::Arc;

use gkr::structs::Circuit;
use gkr::utils::ceil_log2;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use simple_frontend::structs::WireId;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::chips::bytecode::construct_bytecode_table;
use crate::chips::calldata::construct_calldata_table;
use crate::component::{ChipType, ToChipsWires};
use crate::constants::RANGE_CHIP_BIT_WIDTH;
use crate::error::ZKVMError;
use crate::{ChipChallenges, WirsInValues};

use self::circuit_gadgets::{LeafCircuit, LeafFracSumCircuit, LeafFracSumNoSelectorCircuit};
use self::range::construct_range_table;

mod bytecode;
mod calldata;
mod range;

pub mod circuit_gadgets;

pub struct SingerChipBuilder<F: SmallField> {
    pub(crate) chip_circuit_gadgets: ChipCircuitGadgets<F>,
    pub(crate) output_wires_id: Vec<Vec<NodeOutputType>>,
}

impl<F: SmallField> SingerChipBuilder<F> {
    pub fn new(challenges: ChipChallenges) -> Self {
        let chip_circuit_gadgets = ChipCircuitGadgets::new();
        Self {
            chip_circuit_gadgets,
            output_wires_id: vec![vec![]; ChipType::iter().count()],
        }
    }

    /// Construct the product of frac sum circuits for to chips of each circuit.
    /// This includes computing the LHS and RHS of the set equality check, and
    /// the input of lookup arguments.
    pub(crate) fn construct_chip_checks(
        &mut self,
        graph_builder: &mut CircuitGraphBuilder<F>,
        node_id: usize,
        to_chip_ids: &ToChipsWires,
        real_challenges: &[F],
        n_instances: usize,
    ) -> Result<(), ZKVMError> {
        let mut build = |n_instances: usize,
                         num: usize,
                         input_wire_id: WireId,
                         leaf: &LeafCircuit<F>,
                         inner: &Arc<Circuit<F>>|
         -> Result<NodeOutputType, ZKVMError> {
            let selector = ChipCircuitGadgets::construct_prefix_selector(n_instances, num);
            let selector_node_id = graph_builder.add_node_with_witness(
                "selector circuit",
                &selector.circuit,
                vec![],
                real_challenges.to_vec(),
                vec![],
            )?;
            let mut preds = vec![PredType::Source; 2];
            preds[leaf.input_id as usize] =
                PredType::PredWire(NodeOutputType::WireOut(node_id, input_wire_id));
            preds[leaf.cond_id as usize] =
                PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id));

            let instance_num_vars = ceil_log2(n_instances * num) - 1;
            build_tree_circuits(
                graph_builder,
                preds,
                &leaf.circuit,
                inner,
                vec![],
                real_challenges,
                instance_num_vars,
            )
        };

        // Set equality argument
        for output_type in [
            ChipType::GlobalStateIn,
            ChipType::GlobalStateOut,
            ChipType::StackPop,
            ChipType::StackPush,
            ChipType::MemoryLoad,
            ChipType::MemoryStore,
        ] {
            if let Some((id, num)) = to_chip_ids[output_type as usize] {
                let out = build(
                    n_instances,
                    num,
                    id,
                    &self.chip_circuit_gadgets.product_leaf,
                    &self.chip_circuit_gadgets.product_inner,
                )?;
                self.output_wires_id[output_type as usize].push(out);
            }
        }

        // Lookup argument
        for output_type in [
            ChipType::BytecodeChip,
            ChipType::CalldataChip,
            ChipType::RangeChip,
        ] {
            if let Some((id, num)) = to_chip_ids[output_type as usize] {
                let out = build(
                    n_instances,
                    num,
                    id,
                    &self.chip_circuit_gadgets.inv_sum,
                    &self.chip_circuit_gadgets.frac_sum_inner,
                )?;
                self.output_wires_id[output_type as usize].push(out);
            }
        }

        Ok(())
    }

    /// Construct circuits to generate the lookup table for each table, including
    /// bytecode, range and calldata. Also generate the tree-structured circuits to
    /// fold the summation.
    pub(crate) fn construct_chip_tables(
        &self,
        graph_builder: &mut CircuitGraphBuilder<F>,
        basic_blocks: &[Vec<u8>],
        program_input: &[u8],
        mut table_count_witness: Vec<WirsInValues<F::BaseField>>,
        challenges: &ChipChallenges,
        real_challenges: &[F],
    ) -> Result<Vec<NodeOutputType>, ZKVMError> {
        let mut tables_out = vec![NodeOutputType::OutputLayer(0); LookupChipType::iter().count()];

        let leaf = &self.chip_circuit_gadgets.frac_sum_leaf;
        let inner = &self.chip_circuit_gadgets.frac_sum_inner;
        let mut pred_source = |table_type, table_pred, selector_pred| {
            let mut preds = vec![PredType::Source; 3];
            preds[leaf.input_den_id as usize] = table_pred;
            preds[leaf.cond_id as usize] = selector_pred;
            let mut sources = vec![vec![]; 3];
            sources[leaf.input_num_id as usize] =
                mem::take(&mut table_count_witness[table_type as usize]);
            (preds, sources)
        };

        let (input_pred, selector_pred, instance_num_vars) =
            construct_bytecode_table(graph_builder, basic_blocks, challenges, real_challenges)?;
        let (preds, sources) = pred_source(
            LookupChipType::BytecodeChip as usize,
            input_pred,
            selector_pred,
        );
        tables_out[LookupChipType::BytecodeChip as usize] = build_tree_circuits(
            graph_builder,
            preds,
            &leaf.circuit,
            inner,
            sources,
            real_challenges,
            instance_num_vars,
        )?;

        let (input_pred, selector_pred, instance_num_vars) =
            construct_calldata_table(graph_builder, program_input, challenges, real_challenges)?;
        let (preds, sources) = pred_source(
            LookupChipType::CalldataChip as usize,
            input_pred,
            selector_pred,
        );
        tables_out[LookupChipType::CalldataChip as usize] = build_tree_circuits(
            graph_builder,
            preds,
            &leaf.circuit,
            inner,
            sources,
            real_challenges,
            instance_num_vars,
        )?;

        let leaf = &self.chip_circuit_gadgets.frac_sum_leaf_no_selector;
        let mut preds_no_selector = |table_type, table_pred| {
            let mut preds = vec![PredType::Source; 2];
            preds[leaf.input_den_id as usize] = table_pred;
            let mut sources = vec![vec![]; 3];
            sources[leaf.input_num_id as usize] =
                mem::take(&mut table_count_witness[table_type as usize]);
            (preds, sources)
        };
        let (input_pred, instance_num_vars) = construct_range_table(
            graph_builder,
            RANGE_CHIP_BIT_WIDTH,
            challenges,
            real_challenges,
        )?;
        let (preds, sources) = preds_no_selector(LookupChipType::RangeChip as usize, input_pred);
        tables_out[LookupChipType::RangeChip as usize] = build_tree_circuits(
            graph_builder,
            preds,
            &leaf.circuit,
            inner,
            sources,
            real_challenges,
            instance_num_vars,
        )?;
        Ok(tables_out)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChipCircuitGadgets<F: SmallField> {
    inv_sum: LeafCircuit<F>,
    frac_sum_inner: Arc<Circuit<F>>,
    frac_sum_leaf: LeafFracSumCircuit<F>,
    frac_sum_leaf_no_selector: LeafFracSumNoSelectorCircuit<F>,
    product_inner: Arc<Circuit<F>>,
    product_leaf: LeafCircuit<F>,
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
    first_pred: Vec<PredType>,
    leaf: &Arc<Circuit<F>>,
    inner: &Arc<Circuit<F>>,
    first_source: Vec<Vec<Vec<F::BaseField>>>,
    real_challenges: &[F],
    instance_num_vars: usize,
) -> Result<NodeOutputType, ZKVMError> {
    let (last_pred, _) =
        (0..instance_num_vars).fold(Ok((first_pred, first_source)), |prev, i| {
            let circuit = if i == 0 { leaf } else { inner };
            match prev {
                Ok((pred, source)) => graph_builder
                    .add_node_with_witness(
                        "tree inner node",
                        circuit,
                        pred,
                        real_challenges.to_vec(),
                        source,
                    )
                    .map(|id| {
                        (
                            vec![PredType::PredWire(NodeOutputType::OutputLayer(id))],
                            vec![vec![]],
                        )
                    }),
                Err(err) => Err(err),
            }
        })?;
    match last_pred[0] {
        PredType::PredWire(out) => Ok(out),
        PredType::PredWireTrans(out) => Ok(out),
        _ => unreachable!(),
    }
}
