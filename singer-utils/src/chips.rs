use std::{mem, sync::Arc};

use ff_ext::ExtensionField;
use gkr::{
    structs::{Circuit, LayerWitness},
    utils::ceil_log2,
};
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use simple_frontend::structs::WitnessId;
pub use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{
    constants::RANGE_CHIP_BIT_WIDTH,
    error::UtilError,
    structs::{ChipChallenges, InstOutChipType},
};

use self::{
    bytecode::{construct_bytecode_table, construct_bytecode_table_and_witness},
    calldata::{construct_calldata_table, construct_calldata_table_and_witness},
    circuit_gadgets::{LeafCircuit, LeafFracSumCircuit, LeafFracSumNoSelectorCircuit},
    range::{construct_range_table, construct_range_table_and_witness},
};

mod bytecode;
mod calldata;
mod range;

pub mod circuit_gadgets;

#[derive(Clone, Debug)]
pub struct SingerChipBuilder<E: ExtensionField> {
    pub chip_circuit_gadgets: ChipCircuitGadgets<E>,
    pub output_wires_id: Vec<Vec<NodeOutputType>>,
}

impl<E: ExtensionField> SingerChipBuilder<E> {
    pub fn new() -> Self {
        let chip_circuit_gadgets = ChipCircuitGadgets::new();
        Self {
            chip_circuit_gadgets,
            output_wires_id: vec![vec![]; InstOutChipType::iter().count()],
        }
    }

    /// Construct the product of frac sum circuits for to chips of each circuit
    /// and witnesses. This includes computing the LHS and RHS of the set
    /// equality check, and the input of lookup arguments.
    pub fn construct_chip_check_graph_and_witness(
        &mut self,
        graph_builder: &mut CircuitGraphBuilder<E>,
        node_id: usize,
        to_chip_ids: &[Option<(WitnessId, usize)>],
        real_challenges: &[E],
        real_n_instances: usize,
    ) -> Result<(), UtilError> {
        let mut build = |real_n_instances: usize,
                         num: usize,
                         input_wit_id: WitnessId,
                         leaf: &LeafCircuit<E>,
                         inner: &Arc<Circuit<E>>|
         -> Result<NodeOutputType, UtilError> {
            let selector = ChipCircuitGadgets::construct_prefix_selector(real_n_instances, num);
            let selector_node_id = graph_builder.add_node_with_witness(
                "selector circuit",
                &selector.circuit,
                vec![],
                real_challenges.to_vec(),
                vec![],
                real_n_instances.next_power_of_two(),
            )?;
            let mut preds = vec![PredType::Source; 2];
            preds[leaf.input_id as usize] =
                PredType::PredWire(NodeOutputType::WireOut(node_id, input_wit_id));
            preds[leaf.cond_id as usize] =
                PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id));

            let instance_num_vars = ceil_log2(real_n_instances * num) - 1;
            build_tree_graph_and_witness(
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
        for output_type in [InstOutChipType::RAMLoad, InstOutChipType::RAMStore] {
            if let Some((id, num)) = to_chip_ids[output_type as usize] {
                let out = build(
                    real_n_instances,
                    num,
                    id,
                    &self.chip_circuit_gadgets.product_leaf,
                    &self.chip_circuit_gadgets.product_inner,
                )?;
                self.output_wires_id[output_type as usize].push(out);
            }
        }

        // Lookup argument
        for output_type in [InstOutChipType::ROMInput] {
            if let Some((id, num)) = to_chip_ids[output_type as usize] {
                let out = build(
                    real_n_instances,
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

    /// Construct the product of frac sum circuits for to chips of each circuit.
    /// This includes computing the LHS and RHS of the set equality check, and
    /// the input of lookup arguments.
    pub fn construct_chip_check_graph(
        &mut self,
        graph_builder: &mut CircuitGraphBuilder<E>,
        node_id: usize,
        to_chip_ids: &[Option<(WitnessId, usize)>],
        real_n_instances: usize,
    ) -> Result<(), UtilError> {
        let mut build = |n_instances: usize,
                         num: usize,
                         input_wit_id: WitnessId,
                         leaf: &LeafCircuit<E>,
                         inner: &Arc<Circuit<E>>|
         -> Result<NodeOutputType, UtilError> {
            let selector = ChipCircuitGadgets::construct_prefix_selector(n_instances, num);
            let selector_node_id =
                graph_builder.add_node("selector circuit", &selector.circuit, vec![])?;
            let mut preds = vec![PredType::Source; 2];
            preds[leaf.input_id as usize] =
                PredType::PredWire(NodeOutputType::WireOut(node_id, input_wit_id));
            preds[leaf.cond_id as usize] =
                PredType::PredWire(NodeOutputType::OutputLayer(selector_node_id));

            let instance_num_vars = ceil_log2(real_n_instances) - 1;
            build_tree_graph(
                graph_builder,
                preds,
                &leaf.circuit,
                inner,
                instance_num_vars,
            )
        };

        // Set equality argument
        for output_type in [InstOutChipType::RAMLoad, InstOutChipType::RAMStore] {
            if let Some((id, num)) = to_chip_ids[output_type as usize] {
                let out = build(
                    real_n_instances,
                    num,
                    id,
                    &self.chip_circuit_gadgets.product_leaf,
                    &self.chip_circuit_gadgets.product_inner,
                )?;
                self.output_wires_id[output_type as usize].push(out);
            }
        }

        // Lookup argument
        for output_type in [InstOutChipType::ROMInput] {
            if let Some((id, num)) = to_chip_ids[output_type as usize] {
                let out = build(
                    real_n_instances,
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

    /// Construct circuits and witnesses to generate the lookup table for each
    /// table, including bytecode, range and calldata. Also generate the
    /// tree-structured circuits to fold the summation.
    pub fn construct_lookup_table_graph_and_witness(
        &self,
        graph_builder: &mut CircuitGraphBuilder<E>,
        bytecode: &[u8],
        program_input: &[u8],
        mut table_count_witness: Vec<LayerWitness<E::BaseField>>,
        challenges: &ChipChallenges,
        real_challenges: &[E],
    ) -> Result<Vec<NodeOutputType>, UtilError> {
        let mut tables_out = vec![NodeOutputType::OutputLayer(0); LookupChipType::iter().count()];

        let leaf = &self.chip_circuit_gadgets.frac_sum_leaf;
        let inner = &self.chip_circuit_gadgets.frac_sum_inner;
        let mut pred_source = |table_type, table_pred, selector_pred| {
            let mut preds = vec![PredType::Source; 3];
            preds[leaf.input_den_id as usize] = table_pred;
            preds[leaf.cond_id as usize] = selector_pred;
            let mut sources = vec![LayerWitness::default(); 3];
            sources[leaf.input_num_id as usize].instances =
                mem::take(&mut table_count_witness[table_type as usize].instances);
            (preds, sources)
        };

        let (input_pred, selector_pred, instance_num_vars) = construct_bytecode_table_and_witness(
            graph_builder,
            bytecode,
            challenges,
            real_challenges,
        )?;
        let (preds, sources) = pred_source(
            LookupChipType::BytecodeChip as usize,
            input_pred,
            selector_pred,
        );
        tables_out[LookupChipType::BytecodeChip as usize] = build_tree_graph_and_witness(
            graph_builder,
            preds,
            &leaf.circuit,
            inner,
            sources,
            real_challenges,
            instance_num_vars,
        )?;

        let (input_pred, selector_pred, instance_num_vars) = construct_calldata_table_and_witness(
            graph_builder,
            program_input,
            challenges,
            real_challenges,
        )?;
        let (preds, sources) = pred_source(
            LookupChipType::CalldataChip as usize,
            input_pred,
            selector_pred,
        );
        tables_out[LookupChipType::CalldataChip as usize] = build_tree_graph_and_witness(
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
            let mut sources = vec![LayerWitness::default(); 3];
            sources[leaf.input_num_id as usize].instances =
                mem::take(&mut table_count_witness[table_type as usize].instances);
            (preds, sources)
        };
        let (input_pred, instance_num_vars) = construct_range_table_and_witness(
            graph_builder,
            RANGE_CHIP_BIT_WIDTH,
            challenges,
            real_challenges,
        )?;
        let (preds, sources) = preds_no_selector(LookupChipType::RangeChip as usize, input_pred);
        tables_out[LookupChipType::RangeChip as usize] = build_tree_graph_and_witness(
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

    /// Construct circuits to generate the lookup table for each table, including
    /// bytecode, range and calldata. Also generate the tree-structured circuits to
    /// fold the summation.
    pub fn construct_lookup_table_graph(
        &self,
        graph_builder: &mut CircuitGraphBuilder<E>,
        byte_code_len: usize,
        program_input_len: usize,
        challenges: &ChipChallenges,
    ) -> Result<Vec<NodeOutputType>, UtilError> {
        let mut tables_out = vec![NodeOutputType::OutputLayer(0); LookupChipType::iter().count()];

        let leaf = &self.chip_circuit_gadgets.frac_sum_leaf;
        let inner = &self.chip_circuit_gadgets.frac_sum_inner;
        let compute_preds = |table_pred, selector_pred| {
            let mut preds = vec![PredType::Source; 3];
            preds[leaf.input_den_id as usize] = table_pred;
            preds[leaf.cond_id as usize] = selector_pred;
            preds
        };

        let (input_pred, selector_pred, instance_num_vars) =
            construct_bytecode_table(graph_builder, byte_code_len, challenges)?;
        let preds = compute_preds(input_pred, selector_pred);
        tables_out[LookupChipType::BytecodeChip as usize] = build_tree_graph(
            graph_builder,
            preds,
            &leaf.circuit,
            inner,
            instance_num_vars,
        )?;

        let (input_pred, selector_pred, instance_num_vars) =
            construct_calldata_table(graph_builder, program_input_len, challenges)?;
        let preds = compute_preds(input_pred, selector_pred);
        tables_out[LookupChipType::CalldataChip as usize] = build_tree_graph(
            graph_builder,
            preds,
            &leaf.circuit,
            inner,
            instance_num_vars,
        )?;

        let leaf = &self.chip_circuit_gadgets.frac_sum_leaf_no_selector;
        let compute_preds_no_selector = |table_pred| {
            let mut preds = vec![PredType::Source; 2];
            preds[leaf.input_den_id as usize] = table_pred;
            preds
        };
        let (input_pred, instance_num_vars) =
            construct_range_table(graph_builder, RANGE_CHIP_BIT_WIDTH, challenges)?;
        let preds = compute_preds_no_selector(input_pred);
        tables_out[LookupChipType::RangeChip as usize] = build_tree_graph(
            graph_builder,
            preds,
            &leaf.circuit,
            inner,
            instance_num_vars,
        )?;
        Ok(tables_out)
    }
}

#[derive(Clone, Debug)]
pub struct ChipCircuitGadgets<E: ExtensionField> {
    inv_sum: LeafCircuit<E>,
    frac_sum_inner: Arc<Circuit<E>>,
    frac_sum_leaf: LeafFracSumCircuit<E>,
    frac_sum_leaf_no_selector: LeafFracSumNoSelectorCircuit<E>,
    product_inner: Arc<Circuit<E>>,
    product_leaf: LeafCircuit<E>,
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum LookupChipType {
    BytecodeChip,
    RangeChip,
    CalldataChip,
}

/// Generate the tree-structured circuit and witness to compute the product or
/// summation. `instance_num_vars` is corresponding to the leaves.
fn build_tree_graph_and_witness<E: ExtensionField>(
    graph_builder: &mut CircuitGraphBuilder<E>,
    first_pred: Vec<PredType>,
    leaf: &Arc<Circuit<E>>,
    inner: &Arc<Circuit<E>>,
    first_source: Vec<LayerWitness<E::BaseField>>,
    real_challenges: &[E],
    instance_num_vars: usize,
) -> Result<NodeOutputType, UtilError> {
    let (last_pred, _) =
        (0..=instance_num_vars).fold(Ok((first_pred, first_source)), |prev, i| {
            let circuit = if i == 0 { leaf } else { inner };
            match prev {
                Ok((pred, source)) => graph_builder
                    .add_node_with_witness(
                        "tree inner node",
                        circuit,
                        pred,
                        real_challenges.to_vec(),
                        source,
                        1 << (instance_num_vars - i),
                    )
                    .map(|id| {
                        (
                            vec![PredType::PredWire(NodeOutputType::OutputLayer(id))],
                            vec![LayerWitness { instances: vec![] }],
                        )
                    }),
                Err(err) => Err(err),
            }
        })?;
    match last_pred[0] {
        PredType::PredWire(out) => Ok(out),
        _ => unreachable!(),
    }
}

/// Generate the tree-structured circuit to compute the product or summation.
/// `instance_num_vars` is corresponding to the leaves.
fn build_tree_graph<E: ExtensionField>(
    graph_builder: &mut CircuitGraphBuilder<E>,
    first_pred: Vec<PredType>,
    leaf: &Arc<Circuit<E>>,
    inner: &Arc<Circuit<E>>,
    instance_num_vars: usize,
) -> Result<NodeOutputType, UtilError> {
    let last_pred = (0..=instance_num_vars).fold(Ok(first_pred), |prev, i| {
        let circuit = if i == 0 { leaf } else { inner };
        match prev {
            Ok(pred) => graph_builder
                .add_node("tree inner node", circuit, pred)
                .map(|id| vec![PredType::PredWire(NodeOutputType::OutputLayer(id))]),
            Err(err) => Err(err),
        }
    })?;
    match last_pred[0] {
        PredType::PredWire(out) => Ok(out),
        _ => unreachable!(),
    }
}
