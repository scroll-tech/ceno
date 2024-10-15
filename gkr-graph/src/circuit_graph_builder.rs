use std::{collections::BTreeSet, sync::Arc};

use ark_std::Zero;
use ff_ext::ExtensionField;
use gkr::structs::{Circuit, CircuitWitness};
use itertools::{chain, izip, Itertools};
use multilinear_extensions::{
    mle::DenseMultilinearExtension, virtual_poly_v2::ArcMultilinearExtension,
};
use simple_frontend::structs::WitnessId;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphBuilder, CircuitGraphWitness, CircuitNode, NodeInputType,
        NodeOutputType, PredType,
    },
};

impl<'a, E: ExtensionField> CircuitGraphBuilder<'a, E> {
    /// Add a new node indicating the predecessors and generate the witness.
    /// Return the index of the new node. sources has the same number as the
    /// input witnesses. If some witness is not source, then the corresponding
    /// entry in sources is default.
    pub fn add_node_with_witness(
        &mut self,
        label: &'static str,
        circuit: &Arc<Circuit<E>>,
        preds: Vec<PredType>,
        challenges: Vec<E>,
        sources: Vec<DenseMultilinearExtension<E>>,
        num_instances: usize,
    ) -> Result<usize, GKRGraphError> {
        let id = self.graph.nodes.len();
        // println!(
        //     "id: {}, label: {}, num_instances: {}, preds: {:?}",
        //     id, label, num_instances, preds
        // );

        assert_eq!(preds.len(), circuit.n_witness_in);
        assert!(num_instances.is_power_of_two());
        assert_eq!(sources.len(), circuit.n_witness_in);
        assert!(
            sources
                .iter()
                .all(|source| source.evaluations.len() % num_instances == 0),
            "node_id: {}, num_instances: {}, sources_num_instances: {:?}",
            id,
            num_instances,
            sources
                .iter()
                .map(|source| source.evaluations.len())
                .collect_vec()
        );

        let mut witness = CircuitWitness::new(circuit, challenges);
        let wits_in = izip!(preds.iter(), sources.into_iter())
            .map(|(pred, source)| match pred {
                PredType::Source => source.into(),
                PredType::PredWire(out) | PredType::PredWireDup(out) => {
                    let (id, out) = match out {
                        NodeOutputType::OutputLayer(id) => (
                            *id,
                            self.witness.node_witnesses[*id]
                                .output_layer_witness_ref()
                                .clone(),
                        ),
                        NodeOutputType::WireOut(id, wit_id) => (
                            *id,
                            self.witness.node_witnesses[*id].witness_out_ref()[*wit_id as usize]
                                .clone(),
                        ),
                    };
                    let old_num_instances = self.witness.node_witnesses[id].n_instances();
                    let new_instances: ArcMultilinearExtension<'a, E> = match pred {
                        PredType::PredWire(_) => out,
                        PredType::PredWireDup(_) => {
                            let num_dups = num_instances / old_num_instances;
                            let new: ArcMultilinearExtension<E> =
                                out.dup(old_num_instances, num_dups).into();
                            new
                        }
                        _ => unreachable!(),
                    };
                    new_instances
                }
            })
            .collect_vec();

        witness.set_instances(circuit, wits_in, num_instances);
        self.witness.node_witnesses.push(Arc::new(witness));

        self.graph.nodes.push(CircuitNode {
            id,
            label,
            circuit: circuit.clone(),
            preds,
        });

        Ok(id)
    }

    /// Add a new node indicating the predecessors. Return the index of the new
    /// node.
    pub fn add_node(
        &mut self,
        label: &'static str,
        circuit: &Arc<Circuit<E>>,
        preds: Vec<PredType>,
    ) -> Result<usize, GKRGraphError> {
        let id = self.graph.nodes.len();

        self.graph.nodes.push(CircuitNode {
            id,
            label,
            circuit: circuit.clone(),
            preds,
        });

        Ok(id)
    }

    /// Collect the information of `self.sources` and `self.targets`.
    pub fn finalize_graph_and_witness(mut self) -> (CircuitGraph<E>, CircuitGraphWitness<'a, E>) {
        // Generate all possible graph output
        let outs = self
            .graph
            .nodes
            .iter()
            .enumerate()
            .flat_map(|(id, node)| {
                chain![
                    (0..node.circuit.n_witness_out)
                        .map(move |wire_id| NodeOutputType::WireOut(id, wire_id as WitnessId)),
                    node.circuit
                        .n_witness_out
                        .is_zero()
                        .then_some(NodeOutputType::OutputLayer(id))
                ]
            })
            .collect::<BTreeSet<_>>();
        // Collect all assigned source into `sources`,
        // and remove assigned `PredWire*` from possible outs
        let (sources, targets) = self.graph.nodes.iter().enumerate().fold(
            (BTreeSet::new(), outs),
            |(mut sources, mut targets), (id, node)| {
                for (wire_id, pred) in node.preds.iter().enumerate() {
                    match pred {
                        PredType::Source => {
                            sources.insert(NodeInputType::WireIn(id, wire_id as WitnessId));
                        }
                        PredType::PredWire(out) => {
                            targets.remove(out);
                        }
                        PredType::PredWireDup(out) => {
                            targets.remove(out);
                        }
                    }
                }

                (sources, targets)
            },
        );
        self.graph.sources = sources.into_iter().collect();
        self.graph.targets = targets.into_iter().collect();

        (self.graph, self.witness)
    }

    pub fn finalize_graph(self) -> CircuitGraph<E> {
        let (graph, _) = self.finalize_graph_and_witness();
        graph
    }

    /// Collect the information of `self.sources` and `self.targets`.
    pub fn finalize_graph_and_witness_with_targets(
        mut self,
        targets: &[NodeOutputType],
    ) -> (CircuitGraph<E>, CircuitGraphWitness<'a, E>) {
        // Generate all possible graph output
        let outs = self
            .graph
            .nodes
            .iter()
            .enumerate()
            .flat_map(|(id, node)| {
                chain![
                    (0..node.circuit.n_witness_out)
                        .map(move |wire_id| NodeOutputType::WireOut(id, wire_id as WitnessId)),
                    node.circuit
                        .n_witness_out
                        .is_zero()
                        .then_some(NodeOutputType::OutputLayer(id))
                ]
            })
            .collect::<BTreeSet<_>>();
        // Collect all assigned source into `sources`,
        // and remove assigned `PredWire*` from possible outs
        let (sources, expected_target) = self.graph.nodes.iter().enumerate().fold(
            (BTreeSet::new(), outs),
            |(mut sources, mut targets), (id, node)| {
                for (wire_id, pred) in node.preds.iter().enumerate() {
                    match pred {
                        PredType::Source => {
                            sources.insert(NodeInputType::WireIn(id, wire_id as WitnessId));
                        }
                        PredType::PredWire(out) => {
                            targets.remove(out);
                        }
                        PredType::PredWireDup(out) => {
                            targets.remove(out);
                        }
                    }
                }

                (sources, targets)
            },
        );

        assert_eq!(
            expected_target,
            targets.iter().cloned().collect::<BTreeSet<_>>()
        );

        self.graph.sources = sources.into_iter().collect();
        self.graph.targets = targets.to_vec();

        (self.graph, self.witness)
    }

    pub fn finalize_graph_with_targets(self, targets: &[NodeOutputType]) -> CircuitGraph<E> {
        let (graph, _) = self.finalize_graph_and_witness_with_targets(targets);
        graph
    }
}
