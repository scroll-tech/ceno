use std::{collections::BTreeSet, sync::Arc};

use ark_std::Zero;
use gkr::structs::{Circuit, CircuitWitness, LayerWitness};
use goldilocks::SmallField;
use itertools::{chain, izip, Itertools};
use simple_frontend::structs::WitnessId;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphBuilder, CircuitGraphWitness, CircuitNode, NodeInputType,
        NodeOutputType, PredType,
    },
};

impl<F: SmallField> CircuitGraphBuilder<F> {
    pub fn new() -> Self {
        Self {
            graph: Default::default(),
            witness: Default::default(),
        }
    }

    /// Add a new node indicating the predecessors and generate the witness.
    /// Return the index of the new node. sources has the same number as the
    /// input witnesses. If some witness is not source, then the corresponding
    /// entry in sources is default.
    pub fn add_node_with_witness(
        &mut self,
        label: &'static str,
        circuit: &Arc<Circuit<F>>,
        preds: Vec<PredType>,
        challenges: Vec<F>,
        sources: Vec<LayerWitness<F::BaseField>>,
        num_instances: usize,
    ) -> Result<usize, GKRGraphError> {
        let id = self.graph.nodes.len();

        assert_eq!(preds.len(), circuit.n_witness_in);
        assert!(num_instances.is_power_of_two());
        assert_eq!(sources.len(), circuit.n_witness_in);
        assert!(
            !sources.iter().any(
                |source| source.instances.len() != 0 && source.instances.len() != num_instances
            ),
            "node_id: {}, num_instances: {}, sources_num_instances: {:?}",
            id,
            num_instances,
            sources
                .iter()
                .map(|source| source.instances.len())
                .collect_vec()
        );

        let mut witness = CircuitWitness::new(circuit, challenges);
        let wits_in = izip!(preds.iter(), sources.into_iter())
            .map(|(pred, source)| match pred {
                PredType::Source => source,
                PredType::PredWire(out) | PredType::PredWireDup(out) => {
                    let (id, out) = &match out {
                        NodeOutputType::OutputLayer(id) => (
                            *id,
                            &self.witness.node_witnesses[*id]
                                .output_layer_witness_ref()
                                .instances,
                        ),
                        NodeOutputType::WireOut(id, wit_id) => (
                            *id,
                            &self.witness.node_witnesses[*id].witness_out_ref()[*wit_id as usize]
                                .instances,
                        ),
                    };
                    let old_num_instances = self.witness.node_witnesses[*id].n_instances();
                    let new_instances = match pred {
                        PredType::PredWire(_) => {
                            let new_size = (old_num_instances * out[0].len()) / num_instances;
                            out.iter()
                                .cloned()
                                .flatten()
                                .chunks(new_size)
                                .into_iter()
                                .map(|c| c.collect_vec())
                                .collect_vec()
                        }
                        PredType::PredWireDup(_) => {
                            let num_dups = num_instances / old_num_instances;
                            let old_size = out[0].len();
                            out.iter()
                                .cloned()
                                .flat_map(|single_instance| {
                                    single_instance
                                        .into_iter()
                                        .cycle()
                                        .take(num_dups * old_size)
                                })
                                .chunks(old_size)
                                .into_iter()
                                .map(|c| c.collect_vec())
                                .collect_vec()
                        }
                        _ => unreachable!(),
                    };
                    LayerWitness {
                        instances: new_instances,
                    }
                }
            })
            .collect_vec();
        witness.add_instances(circuit, wits_in, num_instances);

        self.graph.nodes.push(CircuitNode {
            id,
            label,
            circuit: circuit.clone(),
            preds,
        });
        self.witness.node_witnesses.push(witness);

        Ok(id)
    }

    /// Add a new node indicating the predecessors. Return the index of the new
    /// node.
    pub fn add_node(
        &mut self,
        label: &'static str,
        circuit: &Arc<Circuit<F>>,
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
    pub fn finalize_graph_and_witness(
        mut self,
    ) -> (CircuitGraph<F>, CircuitGraphWitness<F::BaseField>) {
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

    pub fn finalize_graph(self) -> CircuitGraph<F> {
        let (graph, _) = self.finalize_graph_and_witness();
        graph
    }

    /// Collect the information of `self.sources` and `self.targets`.
    pub fn finalize_graph_and_witness_with_targets(
        mut self,
        targets: &[NodeOutputType],
    ) -> (CircuitGraph<F>, CircuitGraphWitness<F::BaseField>) {
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

    pub fn finalize_graph_with_targets(self, targets: &[NodeOutputType]) -> CircuitGraph<F> {
        let (graph, _) = self.finalize_graph_and_witness_with_targets(targets);
        graph
    }
}
