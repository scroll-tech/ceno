use frontend::structs::WireId;
use gkr::structs::{Circuit, CircuitWitness};
use goldilocks::SmallField;
use itertools::{chain, Itertools};
use std::{collections::BTreeSet, sync::Arc};

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

    /// Add a new node indicating the predecessors. Return the index of the new
    /// node.
    pub fn add_node_with_witness(
        &mut self,
        label: &'static str,
        circuit: &Arc<Circuit<F>>,
        preds: Vec<PredType>,
        challenges: Vec<F>,
        sources: Vec<Vec<F>>, // instances
    ) -> Result<usize, GKRGraphError> {
        let id = self.graph.nodes.len();

        assert_eq!(preds.len(), circuit.n_wires_in);

        let mut witness = CircuitWitness::new(circuit, challenges);
        let num_instances = sources.len();
        for instance_id in 0..num_instances {
            let wires_in = preds
                .iter()
                .map(|pred| match pred {
                    PredType::Source => sources[instance_id].clone(),
                    PredType::PredWire(out) | PredType::PredWireTrans(out) => match out {
                        NodeOutputType::OutputLayer(id) => {
                            let output = &self.witness.node_witnesses[*id].last_layer_witness_ref();
                            let size = output.len() * output[0].len() / num_instances;
                            output
                                .iter()
                                .flatten()
                                .skip(size * instance_id)
                                .take(size)
                                .copied()
                                .collect_vec()
                        }
                        NodeOutputType::WireOut(id, wire_id) => {
                            let wire_out = &self.witness.node_witnesses[*id].wires_out_ref()
                                [*wire_id as usize];
                            let size = wire_out.len() * wire_out[0].len() / num_instances;
                            wire_out
                                .iter()
                                .flatten()
                                .skip(size * instance_id)
                                .take(size)
                                .copied()
                                .collect_vec()
                        }
                    },
                })
                .collect_vec();
            witness.add_instance(circuit, &wires_in);
        }

        self.graph.nodes.push(CircuitNode {
            id,
            label,
            circuit: circuit.clone(),
            preds,
        });
        self.witness.node_witnesses.push(witness);

        Ok(id)
    }

    /// Collect the information of `self.sources` and `self.targets`.
    pub fn finalize(mut self) -> (CircuitGraph<F>, CircuitGraphWitness<F>) {
        // Generate all possible graph output
        let outs = self
            .graph
            .nodes
            .iter()
            .enumerate()
            .flat_map(|(id, node)| {
                chain![
                    (0..node.circuit.copy_to_wires_out.len())
                        .map(move |wire_id| NodeOutputType::WireOut(id, wire_id as WireId)),
                    node.circuit
                        .copy_to_wires_out
                        .is_empty()
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
                            sources.insert(NodeInputType::WireIn(id, wire_id as WireId));
                        }
                        PredType::PredWire(out) | PredType::PredWireTrans(out) => {
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
}
