use std::{collections::BTreeSet, sync::Arc};

use gkr::structs::{Circuit, CircuitWitness, LayerWitness};
use goldilocks::SmallField;
use itertools::Itertools;
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

    /// Add a new node indicating the predecessors. Return the index of the new
    /// node.
    pub fn add_node_with_witness(
        &mut self,
        label: &'static str,
        circuit: &Arc<Circuit<F>>,
        preds: Vec<PredType>,
        challenges: Vec<F>,
        sources: Vec<LayerWitness<F::BaseField>>,
    ) -> Result<usize, GKRGraphError> {
        let id = self.graph.nodes.len();
        let num_instances = sources[0].instances.len();

        assert_eq!(preds.len(), circuit.n_witness_in);
        assert!(num_instances.is_power_of_two());
        assert!(!sources
            .iter()
            .any(|source| source.instances.len() != num_instances));

        let mut source_iter = sources.iter();
        let mut witness = CircuitWitness::new(circuit, challenges);
        let wits_in = preds
            .iter()
            .map(|pred| match pred {
                PredType::Source => source_iter.next().unwrap().clone(),
                PredType::PredWire(out) | PredType::PredWireDup(out) => {
                    let out = &match out {
                        NodeOutputType::WireOut(id, wit_id) => {
                            &self.witness.node_witnesses[*id].witness_out_ref()[*wit_id as usize]
                        }
                    }
                    .instances;
                    let old_num_instances = out.len();
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
        witness.add_instances(circuit, wits_in);

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
    pub fn finalize(mut self) -> (CircuitGraph<F>, CircuitGraphWitness<F::BaseField>) {
        // Generate all possible graph output
        let outs = self
            .graph
            .nodes
            .iter()
            .enumerate()
            .flat_map(|(id, node)| {
                (0..node.circuit.n_witness_out)
                    .map(move |wit_id| NodeOutputType::WireOut(id, wit_id as WitnessId))
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
}
