use ff_ext::ExtensionField;
use gkr::structs::{Point, PointAndEval};
use itertools::Itertools;

use crate::structs::{CircuitGraph, CircuitGraphWitness, NodeOutputType, TargetEvaluations};

impl<E: ExtensionField> CircuitGraph<E> {
    pub fn target_evals(
        &self,
        witness: &CircuitGraphWitness<E>,
        point: &Point<E>,
    ) -> TargetEvaluations<E> {
        // println!("targets: {:?}, point: {:?}", self.targets, point);
        let target_evals = self
            .targets
            .iter()
            .map(|target| {
                let poly = match target {
                    NodeOutputType::OutputLayer(node_id) => {
                        witness.node_witnesses[*node_id].output_layer_witness_ref()
                    }
                    NodeOutputType::WireOut(node_id, wit_id) => {
                        &witness.node_witnesses[*node_id].witness_out_ref()[*wit_id as usize]
                    }
                };
                // println!("target: {:?}, poly.num_vars: {:?}", target, poly.num_vars);
                let p = point[..poly.num_vars()].to_vec();
                PointAndEval::new_from_ref(&p, &poly.evaluate(&p))
            })
            .collect_vec();
        TargetEvaluations(target_evals)
    }
}
