use ff_ext::ExtensionField;
use gkr::{
    structs::{Point, PointAndEval},
    utils::MultilinearExtensionFromVectors,
};
use itertools::Itertools;

use crate::structs::{CircuitGraph, CircuitGraphWitness, NodeOutputType, TargetEvaluations};

impl<E: ExtensionField> CircuitGraph<E> {
    pub fn target_evals(
        &self,
        witness: &CircuitGraphWitness<E::BaseField>,
        point: &Point<E>,
    ) -> TargetEvaluations<E> {
        let target_evals = self
            .targets
            .iter()
            .map(|target| {
                let poly = match target {
                    NodeOutputType::OutputLayer(node_id) => witness.node_witnesses[*node_id]
                        .output_layer_witness_ref()
                        .instances
                        .as_slice()
                        .original_mle(),
                    NodeOutputType::WireOut(node_id, wit_id) => witness.node_witnesses[*node_id]
                        .witness_out_ref()[*wit_id as usize]
                        .instances
                        .as_slice()
                        .original_mle(),
                };
                PointAndEval::new(point[..poly.num_vars].to_vec(), poly.evaluate(point))
            })
            .collect_vec();
        TargetEvaluations(target_evals)
    }
}
