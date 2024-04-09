use gkr::structs::PointAndEval;
use goldilocks::SmallField;
use itertools::{izip, Itertools};
use std::mem;
use transcript::Transcript;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphAuxInfo, GKRVerifierState, IOPProof, IOPVerifierState,
        NodeOutputType, PredType, TargetEvaluations,
    },
};

impl<F: SmallField> IOPVerifierState<F> {
    pub fn verify(
        circuit: &CircuitGraph<F>,
        challenges: &[F],
        target_evals: &TargetEvaluations<F>,
        proof: IOPProof<F>,
        aux_info: &CircuitGraphAuxInfo,
        transcript: &mut Transcript<F>,
    ) -> Result<Vec<Vec<PointAndEval<F>>>, GKRGraphError> {
        assert_eq!(target_evals.0.len(), circuit.targets.len());

        let mut output_evals = vec![vec![]; circuit.nodes.len()];
        let mut wit_out_evals = circuit
            .nodes
            .iter()
            .map(|node| vec![PointAndEval::default(); node.circuit.n_witness_out])
            .collect_vec();
        izip!(&circuit.targets, &target_evals.0).for_each(|(target, eval)| match target {
            NodeOutputType::OutputLayer(id) => output_evals[*id].push(eval.clone()),
            NodeOutputType::WireOut(id, _) => wit_out_evals[*id].push(eval.clone()),
        });

        let mut pcs_point_evals = vec![];

        for ((node, instance_num_vars), proof) in izip!(
            izip!(&circuit.nodes, &aux_info.instance_num_vars,).rev(),
            proof.gkr_proofs
        ) {
            let input_claim = GKRVerifierState::verify_parallel(
                &node.circuit,
                challenges,
                mem::take(&mut output_evals[node.id]),
                mem::take(&mut wit_out_evals[node.id]),
                proof,
                *instance_num_vars,
                transcript,
            )?;

            let new_instance_num_vars = aux_info.instance_num_vars[node.id];
            let mut pcs_point_evals_for_node = vec![];

            izip!(&node.preds, input_claim.point_and_evals).for_each(|(pred, point_and_eval)| {
                match pred {
                    PredType::Source => {
                        pcs_point_evals_for_node.push(point_and_eval.clone());
                    }
                    PredType::PredWire(out) | PredType::PredWireDup(out) => {
                        // No need to push the real one because it is not going to be
                        // used by the PCS opening. But still need to push something
                        // to take the position and make the wire id correct. So push
                        // an empty point.
                        pcs_point_evals_for_node.push(PointAndEval::default());
                        let old_point = match pred {
                            PredType::PredWire(_) => point_and_eval.point.clone(),
                            PredType::PredWireDup(out) => {
                                let node_id = match out {
                                    NodeOutputType::OutputLayer(id) => *id,
                                    NodeOutputType::WireOut(id, _) => *id,
                                };
                                // Suppose the new point is
                                // [single_instance_slice ||
                                // new_instance_index_slice]. The old point
                                // is [single_instance_slices ||
                                // new_instance_index_slices[(new_instance_num_vars
                                // - old_instance_num_vars)..]]
                                let old_instance_num_vars = aux_info.instance_num_vars[node_id];
                                let num_vars = point_and_eval.point.len() - new_instance_num_vars;
                                [
                                    point_and_eval.point[..num_vars].to_vec(),
                                    point_and_eval.point[num_vars
                                        + (new_instance_num_vars - old_instance_num_vars)..]
                                        .to_vec(),
                                ]
                                .concat()
                            }
                            _ => unreachable!(),
                        };
                        match out {
                            NodeOutputType::OutputLayer(id) => output_evals[*id]
                                .push(PointAndEval::new_from_ref(&old_point, &point_and_eval.eval)),
                            NodeOutputType::WireOut(id, wire_id) => {
                                let evals = &mut wit_out_evals[*id][*wire_id as usize];
                                assert!(
                                    evals.point.is_empty() && evals.eval.is_zero_vartime(),
                                    "unimplemented",
                                );
                                *evals = PointAndEval::new(old_point, point_and_eval.eval);
                            }
                        }
                    }
                }
            });
            pcs_point_evals.push(pcs_point_evals_for_node);
        }

        // Reverse the vector because they were pushed in the reverse order of the nodes.
        let pcs_point_evals = pcs_point_evals.into_iter().rev().collect();

        Ok(pcs_point_evals)
    }
}
