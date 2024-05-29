use ff_ext::ExtensionField;
use gkr::{structs::PointAndEval, utils::MultilinearExtensionFromVectors};
use itertools::{izip, Itertools};
use std::mem;
use transcript::Transcript;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphWitness, GKRProverState, IOPProof, IOPProverState,
        NodeOutputType, PredType, TargetEvaluations,
    },
};

impl<E: ExtensionField> IOPProverState<E> {
    pub fn prove(
        circuit: &CircuitGraph<E>,
        circuit_witness: &CircuitGraphWitness<E::BaseField>,
        target_evals: &TargetEvaluations<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<IOPProof<E>, GKRGraphError> {
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

        let gkr_proofs = izip!(&circuit.nodes, &circuit_witness.node_witnesses)
            .rev()
            .map(|(node, witness)| {
                let (proof, input_claim) = GKRProverState::prove_parallel(
                    &node.circuit,
                    witness,
                    mem::take(&mut output_evals[node.id]),
                    mem::take(&mut wit_out_evals[node.id]),
                    transcript,
                );

                izip!(&node.preds, input_claim.point_and_evals)
                    .enumerate()
                    .for_each(|(wire_id, (pred, point_and_eval))| match pred {
                        PredType::Source => {
                            debug_assert_eq!(
                                witness.witness_in_ref()[wire_id as usize]
                                    .instances
                                    .as_slice()
                                    .original_mle()
                                    .evaluate(&point_and_eval.point),
                                point_and_eval.eval
                            );
                        }
                        PredType::PredWire(out) | PredType::PredWireDup(out) => {
                            let point = match pred {
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
                                    let old_instance_num_vars =
                                        circuit_witness.node_witnesses[node_id].instance_num_vars();
                                    let new_instance_num_vars = witness.instance_num_vars();
                                    let num_vars =
                                        point_and_eval.point.len() - new_instance_num_vars;
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
                                    .push(PointAndEval::new_from_ref(&point, &point_and_eval.eval)),
                                NodeOutputType::WireOut(id, wire_id) => {
                                    let evals = &mut wit_out_evals[*id][*wire_id as usize];
                                    assert!(
                                        evals.point.is_empty() && evals.eval.is_zero_vartime(),
                                        "unimplemented",
                                    );
                                    *evals = PointAndEval::new(point, point_and_eval.eval);
                                }
                            }
                        }
                    });

                proof
            })
            .collect();

        Ok(IOPProof { gkr_proofs })
    }
}
