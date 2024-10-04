use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphWitness, GKRProverState, IOPProof, IOPProverState,
        NodeOutputType, PredType, TargetEvaluations,
    },
};
use ff_ext::ExtensionField;
use gkr::structs::PointAndEval;
use itertools::{Itertools, izip};
use std::mem;
use transcript::Transcript;

impl<E: ExtensionField> IOPProverState<E> {
    pub fn prove(
        circuit: &CircuitGraph<E>,
        circuit_witness: &CircuitGraphWitness<E>,
        target_evals: &TargetEvaluations<E>,
        transcript: &mut Transcript<E>,
        expected_max_thread_id: usize,
    ) -> Result<IOPProof<E>, GKRGraphError> {
        assert_eq!(target_evals.0.len(), circuit.targets.len());
        assert_eq!(circuit_witness.node_witnesses.len(), circuit.nodes.len());

        let mut output_evals = vec![vec![]; circuit.nodes.len()];
        let mut wit_out_evals = circuit
            .nodes
            .iter()
            .map(|node| vec![PointAndEval::default(); node.circuit.n_witness_out])
            .collect_vec();
        izip!(&circuit.targets, &target_evals.0).for_each(|(target, eval)| match target {
            NodeOutputType::OutputLayer(id) => output_evals[*id].push(eval.clone()),
            NodeOutputType::WireOut(id, wire_out_id) => {
                wit_out_evals[*id][*wire_out_id as usize] = eval.clone()
            }
        });

        let gkr_proofs = izip!(&circuit.nodes, &circuit_witness.node_witnesses)
            .rev()
            .map(|(node, witness)| {
                let max_thread_id = witness.n_instances().min(expected_max_thread_id);

                // sanity check for witness poly evaluation
                if cfg!(debug_assertions) {

                    // TODO figure out a way to do sanity check on output_evals
                    // it doens't work for now because output evaluation
                    // might only take partial range of output layer witness
                    // assert!(output_evals[node.id].len() <= 1);
                    // if !output_evals[node.id].is_empty() {
                    // debug_assert_eq!(
                    //     witness
                    //         .output_layer_witness_ref()
                    //         .instances
                    //         .as_slice()
                    //         .original_mle()
                    //         .evaluate(&point_and_eval.point),
                    //         point_and_eval.eval,
                    //     "node_id {} output eval failed",
                    //     node.id,
                    // );
                    // }

                    for (witness_id, point_and_eval) in wit_out_evals[node.id].iter().enumerate() {
                        let mle = &witness.witness_out_ref()[witness_id];
                        debug_assert_eq!(
                            mle.evaluate(&point_and_eval.point),
                            point_and_eval.eval,
                            "node_id {} output eval failed",
                            node.id,
                        );
                    }
                }
                let (proof, input_claim) = GKRProverState::prove_parallel(
                    &node.circuit,
                    witness,
                    mem::take(&mut output_evals[node.id]),
                    mem::take(&mut wit_out_evals[node.id]),
                    max_thread_id,
                    transcript,
                );

                // println!(
                //     "Proving node {}, label {}, num_instances:{}, took {}s",
                //     node.id,
                //     node.label,
                //     witness.instance_num_vars(),
                //     timer.elapsed().as_secs_f64()
                // );

                izip!(&node.preds, &input_claim.point_and_evals)
                    .enumerate()
                    .for_each(|(wire_id, (pred_type, point_and_eval))| match pred_type {
                        PredType::Source => {
                            // sanity check for input poly evaluation
                            if cfg!(debug_assertions) {
                                let input_layer_poly = &witness.witness_in_ref()[wire_id];
                                debug_assert_eq!(
                                    input_layer_poly.evaluate(&point_and_eval.point),
                                    point_and_eval.eval,
                                    "mismatch at node.id {:?} wire_id {:?}, input_claim.point_and_evals.point {:?}, node.preds {:?}",
                                    node.id,
                                    wire_id,
                                    input_claim.point_and_evals[0].point,
                                    node.preds
                                );
                            }
                        }
                        PredType::PredWire(pred_out) | PredType::PredWireDup(pred_out) => {
                            let point = match pred_type {
                                PredType::PredWire(_) => point_and_eval.point.clone(),
                                PredType::PredWireDup(out) => {
                                    let pred_node_id = match out {
                                        NodeOutputType::OutputLayer(id) => id,
                                        NodeOutputType::WireOut(id, _) => id,
                                    };
                                    // Suppose the new point is
                                    // [single_instance_slice ||
                                    // new_instance_index_slice]. The old point
                                    // is [single_instance_slices ||
                                    // new_instance_index_slices[(instance_num_vars
                                    // - pred_instance_num_vars)..]]
                                    let pred_instance_num_vars = circuit_witness.node_witnesses
                                        [*pred_node_id]
                                        .instance_num_vars();
                                    let instance_num_vars = witness.instance_num_vars();
                                    let num_vars = point_and_eval.point.len() - instance_num_vars;
                                    [
                                        point_and_eval.point[..num_vars].to_vec(),
                                        point_and_eval.point[num_vars
                                            + (instance_num_vars - pred_instance_num_vars)..]
                                            .to_vec(),
                                    ]
                                    .concat()
                                }
                                _ => unreachable!(),
                            };
                            match pred_out {
                                NodeOutputType::OutputLayer(id) => {
                                    output_evals[*id]
                                    .push(PointAndEval::new_from_ref(&point, &point_and_eval.eval))
                                },
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
