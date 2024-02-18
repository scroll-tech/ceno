use gkr::{
    structs::{IOPProverPhase2Message, PointAndEval},
    utils::{ceil_log2, MultilinearExtensionFromVectors},
};
use goldilocks::SmallField;
use itertools::izip;
use std::mem;
use transcript::Transcript;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphWitness, GKRProverState, IOPProof, IOPProverState,
        NodeOutputType, PredType, TargetEvaluations,
    },
};

impl<F: SmallField> IOPProverState<F> {
    pub fn prove(
        circuit: &CircuitGraph<F>,
        circuit_witness: &CircuitGraphWitness<F::BaseField>,
        target_evals: &TargetEvaluations<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<IOPProof<F>, GKRGraphError> {
        assert_eq!(target_evals.0.len(), circuit.targets.len());

        let mut wit_out_evals = vec![vec![]; circuit.nodes.len()];
        izip!(&circuit.targets, &target_evals.0).for_each(|(target, eval)| match target {
            NodeOutputType::WireOut(id, _) => wit_out_evals[*id].push(eval.clone()),
        });

        let gkr_proofs = izip!(&circuit.nodes, &circuit_witness.node_witnesses)
            .rev()
            .map(|(node, witness)| {
                let proof = GKRProverState::prove_parallel(
                    &node.circuit,
                    witness,
                    mem::take(&mut wit_out_evals[node.id]),
                    transcript,
                );

                let IOPProverPhase2Message {
                    sumcheck_proofs,
                    sumcheck_eval_values,
                } = &proof.sumcheck_proofs.last().unwrap().1;
                izip!(sumcheck_proofs, sumcheck_eval_values).for_each(|(proof, evals)| {
                    izip!(&node.preds, evals)
                        .enumerate()
                        .for_each(|(wire_id, (pred, eval))| match pred {
                            PredType::Source => {
                                debug_assert_eq!(
                                    witness.witness_in_ref()[wire_id as usize]
                                        .instances
                                        .as_slice()
                                        .mle(
                                            node.circuit.max_wires_in_num_vars.unwrap(),
                                            witness.instance_num_vars(),
                                        )
                                        .evaluate(&proof.point),
                                    *eval
                                );
                            }
                            PredType::PredWire(out) | PredType::PredWireDup(out) => {
                                let point = match pred {
                                    PredType::PredWire(_) => proof.point.clone(),
                                    PredType::PredWireDup(NodeOutputType::WireOut(
                                        node_id,
                                        wire_id,
                                    )) => {
                                        let old_instance_num_vars = circuit_witness.node_witnesses
                                            [*node_id]
                                            .instance_num_vars();
                                        let new_instance_num_vars = witness.instance_num_vars();
                                        let num_vars = ceil_log2(
                                            witness.witness_in_ref()[*wire_id as usize].instances
                                                [0]
                                            .len(),
                                        );
                                        [
                                            proof.point[..num_vars].to_vec(),
                                            proof.point[proof.point.len() - new_instance_num_vars
                                                + old_instance_num_vars
                                                ..proof.point.len()]
                                                .to_vec(),
                                        ]
                                        .concat()
                                    }
                                    _ => unreachable!(),
                                };
                                match out {
                                    NodeOutputType::WireOut(id, wire_id) => {
                                        wit_out_evals[*id].resize(
                                            *wire_id as usize + 1,
                                            PointAndEval::new(vec![], F::ZERO),
                                        );
                                        let evals = &mut wit_out_evals[*id][*wire_id as usize];
                                        assert!(
                                            evals.point.is_empty() && evals.eval.is_zero_vartime(),
                                            "unimplemented",
                                        );
                                        *evals = PointAndEval::new(point, *eval);
                                    }
                                }
                            }
                        });
                });

                proof
            })
            .collect();

        Ok(IOPProof { gkr_proofs })
    }
}
