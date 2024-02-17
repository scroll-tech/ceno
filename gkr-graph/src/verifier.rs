use gkr::structs::IOPProverPhase2Message;
use goldilocks::SmallField;
use itertools::{chain, izip, Itertools};
use std::mem;
use transcript::Transcript;

use crate::{
    error::GKRGraphError,
    structs::{
        CircuitGraph, CircuitGraphAuxInfo, IOPProof, IOPVerifierState, NodeOutputType, PredType,
        TargetEvaluations,
    },
};

impl<F: SmallField> IOPVerifierState<F> {
    pub fn verify(
        circuit: &CircuitGraph<F>,
        challenges: &[F],
        target_evals: &TargetEvaluations<F>,
        proof: &IOPProof<F>,
        aux_info: &CircuitGraphAuxInfo,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRGraphError> {
        assert_eq!(target_evals.0.len(), circuit.targets.len());

        let mut output_evals = vec![vec![]; circuit.nodes.len()];
        let mut wires_out_evals = vec![vec![]; circuit.nodes.len()];
        izip!(&circuit.targets, &target_evals.0).for_each(|(target, eval)| match target {
            NodeOutputType::OutputLayer(id) => output_evals[*id].push(eval.clone()),
            NodeOutputType::WireOut(id, _) => wires_out_evals[*id].push(eval.clone()),
        });

        for ((node, instance_num_vars), proof) in izip!(
            izip!(&circuit.nodes, &aux_info.instance_num_vars,).rev(),
            &proof.gkr_proofs
        ) {
            let _claim = gkr::structs::IOPVerifierState::verify_parallel(
                &node.circuit,
                challenges,
                &mem::take(&mut output_evals[node.id]),
                &mem::take(&mut wires_out_evals[node.id]),
                proof,
                *instance_num_vars,
                transcript,
            )?;

            let IOPProverPhase2Message {
                sumcheck_proofs,
                sumcheck_eval_values,
            } = &proof.sumcheck_proofs.last().unwrap().1;
            izip!(sumcheck_proofs, sumcheck_eval_values).for_each(|(proof, evals)| {
                izip!(&node.preds, evals).for_each(|(pred, eval)| match pred {
                    PredType::Source(_) => {
                        // TODO: collect `(proof.point.clone(), *eval)` as `TargetEvaluations` for later PCS open?
                    }
                    PredType::PredWire(out)
                    | PredType::PredWireTrans(out)
                    | PredType::PredWireDup(out) => {
                        let point = match pred {
                            PredType::PredWire(_) => proof.point.clone(),
                            PredType::PredWireTrans(_) => {
                                let mid = proof.point.len() - instance_num_vars;
                                let (lo, hi) = proof.point.split_at(mid);
                                chain![hi, lo].copied().collect_vec()
                            }
                            PredType::PredWireDup(_) => {
                                let dedup_num_vars = proof.point.len() - instance_num_vars;
                                proof.point[..dedup_num_vars].to_vec()
                            }
                            _ => unreachable!(),
                        };
                        match out {
                            NodeOutputType::OutputLayer(id) => {
                                output_evals[*id].push((point, *eval))
                            }
                            NodeOutputType::WireOut(id, wire_id) => {
                                wires_out_evals[*id]
                                    .resize(*wire_id as usize + 1, (vec![], F::ZERO));
                                let evals = &mut wires_out_evals[*id][*wire_id as usize];
                                assert!(
                                    evals.0.is_empty() && evals.1.is_zero_vartime(),
                                    "unimplemented",
                                );
                                *evals = (point, *eval);
                            }
                        }
                    }
                });
            });
        }

        Ok(())
    }
}
