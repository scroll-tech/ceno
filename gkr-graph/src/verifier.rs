use gkr::{
    structs::{IOPProverPhase2Message, PointAndEval},
    utils::ceil_log2,
};
use goldilocks::SmallField;
use itertools::izip;

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
        proof: &IOPProof<F>,
        aux_info: &CircuitGraphAuxInfo,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRGraphError> {
        assert_eq!(target_evals.0.len(), circuit.targets.len());

        let mut wit_out_evals = vec![vec![]; circuit.nodes.len()];
        izip!(&circuit.targets, &target_evals.0).for_each(|(target, eval)| match target {
            NodeOutputType::WireOut(id, _) => wit_out_evals[*id].push(eval.clone()),
        });

        for ((node, instance_num_vars), proof) in izip!(
            izip!(&circuit.nodes, &aux_info.instance_num_vars,).rev(),
            &proof.gkr_proofs
        ) {
            let _claim = GKRVerifierState::verify_parallel(
                &node.circuit,
                challenges,
                mem::take(&mut wit_out_evals[node.id]),
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
                    PredType::Source => {
                        // TODO: collect `(proof.point.clone(), *eval)` as `TargetEvaluations` for later PCS open?
                    }
                    PredType::PredWire(out) | PredType::PredWireDup(out) => {
                        let point = match pred {
                            PredType::PredWire(_) => proof.point.clone(),
                            PredType::PredWireDup(NodeOutputType::WireOut(node_id, wire_id)) => {
                                let old_instance_num_vars = aux_info.instance_num_vars[*node_id];
                                let new_instance_num_vars = instance_num_vars;
                                let seg = node.circuit.paste_from_wits_in[*wire_id as usize];
                                let num_vars = ceil_log2(seg.1 - seg.0);
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
        }

        Ok(())
    }
}
